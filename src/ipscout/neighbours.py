"""Neighbour-cache reads, and the honest answer to "what is the MAC of X".

Contents:
    neighbours: Every entry this host's neighbour cache holds.
    get_mac_address: The direct layer-2 address, or None for anything routed.
    lookup_mac: A scoped answer that works for any address.
    normalise_mac: Compare hardware addresses across their written forms.

Note:
    **A MAC address does not survive a router hop.** The Ethernet frame sent
    toward a routed address carries the *next-hop router's* destination MAC;
    the remote host's own address never appears in any packet that arrives
    here. No privilege level, protocol or library changes that - it is how
    Ethernet works. A tool that answers "the MAC of 8.8.8.8" with a value is
    returning the local gateway's MAC without saying so.

    Hence two functions rather than one. :func:`get_mac_address` stays strict
    and answers ``None`` for anything routed. :func:`lookup_mac` answers the
    question people actually mean, and makes the scope part of the return type
    so the answer cannot be misread.

    Every read here is passive: it reports what the kernel already learned and
    sends nothing, so it needs no privileges. The cache only knows hosts that
    have been talked to, which is why the usual sequence is to sweep first and
    read second.

"""

from __future__ import annotations

import sys
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Annotated, NamedTuple

from pydantic import BaseModel, BeforeValidator, ConfigDict, ValidationError

from .arp import normalise_mac
from .errors import IPScoutPermissionError, IPScoutResolutionError, IPScoutUnsupportedError, refused_arguments
from .interfaces import local_interfaces
from .models import DEFAULT_TIMEOUT, AddressFamily, MacLookup, MacMethod, MacScope, Neighbour, Timeout, parse_address
from .resolve import interface_name, split_zone, zone_index
from .routes import query_route

if TYPE_CHECKING:
    from collections.abc import Callable

    from .models import RouteInfo

__all__ = ["ask_or_read_cache", "get_mac_address", "lookup_mac", "neighbours", "normalise_mac", "resolve_active"]

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"


def of_family(entries: tuple[Neighbour, ...], family: AddressFamily | None) -> tuple[Neighbour, ...]:
    """Keep the entries in ``family``, or all of them when it is ``None``.

    One place, because the three address-returning calls must agree on what "IPv4" selects.

    Read from the ADDRESS rather than ``entry.family``. A ``Neighbour`` refuses a family that
    disagrees with its address, so the two cannot differ; deriving keeps this filter and
    ``scoped`` reading the same thing.
    """
    if family is None:
        return entries
    return tuple(entry for entry in entries if entry.address.version == family.ip_version)


def neighbours(*, family: AddressFamily | None = None) -> tuple[Neighbour, ...]:
    """Return every entry this host's neighbour cache currently holds.

    Args:
        family: Restrict to one address family. ``None``, the default, returns
            both, which is what this has always done.

    Returns:
        One record per entry, in the family asked for. Entries with no learned
        hardware address are not included: an unanswered query is not a
        neighbour this host knows.

    Note:
        Passive by definition. It reports what the kernel already learned, so
        a host that has never been contacted will not appear. Sweep first with
        ``ping_many`` if you need the cache populated.

    Examples:
        >>> entries = neighbours()
        >>> all(entry.mac for entry in entries)
        True

    """

    if IS_WINDOWS:  # pragma: no cover - exercised on Windows CI only
        from .neighbours_windows import list_neighbours  # noqa: PLC0415 - Windows-only import
    elif IS_MACOS:  # pragma: no cover - exercised on macOS CI only
        from .neighbours_macos import list_neighbours  # noqa: PLC0415 - macOS-only import
    else:
        from .neighbours_linux import list_neighbours  # noqa: PLC0415 - Linux-only import
    return of_family(list_neighbours(), family)


class SendingInterface(NamedTuple):
    """Where an address-resolution request leaves from.

    A ``NamedTuple`` rather than three bare strings: every field is a ``str``,
    so a caller that unpacked them in the wrong order would type-check and
    send from the wrong address. Naming them makes the order irrelevant.

    Attributes:
        interface: The name of the interface the route to the target uses.
        source_ip: The address to send from - the route's own source when it
            names one, else the interface's first IPv4 address, else the
            unspecified ``0.0.0.0``. Only an IPv4 request reads it.
        source_mac: The interface's hardware address, which the request
            carries as its sender.

    Examples:
        >>> sender = SendingInterface("eth0", "192.0.2.10", "00:00:5e:00:53:01")
        >>> sender.interface, sender.source_mac
        ('eth0', '00:00:5e:00:53:01')
        >>> sender == ("eth0", "192.0.2.10", "00:00:5e:00:53:01")
        True

    """

    interface: str
    source_ip: str
    source_mac: str


def _address_literal(value: object) -> IPv4Address | IPv6Address:
    """Parse the text a caller named an address with, refusing anything that is not text.

    A ``BeforeValidator`` because the field holds the parsed address, which
    strict mode only accepts as an instance: the text is parsed here, once,
    and the parsed value is what every later step reads. ``ip_address`` alone
    would also take an ``int`` and quietly turn ``5`` into ``0.0.0.5``.
    """

    if not isinstance(value, str):
        msg = f"must be an address literal as text, not {type(value).__name__}"
        # ValueError, not TypeError: pydantic turns only a ValueError into the
        # field's refusal; a TypeError would escape validation unreported.
        raise ValueError(msg)
    return parse_address(value)


class _ActiveResolution(BaseModel):
    """The arguments of one active resolution, checked before anything is sent.

    Strict, so ``True`` is not a timeout and ``"5"`` is not a number, and the
    timeout is the library's one ``Timeout``: zero would hand the backend a
    non-blocking socket that waits for nothing, and a negative one would reach
    ``settimeout`` and fail there in words that name no argument.

    Examples:
        >>> _ActiveResolution(ip="fe80::1%eth0").ip.scope_id
        'eth0'
        >>> _ActiveResolution(ip="192.0.2.1", timeout=0)
        Traceback (most recent call last):
        ...
        pydantic_core._pydantic_core.ValidationError: ...

    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    #: The address to resolve, an RFC 4007 zone included when the caller gave one.
    ip: Annotated[IPv4Address | IPv6Address, BeforeValidator(_address_literal)]
    #: Seconds to wait for an answer.
    timeout: Timeout = DEFAULT_TIMEOUT


class _ZoneInterface(NamedTuple):
    """The interface an RFC 4007 zone names.

    Attributes:
        interface_index: Its interface index, which is what a request is addressed by.
        name: Its name as the neighbour cache and ``if_nametoindex`` speak it.

    """

    interface_index: int
    name: str


def _zone_interface(zone: str) -> str:
    """Return the name of the interface an RFC 4007 zone names; see :func:`_zone`."""

    return _zone(zone).name


def _zone(zone: str) -> _ZoneInterface:
    """Return the interface an RFC 4007 zone names, by index or by either name.

    The name returned is the one the neighbour cache and ``if_nametoindex``
    speak, so it can be matched against cache entries. Windows names an
    adapter two ways - the friendly name ``local_interfaces()`` reports
    ("Ethernet 4") and the ``if_nametoindex`` one ("ethernet_32768") - and a
    caller may hold either, so the friendly name is tried when the other
    spelling is unknown.

    Raises:
        IPScoutResolutionError: No interface here goes by that name or index.
    """

    try:
        index = zone_index(zone)
    except IPScoutResolutionError:
        index = next((entry.index for entry in local_interfaces() if entry.name == zone and entry.index), None)
        if index is None:
            raise
    name = interface_name(index)
    if name is None:
        msg = f"no interface with index {index} to send on: name one this host has, or use its index"
        raise IPScoutResolutionError(msg)
    return _ZoneInterface(index, name)


def _link_of(zone: str) -> str:
    """Return the interface a zone names for a passive read, or the zone's text when it names none.

    The passive path never raises for an address it cannot place, so an
    unknown zone is kept as written and simply matches no cache entry.
    """

    try:
        return _zone_interface(zone)
    except IPScoutResolutionError:
        return zone


def _sending_interface(ip: str, family: AddressFamily, *, zone: str | None = None) -> SendingInterface:
    """Return the interface, source address and hardware address to send from.

    An ARP request is answered to the address it came from, so a source on the
    wrong subnet gets no reply at all. The route lookup names the interface,
    and its own addresses supply the rest.

    Args:
        ip: The address the request will ask about, without a zone.
        family: The family of ``ip``; only IPv4 needs a source address.
        zone: The RFC 4007 zone the caller wrote, which names the interface
            outright. A link-local address is unique on one link only, so the
            routing table cannot say which link was meant, and the caller's
            zone wins over whatever it would pick.

    Returns:
        A :class:`SendingInterface` naming each of the three.

    Raises:
        IPScoutUnsupportedError: No interface on this host can reach that
            address, or the one that can has no hardware address (loopback and
            tunnels have none, and there is nothing to ARP over) or one that is
            not a six-byte Ethernet address.
        IPScoutResolutionError: ``zone`` names no interface this host has.
    """

    route = None if zone is not None else query_route(ip, family)
    name = _zone_interface(zone) if zone is not None else (route.interface if route else None)
    if name is None:
        msg = f"no route to {ip}, so no interface to send a resolution request on"
        raise IPScoutUnsupportedError(msg)

    for candidate in local_interfaces():
        if candidate.name != name:
            continue
        if not candidate.mac:
            msg = f"{name} has no hardware address, so it cannot carry an address-resolution request"
            raise IPScoutUnsupportedError(msg)
        if normalise_mac(candidate.mac) is None:
            # ARP and neighbour discovery as built here carry a six-byte
            # Ethernet sender; an InfiniBand or other longer address cannot be
            # written into either, and the codec refuses it.
            msg = f"{name} has a non-Ethernet hardware address ({candidate.mac}), so it cannot carry this address-resolution request"
            raise IPScoutUnsupportedError(msg)
        source = route.source if route and route.source else next((entry.address for entry in candidate.ipv4), None)
        if family is AddressFamily.IPV4 and source is None:
            msg = f"{name} has no IPv4 address to send from"
            raise IPScoutUnsupportedError(msg)
        # Only an IPv6 solicitation gets here without an IPv4 source, and it never
        # reads one, so the unspecified address fills the field rather than naming
        # an address anything sends from.
        return SendingInterface(name, source or AddressFamily.IPV4.unspecified_address, candidate.mac)

    msg = f"the route to {ip} names interface {name!r}, which is not among this host's interfaces"
    raise IPScoutUnsupportedError(msg)


def resolve_active(ip: str, *, timeout: float = DEFAULT_TIMEOUT) -> str | None:
    """Actively resolve one address, sending a real request rather than reading.

    Args:
        ip: The address to resolve.
        timeout: Seconds to wait for an answer. Windows ignores it: ``SendARP``
            and ``ResolveIpNetEntry2`` take no timeout and wait as long as the
            stack's own resolution does.

    Returns:
        The hardware address, or ``None`` when nothing answered in time.

    Raises:
        ValueError: ``ip`` is not an IP address literal given as text, or
            ``timeout`` is not a number above zero and at most
            ``MAX_TIMEOUT``. Refused before anything is sent.
        IPScoutPermissionError: The process lacks the privilege the send
            needs - root or ``CAP_NET_RAW`` on Linux, root on macOS. The
            message names the remedy, including the unprivileged alternative.
        IPScoutUnsupportedError: There is no interface or route that can carry
            the request, the platform has no active path for that family, or
            the request could not be sent or its reply read. Never a ``None``
            answer: ``None`` means a request went out and nothing answered.
        IPScoutResolutionError: The address carries a zone that names no
            interface this host has.

    Note:
        Windows IPv4 is the one case that needs no elevation, through
        ``SendARP``. Everywhere else this sends a real ARP request or ICMPv6
        neighbour solicitation over a raw socket, which needs privilege.

        A zone (``fe80::1%eth0``) names the interface to send on, overriding
        the routing table, which cannot tell one link's ``fe80::1`` from
        another's.

        It never falls back to the cache. A caller who asked to resolve
        actively gets a fresh answer or an error, never a stale entry dressed
        up as a fresh one. The unprivileged way to learn the same thing is
        ``arp_scan()``, which sweeps and then reads what the kernel learned.

    Examples:
        >>> import sys
        >>> from ipscout.errors import IPScoutError
        >>> try:
        ...     _ = resolve_active("192.0.2.1")
        ... except IPScoutError:
        ...     pass

    """

    try:
        # model_validate, not the constructor: the field holds the parsed
        # address while the caller hands text, which only validation converts.
        request = _ActiveResolution.model_validate({"ip": ip, "timeout": timeout})
    except ValidationError as refused:
        raise refused_arguments("active resolution", refused) from refused
    family = AddressFamily.of_version(request.ip.version)
    # Every backend packs the address into bytes, and inet_pton refuses a
    # zone, so the backends get the bare address and the zone picks the
    # interface instead of travelling with it.
    bare, zone = split_zone(str(request.ip))

    if IS_WINDOWS:  # pragma: no cover - exercised on Windows CI only
        from .neighbours_windows import resolve_active as _windows_resolve  # noqa: PLC0415 - Windows-only import

        if zone is not None:
            # Only an IPv6 literal carries a zone, and ResolveIpNetEntry2 takes
            # the interface in its row, so the zone is honoured as on POSIX.
            return _windows_resolve(bare, family, interface_index=_zone(zone).interface_index)
        if query_route(bare, family) is None:
            # SendARP answers an unrouted address with the same status as an
            # unanswered one, though nothing was sent, so the missing route is
            # refused here as POSIX refuses it in _sending_interface.
            msg = f"no route to {bare}, so no interface to send a resolution request on"
            raise IPScoutUnsupportedError(msg)
        return _windows_resolve(bare, family)

    sender = _sending_interface(bare, family, zone=zone)

    if IS_MACOS:  # pragma: no cover - exercised on macOS CI only
        from .neighbours_macos import resolve_active_ipv4, resolve_active_ipv6  # noqa: PLC0415 - macOS-only import
    else:
        from .neighbours_linux import resolve_active_ipv4, resolve_active_ipv6  # noqa: PLC0415 - Linux-only import

    if family is AddressFamily.IPV6:
        return resolve_active_ipv6(bare, interface=sender.interface, source_mac=sender.source_mac, timeout=request.timeout)
    return resolve_active_ipv4(
        bare,
        interface=sender.interface,
        source_ip=sender.source_ip,
        source_mac=sender.source_mac,
        timeout=request.timeout,
    )


def _entry_for(ip: str, entries: tuple[Neighbour, ...], *, interface: str | None = None) -> Neighbour | None:
    """Return the cache entry for one address, if it is known.

    Args:
        ip: The address to look up.
        entries: The cache to search.
        interface: The interface the frame would leave by, when one is known.
            An address is only unique per interface - a link-local address
            names a different machine on each link, and one host can hold the
            same address on two of them - so the entry learned on the
            interface that actually carries the frame is the truthful one.
            Without a match there, or with no interface named, the first
            entry for the address is returned, which is all that can be said.

    """

    matches = [entry for entry in entries if entry.ip == ip]
    if not matches:
        return None
    if interface is not None:
        on_link = next((entry for entry in matches if entry.interface == interface), None)
        if on_link is not None:
            return on_link
    return matches[0]


#: What makes this host unable to ASK, as opposed to a caller's mistake: no
#: privilege for a raw socket, or no interface and path that can carry the
#: request. Only these let an active lookup fall back to the cache.
_CANNOT_ASK_ACTIVELY: tuple[type[Exception], ...] = (IPScoutPermissionError, IPScoutUnsupportedError)


def ask_or_read_cache(ask: Callable[[], MacLookup], read_cache: Callable[[], MacLookup], *, fall_back: bool) -> MacLookup:
    """Return the active answer, or the cache's when this host cannot ask and the caller allowed it.

    Args:
        ask: The active lookup.
        read_cache: The passive lookup, run only when ``ask`` cannot be made.
        fall_back: Whether a host that cannot ask may read the cache instead.

    Returns:
        What ``ask`` returned - an active miss included, because "nobody
        answered just now" is the truthful reply a stale cache entry would
        contradict - or, only when ``ask`` raised one of the cannot-ask
        errors and ``fall_back`` is set, what ``read_cache`` returned.

    Raises:
        IPScoutPermissionError: ``ask`` lacked privilege and ``fall_back`` is off.
        IPScoutUnsupportedError: ``ask`` had no path and ``fall_back`` is off.
        IPScoutResolutionError: ``ask`` was given a zone naming no interface,
            whatever ``fall_back`` says; so is anything else ``ask`` raises.

    Examples:
        >>> miss = MacLookup(ip="192.0.2.7", method=MacMethod.ACTIVE)
        >>> ask_or_read_cache(lambda: miss, lambda: MacLookup(ip="192.0.2.7"), fall_back=True) is miss
        True

    """

    if not fall_back:
        return ask()
    try:
        return ask()
    except _CANNOT_ASK_ACTIVELY:
        return read_cache()


def _active_lookup(ip: str, route: RouteInfo | None, on_interface: str | None) -> MacLookup:
    """Resolve whichever address actually carries the frame: the host itself when on-link, the router when not."""

    if route is not None and route.gateway:
        found = resolve_active(ip=route.gateway)
        return MacLookup(
            ip=ip,
            mac=found,
            scope=MacScope.NEXT_HOP,
            via_ip=route.gateway,
            interface=route.interface,
            method=MacMethod.ACTIVE,
        )
    # The zoned text, not the bare address: the zone is the caller naming
    # the link, and resolve_active sends on it.
    found = resolve_active(ip=ip)
    scope = MacScope.DIRECT if found else MacScope.UNKNOWN
    return MacLookup(ip=ip, mac=found, scope=scope, interface=on_interface, method=MacMethod.ACTIVE)


def _cached_lookup(ip: str, bare: str, route: RouteInfo | None, on_interface: str | None) -> MacLookup:
    """Answer from the neighbour cache, labelling a routed answer as the router's."""

    entries = neighbours()

    if route is not None and route.gateway:
        # Routed: the only hardware address on the wire toward this
        # destination belongs to the router, so that is what is reported, and
        # it is labelled as such.
        hop = _entry_for(route.gateway, entries, interface=route.interface)
        return MacLookup(
            ip=ip,
            mac=hop.mac if hop else None,
            scope=MacScope.NEXT_HOP,
            via_ip=route.gateway,
            interface=(hop.interface if hop else route.interface),
            method=MacMethod.CACHE,
        )

    entry = _entry_for(bare, entries, interface=on_interface)
    if entry is not None:
        return MacLookup(ip=ip, mac=entry.mac, scope=MacScope.DIRECT, interface=entry.interface, method=MacMethod.CACHE)

    # On-link but not in the cache, or no route at all. Both mean the same
    # thing to a caller: nothing is known about this address yet.
    return MacLookup(ip=ip, scope=MacScope.UNKNOWN, interface=on_interface, method=MacMethod.CACHE)


def _require_active_for_fallback(*, active: bool, fallback_to_cache: bool) -> None:
    if fallback_to_cache and not active:
        msg = "fallback_to_cache=True needs active=True: without an active ask there is nothing to fall back from"
        raise ValueError(msg)


def lookup_mac(ip: str, *, active: bool = False, fallback_to_cache: bool = False) -> MacLookup:
    """Return the hardware address question answered with its scope attached.

    Args:
        ip: The address asked about. A literal, not a name.
        active: Send a real resolution request rather than reading the cache.
            Opt-in, and without ``fallback_to_cache`` it never falls back: a
            caller who asked to resolve actively gets a truthful answer or an
            error, not a stale cache entry dressed up as a fresh one.
        fallback_to_cache: With ``active``, read the cache instead when this
            host cannot ask - no privilege for the raw socket, or no interface
            that can carry the request - and say so in ``method``. An ask that
            nobody answered is still an ``ACTIVE`` answer and is never replaced
            by a cache entry. Refused without ``active``.

    Returns:
        A record carrying the address found, what it is an address *of*, and
        in ``method`` whether it was asked for or read from the cache. For an
        on-link host that is the host itself, ``scope=DIRECT``. For a routed
        address it is the next-hop router, ``scope=NEXT_HOP``, with ``via_ip``
        naming that router - which is the truthful answer, since the remote
        host's own address is not knowable from here. When nothing is known,
        ``scope=UNKNOWN`` and ``mac`` is ``None``.

    Raises:
        ValueError: ``ip`` is not an IP address literal (a host name, a
            malformed address, or a zone on an IPv4 address), or
            ``fallback_to_cache`` is set without ``active``. Refused before
            anything is sent.
        IPScoutPermissionError: ``active=True`` without the privilege the
            request needs, unless ``fallback_to_cache`` is set.
        IPScoutUnsupportedError: ``active=True`` with no interface or path
            that can carry the request, or one that could not be sent or
            heard, unless ``fallback_to_cache`` is set.
        IPScoutResolutionError: ``active=True`` with a zone that names no
            interface this host has, whatever ``fallback_to_cache`` says.

    Note:
        An address this host has no route to, or has simply not talked to, is
        an ordinary outcome reported as ``UNKNOWN`` rather than an error.

    Examples:
        >>> answer = lookup_mac("127.0.0.1")
        >>> answer.scope in {MacScope.DIRECT, MacScope.UNKNOWN}, answer.method.value
        (True, 'cache')

    """

    _require_active_for_fallback(active=active, fallback_to_cache=fallback_to_cache)
    # A zone is the caller naming the link they mean, so it steers the lookup
    # rather than travelling with the address: the cache, the routing table and
    # every packed sockaddr hold bare addresses, and comparing scoped text
    # against them matches nothing and reports a known neighbour as unknown.
    family = AddressFamily.of_version(parse_address(ip).version)
    bare, zone = split_zone(ip)
    route = query_route(bare, family)

    if not active:
        on_interface = _link_of(zone) if zone is not None else (route.interface if route else None)
        return _cached_lookup(ip, bare, route, on_interface)
    # The zone is resolved here, before anything is sent and on every
    # platform: the routed branch asks the gateway and never looks at it, and
    # Windows sends without one, so a zone naming no interface would otherwise
    # pass unseen. The resolved name, not the zone's text, is what the cache
    # read matches on: "2" names no cache entry's interface, so a numeric zone
    # would fall through to whichever link holds that address.
    on_interface = _zone_interface(zone) if zone is not None else (route.interface if route else None)
    return ask_or_read_cache(
        lambda: _active_lookup(ip, route, on_interface),
        lambda: _cached_lookup(ip, bare, route, on_interface),
        fall_back=fallback_to_cache,
    )


def get_mac_address(ip: str, *, active: bool = False, fallback_to_cache: bool = False) -> str | None:
    """Return the hardware address of an on-link host, or None if it is routed.

    Args:
        ip: The address asked about.
        active: Send a real resolution request rather than reading the cache.
        fallback_to_cache: With ``active``, read the cache when this host
            cannot ask, as :func:`lookup_mac` does. This returns only the
            address, so use :func:`lookup_mac` to learn which one answered.

    Returns:
        The address, or ``None`` when the host is not directly reachable at
        layer 2 or is simply unknown.

    Raises:
        ValueError: As :func:`lookup_mac`: ``ip`` is not an IP address
            literal, or ``fallback_to_cache`` is set without ``active``.
        IPScoutError: As :func:`lookup_mac` for ``active=True``.

    Note:
        Deliberately strict: it refuses to guess rather than quietly handing
        back the gateway's address. Use :func:`lookup_mac` for an answer that
        covers routed addresses and says what it is describing.

    Examples:
        >>> get_mac_address("8.8.8.8") is None
        True

    """

    answer = lookup_mac(ip, active=active, fallback_to_cache=fallback_to_cache)
    return answer.mac if answer.scope is MacScope.DIRECT else None
