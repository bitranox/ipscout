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

from .errors import IPScoutUnsupportedError
from .interfaces import local_interfaces
from .models import AddressFamily, MacLookup, MacScope, Neighbour
from .routes import query_route

__all__ = ["get_mac_address", "lookup_mac", "neighbours", "normalise_mac", "resolve_active"]

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"

#: Separators seen in written hardware addresses: colons, hyphens, and the
#: dotted form Cisco equipment uses.
_SEPARATORS = str.maketrans("", "", ":-.")

#: An Ethernet address is six octets, so twelve hex digits once stripped.
_MAC_DIGITS = 12


def normalise_mac(mac: str) -> str | None:
    """Return a hardware address in one canonical form for comparison.

    Args:
        mac: An address in any common written form - ``aa:bb:cc:dd:ee:ff``,
            ``AA-BB-CC-DD-EE-FF`` or ``aabb.ccdd.eeff``.

    Returns:
        The lowercase colon-separated form, or ``None`` when the input is not
        an Ethernet address at all.

    Examples:
        >>> normalise_mac("AA-BB-CC-DD-EE-FF")
        'aa:bb:cc:dd:ee:ff'
        >>> normalise_mac("aabb.ccdd.eeff")
        'aa:bb:cc:dd:ee:ff'
        >>> normalise_mac("nonsense") is None
        True

    """

    digits = mac.translate(_SEPARATORS).lower()
    if len(digits) != _MAC_DIGITS or any(character not in "0123456789abcdef" for character in digits):
        return None
    return ":".join(digits[index : index + 2] for index in range(0, _MAC_DIGITS, 2))


def neighbours() -> tuple[Neighbour, ...]:
    """Return every entry this host's neighbour cache currently holds.

    Returns:
        One record per entry, across both address families. Entries with no
        learned hardware address are not included: an unanswered query is not
        a neighbour this host knows.

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
    return list_neighbours()


def _sending_interface(ip: str, family: AddressFamily) -> tuple[str, str, str]:
    """Return the interface, source address and hardware address to send from.

    An ARP request is answered to the address it came from, so a source on the
    wrong subnet gets no reply at all. The route lookup names the interface,
    and its own addresses supply the rest.

    Raises:
        IPScoutUnsupportedError: No interface on this host can reach that
            address, or the one that can has no hardware address (loopback and
            tunnels have none, and there is nothing to ARP over).
    """

    route = query_route(ip, family)
    name = route.interface if route else None
    if name is None:
        msg = f"no route to {ip}, so no interface to send a resolution request on"
        raise IPScoutUnsupportedError(msg)

    for candidate in local_interfaces():
        if candidate.name != name:
            continue
        if not candidate.mac:
            msg = f"{name} has no hardware address, so it cannot carry an address-resolution request"
            raise IPScoutUnsupportedError(msg)
        source = route.source if route and route.source else next((entry.address for entry in candidate.ipv4), None)
        if family is AddressFamily.IPV4 and source is None:
            msg = f"{name} has no IPv4 address to send from"
            raise IPScoutUnsupportedError(msg)
        return name, source or "0.0.0.0", candidate.mac  # noqa: S104  # nosec B104

    msg = f"the route to {ip} names interface {name!r}, which is not among this host's interfaces"
    raise IPScoutUnsupportedError(msg)


def resolve_active(ip: str, *, timeout: float = 2.0) -> str | None:
    """Actively resolve one address, sending a real request rather than reading.

    Args:
        ip: The address to resolve.
        timeout: Seconds to wait for an answer.

    Returns:
        The hardware address, or ``None`` when nothing answered in time.

    Raises:
        IPScoutPermissionError: The process lacks the privilege the send
            needs - root or ``CAP_NET_RAW`` on Linux, root on macOS. The
            message names the remedy, including the unprivileged alternative.
        IPScoutUnsupportedError: There is no interface that can carry the
            request, or the platform has no active path for that family.

    Note:
        Windows IPv4 is the one case that needs no elevation, through
        ``SendARP``. Everywhere else this sends a real ARP request or ICMPv6
        neighbour solicitation over a raw socket, which needs privilege.

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

    family = AddressFamily.IPV6 if ":" in ip else AddressFamily.IPV4

    if IS_WINDOWS:  # pragma: no cover - exercised on Windows CI only
        from .neighbours_windows import resolve_active as _windows_resolve  # noqa: PLC0415 - Windows-only import

        return _windows_resolve(ip)

    interface, source_ip, source_mac = _sending_interface(ip, family)

    if IS_MACOS:  # pragma: no cover - exercised on macOS CI only
        from .neighbours_macos import resolve_active_ipv4, resolve_active_ipv6  # noqa: PLC0415 - macOS-only import
    else:
        from .neighbours_linux import resolve_active_ipv4, resolve_active_ipv6  # noqa: PLC0415 - Linux-only import

    if family is AddressFamily.IPV6:
        return resolve_active_ipv6(ip, interface=interface, source_mac=source_mac, timeout=timeout)
    return resolve_active_ipv4(ip, interface=interface, source_ip=source_ip, source_mac=source_mac, timeout=timeout)


def _entry_for(ip: str, entries: tuple[Neighbour, ...]) -> Neighbour | None:
    """Return the cache entry for one address, if it is known."""

    for entry in entries:
        if entry.ip == ip:
            return entry
    return None


def lookup_mac(ip: str, *, active: bool = False) -> MacLookup:
    """Return the hardware address question answered with its scope attached.

    Args:
        ip: The address asked about. A literal, not a name.
        active: Send a real resolution request rather than reading the cache.
            Opt-in, and it never silently falls back: a caller who asked to
            resolve actively gets a truthful answer or an error, not a stale
            cache entry dressed up as a fresh one.

    Returns:
        A record carrying the address found and what it is an address *of*.
        For an on-link host that is the host itself, ``scope=DIRECT``. For a
        routed address it is the next-hop router, ``scope=NEXT_HOP``, with
        ``via_ip`` naming that router - which is the truthful answer, since
        the remote host's own address is not knowable from here. When nothing
        is known, ``scope=UNKNOWN`` and ``mac`` is ``None``.

    Raises:
        IPScoutUnsupportedError: ``active=True`` on a platform with no
            unprivileged active path. The passive default never raises.

    Note:
        Passively, this never raises: an address this host has no route to, or
        has simply not talked to, is an ordinary outcome reported as
        ``UNKNOWN`` rather than an error.

    Examples:
        >>> answer = lookup_mac("127.0.0.1")
        >>> answer.scope in {MacScope.DIRECT, MacScope.UNKNOWN}
        True

    """

    family = AddressFamily.IPV6 if ":" in ip else AddressFamily.IPV4
    route = query_route(ip, family)

    if active:
        # Resolve whichever address actually carries the frame: the host
        # itself when on-link, the router when not. Falling back to the cache
        # for the routed case would make active=True silently passive, which
        # is the one thing this flag must never do.
        if route is not None and route.gateway:
            found = resolve_active(ip=route.gateway)
            return MacLookup(ip=ip, mac=found, scope=MacScope.NEXT_HOP, via_ip=route.gateway, interface=route.interface)
        found = resolve_active(ip=ip)
        scope = MacScope.DIRECT if found else MacScope.UNKNOWN
        return MacLookup(ip=ip, mac=found, scope=scope, interface=route.interface if route else None)

    entries = neighbours()

    if route is not None and route.gateway:
        # Routed: the only hardware address on the wire toward this
        # destination belongs to the router, so that is what is reported, and
        # it is labelled as such.
        hop = _entry_for(route.gateway, entries)
        return MacLookup(
            ip=ip,
            mac=hop.mac if hop else None,
            scope=MacScope.NEXT_HOP,
            via_ip=route.gateway,
            interface=(hop.interface if hop else route.interface),
        )

    entry = _entry_for(ip, entries)
    if entry is not None:
        return MacLookup(ip=ip, mac=entry.mac, scope=MacScope.DIRECT, interface=entry.interface)

    # On-link but not in the cache, or no route at all. Both mean the same
    # thing to a caller: nothing is known about this address yet.
    return MacLookup(ip=ip, scope=MacScope.UNKNOWN, interface=route.interface if route else None)


def get_mac_address(ip: str, *, active: bool = False) -> str | None:
    """Return the hardware address of an on-link host, or None if it is routed.

    Args:
        ip: The address asked about.
        active: Send a real resolution request rather than reading the cache.

    Returns:
        The address, or ``None`` when the host is not directly reachable at
        layer 2 or is simply unknown.

    Note:
        Deliberately strict: it refuses to guess rather than quietly handing
        back the gateway's address. Use :func:`lookup_mac` for an answer that
        covers routed addresses and says what it is describing.

    Examples:
        >>> get_mac_address("8.8.8.8") is None
        True

    """

    answer = lookup_mac(ip, active=active)
    return answer.mac if answer.scope is MacScope.DIRECT else None
