"""Name-to-address resolution and its inverse.

Thin, honest wrappers over ``getaddrinfo`` and ``gethostbyaddr``. The value
added over calling the stdlib directly is a stable error type, deduplicated
results in a predictable order, and one place where the address-family choice
is made rather than that decision being scattered through every transport.

Contents:
    resolve: Turn a hostname or literal into a list of addresses.
    resolve_one: Pick the single address a probe should use.
    ResolvedTarget: The ``(address, family)`` record resolve_one returns.
    split_zone: Separate an address from its IPv6 ``%zone`` suffix.
    ScopedAddress: The ``(address, zone)`` record split_zone returns.
    zone_index: The interface index a zone names, by name or by number.
    interface_name: The name of an interface index, or None.
    MAX_INTERFACE_INDEX: The largest interface index a sockaddr can carry.
    reverse_dns: Turn an address back into a name.
    family_of: Classify a literal address.

Note:
    The family is resolved once, up front, and carried explicitly on the
    result, so no later stage has to guess it or infer it from a failure.

"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import TYPE_CHECKING, NamedTuple

from .errors import IPScoutResolutionError
from .models import BLANK_TARGET_MESSAGE, AddressFamily, is_blank_target, needs_zone

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

__all__ = [
    "INTERFACE_INDEX_DIGITS",
    "MAX_INTERFACE_INDEX",
    "ResolvedTarget",
    "ScopedAddress",
    "family_of",
    "interface_name",
    "resolve",
    "resolve_one",
    "reverse_dns",
    "split_zone",
    "zone_index",
]

#: What ``getaddrinfo`` puts in a sockaddr: ``(address, port)`` for IPv4, and
#: ``(address, port, flowinfo, scope_id)`` for IPv6. The link-layer form,
#: ``(protocol, address)``, is in the signature for families this never asks
#: for, and is carried here so the union matches rather than being cast away.
_SockAddr = tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes]

#: One ``getaddrinfo`` result: family, socket kind, protocol, canonical name, sockaddr.
_AddrInfo = tuple[socket.AddressFamily, socket.SocketKind, int, str, _SockAddr]

#: An ``AF_INET6`` sockaddr is four fields to an ``AF_INET`` one's two, so its
#: length is also what tells the two families apart.
_IPV6_SOCKADDR_FIELDS = 4


def family_of(address: str) -> AddressFamily | None:
    """Return the family of a literal address, or None if it is not one.

    Args:
        address: A candidate IP address literal.

    Returns:
        The matching family, or ``None`` when ``address`` is a hostname rather
        than a literal.

    Examples:
        >>> family_of("192.168.1.1") is AddressFamily.IPV4
        True
        >>> family_of("::1") is AddressFamily.IPV6
        True
        >>> family_of("example.test") is None
        True

    """

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    return AddressFamily.of_version(parsed.version)


class ScopedAddress(NamedTuple):
    """An address with its IPv6 zone held apart from it.

    A ``NamedTuple`` rather than a pydantic model on purpose: it was a plain
    ``(address, zone)`` tuple first, and callers unpack it and compare it with
    tuples. A NamedTuple keeps those working while letting new code name the
    field it wants instead of remembering which side the zone is on.

    Attributes:
        address: The address alone, which is what packing into bytes - a raw
            packet, a sockaddr, ``inet_pton`` - accepts.
        zone: The text after the ``%`` - an interface name or index - or
            ``None`` when the address named no zone.

    Examples:
        >>> scoped = ScopedAddress("fe80::1", "eth0")
        >>> scoped.address, scoped.zone
        ('fe80::1', 'eth0')
        >>> scoped == ("fe80::1", "eth0")
        True

    """

    address: str
    zone: str | None


def split_zone(address: str) -> ScopedAddress:
    """Return an address split from its IPv6 zone, if it carries one.

    RFC 4007 writes the interface an address belongs to after a ``%``:
    ``fe80::1%eth0``. Everything that packs an address into bytes - a raw
    packet, a sockaddr - needs the address alone, while everything that sends
    needs the zone as well, so the two are separated here once rather than by
    each caller guessing.

    Args:
        address: An address literal, scoped or not.

    Returns:
        A :class:`ScopedAddress`. A ``%`` with nothing after it names no zone,
        so the address comes back unchanged with ``zone`` ``None``. It is a
        tuple, so ``bare, zone = split_zone(...)`` still unpacks it.

    Examples:
        >>> split_zone("fe80::1%eth0")
        ScopedAddress(address='fe80::1', zone='eth0')
        >>> split_zone("192.168.1.1")
        ScopedAddress(address='192.168.1.1', zone=None)

    """

    bare, separator, zone = address.partition("%")
    return ScopedAddress(bare, zone) if separator and zone else ScopedAddress(address, None)


#: The digits an interface index may be written with: ASCII only, as many as a uint32 needs.
INTERFACE_INDEX_DIGITS = re.compile(r"[0-9]{1,10}")

#: A sockaddr carries the scope as an unsigned 32-bit field.
MAX_INTERFACE_INDEX = 2**32 - 1


def interface_name(index: int) -> str | None:
    """Return the name of the interface with ``index``, or None if there is none.

    Args:
        index: An interface index, as a sockaddr's scope or a route carries it.

    Returns:
        The interface's name, or ``None`` when the index is out of the range an
        index can take or no interface has it here. Index 0 means "no
        interface" everywhere, so it never names one.

    Examples:
        >>> interface_name(0) is None
        True
        >>> interface_name(-1) is None
        True
        >>> interface_name(2**32) is None
        True
        >>> import socket
        >>> known = getattr(socket, "if_nameindex", list)()
        >>> all(interface_name(index) == name for index, name in known)
        True

    """

    # Out of range is "no such interface" to a caller, never a crash, but
    # if_indextoname reports it as OverflowError past a C unsigned int and as
    # ValueError or OverflowError for a negative index depending on the Python
    # version, and as OSError for index 0. The range check settles all of them
    # the same way before the call; the except keeps the call total anyway.
    if not 1 <= index <= MAX_INTERFACE_INDEX:
        return None
    if index == MAX_INTERFACE_INDEX:
        # 0xFFFFFFFF is also (unsigned long)-1, the value CPython's integer
        # conversion reports failure with. Where an unsigned long is 32 bits
        # (Windows), some releases take it for a failed conversion and raise
        # SystemError instead of OSError (measured on CPython 3.10.11; 3.10.20
        # and 3.11 answer OSError). No interface holds that index, so it is
        # answered from the interface table, which never passes it through.
        return dict(socket.if_nameindex()).get(index)
    try:
        return socket.if_indextoname(index)
    except (OSError, ValueError, OverflowError):
        return None


def zone_index(zone: str) -> int:
    """Return the interface index a zone names, by name or by number.

    Args:
        zone: The text after the ``%`` in a scoped address, which RFC 4007
            allows to be either an interface name or its index.

    Returns:
        The index, which is what a sockaddr carries.

    Raises:
        IPScoutResolutionError: No interface goes by that name here, or the
            number is past the largest index a sockaddr can carry. That is a
            setup problem - a typo, or an interface that has gone away - so it
            raises rather than being reported as an unreachable host.

    """

    # ASCII digits only, and at most ten of them. str.isdigit() also accepts
    # superscripts (which int() then refuses with a bare ValueError) and other
    # scripts' digits (which int() silently reads, so a typo picks a real
    # interface), and an unbounded run would hit int()'s digit limit.
    if INTERFACE_INDEX_DIGITS.fullmatch(zone):
        index = int(zone)
        if index <= MAX_INTERFACE_INDEX:
            return index
        msg = f"zone {zone!r} is past the largest interface index ({MAX_INTERFACE_INDEX}): use an index or a name this host has"
        raise IPScoutResolutionError(msg)
    try:
        return socket.if_nametoindex(zone)
    except (OSError, ValueError) as exc:
        # ValueError is what if_nametoindex raises for an embedded NUL, which no
        # interface name can hold - the same "no such interface" to the caller.
        msg = f"no interface named {zone!r} to send on: name one this host has, or use its index"
        raise IPScoutResolutionError(msg) from exc


def _with_zone(sockaddr: _SockAddr, written_zone: str | None) -> str:
    """Return one ``getaddrinfo`` sockaddr as text, zone included.

    The zone the caller wrote wins, so an address hands back the text it was
    given rather than a spelling derived from an index. A resolver that
    reports a scope of its own - a name whose record carries one - is honoured
    too, because taking the address alone would silently discard which link it
    belongs to.
    """

    address = sockaddr[0]
    if not isinstance(address, str):  # pragma: no cover - a link-layer family, which is never requested here
        return str(address)
    if written_zone:
        return f"{address}%{written_zone}"
    if len(sockaddr) != _IPV6_SOCKADDR_FIELDS:
        return address
    scope = sockaddr[3]
    if not scope:
        return address
    # An index the OS no longer knows keeps its number, so the link is still named.
    return f"{address}%{interface_name(scope) or scope}"


class ResolvedTarget(NamedTuple):
    """The single address a probe should use, and the family it belongs to.

    A ``NamedTuple`` rather than a pydantic model on purpose: it was a plain
    ``(address, family)`` tuple first, and callers unpack it, index it and
    compare it with tuples. A NamedTuple keeps every one of those working while
    letting new code name the fields instead of remembering their order.

    Attributes:
        address: The address literal, with its ``%zone`` suffix when it has one.
        family: The family of ``address``, decided once here so no later stage
            has to infer it.

    Examples:
        >>> target = ResolvedTarget("127.0.0.1", AddressFamily.IPV4)
        >>> target.address, target.family is AddressFamily.IPV4
        ('127.0.0.1', True)
        >>> target == ("127.0.0.1", AddressFamily.IPV4)
        True

    """

    address: str
    family: AddressFamily


def _refuse_a_link_local_address_with_no_zone(target: str, resolved: ResolvedTarget) -> None:
    """Raise when an address cannot be sent anywhere for want of an interface.

    A link-local address is only unique on one link, so without a zone the
    kernel has no interface to send on and every probe reports the target as
    unreachable. That reads exactly like a host that is down, which is the one
    thing this library refuses to let a setup problem look like.
    """

    if resolved.family is not AddressFamily.IPV6:
        return
    bare, zone = split_zone(resolved.address)
    # The text came from getaddrinfo as an AF_INET6 result, so it parses.
    if zone is not None or not needs_zone(ipaddress.IPv6Address(bare)):
        return
    msg = f"{target!r} is a link-local address, which needs the interface to send on: write it as {bare}%<interface>"
    raise IPScoutResolutionError(msg)


def _refuse_a_malformed_zone(target: str) -> None:
    """Raise on a written zone that cannot name an interface, saying which way.

    Each of these is a different mistake with a different fix, and all four
    used to arrive as one message - "resolver returned an unparseable address"
    - which reports what the resolver did rather than what the caller got
    wrong, or as a bare "cannot resolve", which reads as a name that does not
    exist. A zone is checked here, at the boundary, because every one of these
    is a malformed target rather than a fact about the network.
    """

    if "%" not in target:
        return
    bare, zone = split_zone(target)
    # split_zone names no zone for a % with nothing after it, so with a % present
    # a None zone is exactly that trailing-% mistake.
    if zone is None:
        msg = f"{target!r} ends with % but names no interface: write one after it, or drop the %"
        raise IPScoutResolutionError(msg)
    if "%" in zone:
        # The reflex on seeing an unreachable link-local is to add an
        # interface, and doing that to an answer that already names one - as
        # everything this library returns now does - lands exactly here.
        msg = f"{target!r} names more than one interface: an address carries one zone, written once after a single %"
        raise IPScoutResolutionError(msg)

    literal = family_of(bare)
    if literal is AddressFamily.IPV4:
        msg = f"{target!r} is an IPv4 address with a zone: an interface belongs to an IPv6 link-local address and to nothing else"
        raise IPScoutResolutionError(msg)
    if literal is None:
        msg = f"{target!r} puts a zone on {bare!r}, which is not an address literal: an interface can only be written after one"
        raise IPScoutResolutionError(msg)
    try:
        ipaddress.ip_address(target)
    except ValueError as exc:
        msg = f"{zone!r} is not a usable interface name in {target!r}: {exc}"
        raise IPScoutResolutionError(msg) from exc


def _dedupe(items: Iterable[ResolvedTarget]) -> list[ResolvedTarget]:
    """Return items with repeated addresses removed, first occurrence order kept."""

    seen: set[str] = set()
    ordered: list[ResolvedTarget] = []
    for item in items:
        if item.address not in seen:
            seen.add(item.address)
            ordered.append(item)
    return ordered


def _resolved_targets(infos: Iterable[_AddrInfo], written_zone: str | None) -> Iterator[ResolvedTarget]:
    """Yield each ``getaddrinfo`` result as its address text and the family it came with."""

    # Only AF_INET and AF_INET6 are asked for, but a resolver is outside this
    # library: a result of any other family is skipped rather than labelled
    # IPv4, which would hand a probe an address it cannot send to.
    for socket_family, _kind, _proto, _canonname, sockaddr in infos:
        family = AddressFamily.of_socket_family(socket_family)
        if family is None:
            continue
        yield ResolvedTarget(_with_zone(sockaddr, written_zone), family)


def _no_address_of_family(target: str, family: AddressFamily) -> IPScoutResolutionError:
    """Return the refusal for a target that holds no address of ``family``.

    Raised from two places - a literal of the other family, and a literal the
    resolver then refuses for the requested one - and both must read the same,
    because the caller's remedy is the same: drop or flip the family flag.
    """

    return IPScoutResolutionError(f"{target!r} has no {family.value} address")


def resolve(target: str, *, family: AddressFamily | None = None) -> list[str]:
    """Return the addresses ``target`` resolves to.

    Args:
        target: A hostname or an IP address literal.
        family: Restrict to one family. ``None`` accepts whichever families
            the resolver returns, preserving its preference order.

    Returns:
        Addresses as strings, deduplicated, in resolver order.

    Raises:
        IPScoutResolutionError: The name does not resolve, or resolves to no
            address in the requested family. These are separate causes with
            the same consequence, and the message distinguishes them.

    Examples:
        >>> resolve("127.0.0.1")
        ['127.0.0.1']
        >>> resolve("::1", family=AddressFamily.IPV6)
        ['::1']

        Asking for a family the target does not have is an error, not an
        empty list, because silently returning nothing reads as "host down":

        >>> resolve("127.0.0.1", family=AddressFamily.IPV6)
        Traceback (most recent call last):
        ...
        ipscout.errors.IPScoutResolutionError: '127.0.0.1' has no ipv6 address

    """

    return [resolved.address for resolved in _resolve(target, family=family)]


def _resolve(target: str, *, family: AddressFamily | None) -> list[ResolvedTarget]:
    """Return each address ``target`` resolves to, with the family the resolver gave it.

    The family is the one ``getaddrinfo`` reports beside each address, so no
    later stage parses the text again to rediscover it.
    """

    # A blank target is a caller mistake, but resolvers disagree about it:
    # Windows happily resolves "" to the local host, so is_reachable("") would
    # answer True. Reject it here so every platform agrees.
    if is_blank_target(target):
        raise IPScoutResolutionError(BLANK_TARGET_MESSAGE)

    # Decide a literal's family before consulting the resolver, because the
    # resolvers disagree here too: asking macOS for the IPv6 address of an IPv4
    # literal succeeds, returning a v4-mapped ::ffff: form, while Linux fails.
    # Neither is a usable IPv6 address for the caller, so settle it up front.
    literal = family_of(target)
    if family is not None and literal is not None and literal is not family:
        raise _no_address_of_family(target, family)

    # The zone comes off before the resolver sees it, because the resolvers
    # disagree about it as well: Windows getaddrinfo refuses an interface NAME
    # and accepts only an index (measured), so passing scoped text through
    # would make an address that exists on Linux fail to resolve there. It is
    # re-attached to every result below, and the interface it names is checked
    # where it is actually needed, at the send.
    _refuse_a_malformed_zone(target)
    lookup, written_zone = split_zone(target)
    requested = family.socket_family if family is not None else socket.AF_UNSPEC
    try:
        infos = socket.getaddrinfo(lookup, None, requested, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        # Distinguish "no such name" from "name exists, wrong family", because
        # the caller's next move differs: fix the name, or drop the -4/-6 flag.
        if family is not None and literal is not None:
            raise _no_address_of_family(target, family) from exc
        if family is not None:
            msg = f"cannot resolve {target!r} to an {family.value} address: {exc.strerror or exc}"
            raise IPScoutResolutionError(msg) from exc
        msg = f"cannot resolve {target!r}: {exc.strerror or exc}"
        raise IPScoutResolutionError(msg) from exc

    addresses = _dedupe(_resolved_targets(infos, written_zone))
    if not addresses:
        msg = f"{target!r} resolved to no usable address"
        raise IPScoutResolutionError(msg)
    return addresses


def resolve_one(target: str, *, family: AddressFamily | None = None) -> ResolvedTarget:
    """Return the single address a probe should use, plus its family.

    Args:
        target: A hostname or an IP address literal.
        family: Restrict to one family, or accept the resolver's preference.

    Returns:
        A :class:`ResolvedTarget`. It is a tuple, so ``address, family =
        resolve_one(...)`` still unpacks it.

    Raises:
        IPScoutResolutionError: As :func:`resolve`.

    Examples:
        >>> resolve_one("127.0.0.1")
        ResolvedTarget(address='127.0.0.1', family=<AddressFamily.IPV4: 'ipv4'>)
        >>> resolved = resolve_one("::1")
        >>> resolved.address, resolved.family is AddressFamily.IPV6
        ('::1', True)

    """

    resolved = _resolve(target, family=family)[0]
    _refuse_a_link_local_address_with_no_zone(target, resolved)
    return resolved


def reverse_dns(ip: str) -> str | None:
    """Return the hostname for an address, or None when there is no PTR record.

    Args:
        ip: An IP address literal.

    Returns:
        The resolved name, or ``None`` when the lookup fails. A missing PTR
        record is a completely normal state of the world, not an error, so
        this returns rather than raising.

    Examples:
        >>> reverse_dns("127.0.0.1") is not None
        True
        >>> reverse_dns("this is not an address") is None
        True

    """

    try:
        # An empty PTR answer names nothing, the same as no record at all.
        return socket.gethostbyaddr(ip)[0] or None
    except (OSError, UnicodeError):
        return None
