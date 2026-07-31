"""Name-to-address resolution and its inverse.

Thin, honest wrappers over ``getaddrinfo`` and ``gethostbyaddr``. The value
added over calling the stdlib directly is a stable error type, deduplicated
results in a predictable order, and one place where the address-family choice
is made rather than that decision being scattered through every transport.

Contents:
    resolve: Turn a hostname or literal into a list of addresses.
    resolve_one: Pick the single address a probe should use.
    reverse_dns: Turn an address back into a name.
    family_of: Classify a literal address.

Note:
    The family is resolved once, up front, and carried explicitly on the
    result, so no later stage has to guess it or infer it from a failure.

"""

from __future__ import annotations

import ipaddress
import socket
from typing import TYPE_CHECKING

from .errors import IPScoutResolutionError
from .models import AddressFamily

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = ["family_of", "resolve", "resolve_one", "reverse_dns", "split_zone", "zone_index"]

_SOCKET_FAMILY = {
    AddressFamily.IPV4: socket.AF_INET,
    AddressFamily.IPV6: socket.AF_INET6,
}

#: What ``getaddrinfo`` puts in a sockaddr: ``(address, port)`` for IPv4, and
#: ``(address, port, flowinfo, scope_id)`` for IPv6. The link-layer form,
#: ``(protocol, address)``, is in the signature for families this never asks
#: for, and is carried here so the union matches rather than being cast away.
_SockAddr = tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes]

#: An ``AF_INET6`` sockaddr is four fields to an ``AF_INET`` one's two, so its
#: length is also what tells the two families apart.
_IPV6_SOCKADDR_FIELDS = 4

#: Compared against ``ip_address().version``, which speaks numbers.
_IPV6_VERSION = 6


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
    return AddressFamily.IPV6 if parsed.version == 6 else AddressFamily.IPV4  # noqa: PLR2004


def split_zone(address: str) -> tuple[str, str | None]:
    """Return an address split from its IPv6 zone, if it carries one.

    RFC 4007 writes the interface an address belongs to after a ``%``:
    ``fe80::1%eth0``. Everything that packs an address into bytes - a raw
    packet, a sockaddr - needs the address alone, while everything that sends
    needs the zone as well, so the two are separated here once rather than by
    each caller guessing.

    Examples:
        >>> split_zone("fe80::1%eth0")
        ('fe80::1', 'eth0')
        >>> split_zone("192.168.1.1")
        ('192.168.1.1', None)

    """

    bare, separator, zone = address.partition("%")
    return (bare, zone) if separator and zone else (address, None)


def zone_index(zone: str) -> int:
    """Return the interface index a zone names, by name or by number.

    Args:
        zone: The text after the ``%`` in a scoped address, which RFC 4007
            allows to be either an interface name or its index.

    Returns:
        The index, which is what a sockaddr carries.

    Raises:
        IPScoutResolutionError: No interface goes by that name here. That is a
            setup problem - a typo, or a interface that has gone away - so it
            raises rather than being reported as an unreachable host.

    """

    if zone.isdigit():
        return int(zone)
    try:
        return socket.if_nametoindex(zone)
    except OSError as exc:
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
    try:
        return f"{address}%{socket.if_indextoname(scope)}"
    except OSError:  # pragma: no cover - an index the OS no longer knows
        return f"{address}%{scope}"


def _refuse_a_link_local_address_with_no_zone(target: str, address: str) -> None:
    """Raise when an address cannot be sent anywhere for want of an interface.

    A link-local address is only unique on one link, so without a zone the
    kernel has no interface to send on and every probe reports the target as
    unreachable. That reads exactly like a host that is down, which is the one
    thing this library refuses to let a setup problem look like.
    """

    bare, zone = split_zone(address)
    if zone is not None:
        return
    try:
        parsed = ipaddress.ip_address(bare)
    except ValueError:  # pragma: no cover - the address came from getaddrinfo
        return
    if parsed.version != _IPV6_VERSION or not parsed.is_link_local:
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

    bare, separator, zone = target.partition("%")
    if not separator:
        return
    if not zone:
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


def _dedupe(items: Iterable[str]) -> list[str]:
    """Return items with duplicates removed, first occurrence order kept."""

    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


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

    # A blank target is a caller mistake, but resolvers disagree about it:
    # Windows happily resolves "" to the local host, so is_reachable("") would
    # answer True. Reject it here so every platform agrees.
    if not target or not target.strip():
        msg = "target must not be empty"
        raise IPScoutResolutionError(msg)

    # Decide a literal's family before consulting the resolver, because the
    # resolvers disagree here too: asking macOS for the IPv6 address of an IPv4
    # literal succeeds, returning a v4-mapped ::ffff: form, while Linux fails.
    # Neither is a usable IPv6 address for the caller, so settle it up front.
    literal = family_of(target)
    if family is not None and literal is not None and literal is not family:
        msg = f"{target!r} has no {family.value} address"
        raise IPScoutResolutionError(msg)

    # The zone comes off before the resolver sees it, because the resolvers
    # disagree about it as well: Windows getaddrinfo refuses an interface NAME
    # and accepts only an index (measured), so passing scoped text through
    # would make an address that exists on Linux fail to resolve there. It is
    # re-attached to every result below, and the interface it names is checked
    # where it is actually needed, at the send.
    _refuse_a_malformed_zone(target)
    lookup, written_zone = split_zone(target)
    requested = _SOCKET_FAMILY.get(family) if family is not None else socket.AF_UNSPEC
    try:
        infos = socket.getaddrinfo(lookup, None, requested or socket.AF_UNSPEC, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        # Distinguish "no such name" from "name exists, wrong family", because
        # the caller's next move differs: fix the name, or drop the -4/-6 flag.
        if family is not None and family_of(target) is not None:
            msg = f"{target!r} has no {family.value} address"
            raise IPScoutResolutionError(msg) from exc
        if family is not None:
            msg = f"cannot resolve {target!r} to an {family.value} address: {exc.strerror or exc}"
            raise IPScoutResolutionError(msg) from exc
        msg = f"cannot resolve {target!r}: {exc.strerror or exc}"
        raise IPScoutResolutionError(msg) from exc

    addresses = _dedupe(_with_zone(info[4], written_zone) for info in infos)
    if not addresses:
        msg = f"{target!r} resolved to no usable address"
        raise IPScoutResolutionError(msg)
    return addresses


def resolve_one(target: str, *, family: AddressFamily | None = None) -> tuple[str, AddressFamily]:
    """Return the single address a probe should use, plus its family.

    Args:
        target: A hostname or an IP address literal.
        family: Restrict to one family, or accept the resolver's preference.

    Returns:
        An ``(address, family)`` pair.

    Raises:
        IPScoutResolutionError: As :func:`resolve`.

    Examples:
        >>> resolve_one("127.0.0.1")
        ('127.0.0.1', <AddressFamily.IPV4: 'ipv4'>)
        >>> address, fam = resolve_one("::1")
        >>> address, fam is AddressFamily.IPV6
        ('::1', True)

    """

    address = resolve(target, family=family)[0]
    _refuse_a_link_local_address_with_no_zone(target, address)
    resolved = family_of(address)
    if resolved is None:  # pragma: no cover - every way of getting here is refused by name in resolve()
        # A backstop, not a diagnosis. Every known way to produce an address
        # this cannot classify is a malformed zone, and each of those is
        # refused in resolve() with a message naming the specific mistake; the
        # comment here used to claim the case was impossible, which was how
        # four real inputs came to share one useless message. If this ever
        # fires, the input that reached it belongs in _refuse_a_malformed_zone
        # with a message of its own.
        msg = f"{target!r} resolved to {address!r}, which is not an address this host can use, and no more specific reason was recognised - please report it"
        raise IPScoutResolutionError(msg)
    return address, resolved


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
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None
