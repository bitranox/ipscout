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

__all__ = ["family_of", "resolve", "resolve_one", "reverse_dns"]

_SOCKET_FAMILY = {
    AddressFamily.IPV4: socket.AF_INET,
    AddressFamily.IPV6: socket.AF_INET6,
}


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

    requested = _SOCKET_FAMILY.get(family) if family is not None else socket.AF_UNSPEC
    try:
        infos = socket.getaddrinfo(target, None, requested or socket.AF_UNSPEC, socket.SOCK_DGRAM)
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

    addresses = _dedupe(str(info[4][0]) for info in infos)
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
    resolved = family_of(address)
    if resolved is None:  # pragma: no cover - getaddrinfo always returns literals
        msg = f"resolver returned an unparseable address for {target!r}: {address!r}"
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
