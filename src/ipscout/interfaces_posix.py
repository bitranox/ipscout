"""Local interface enumeration on POSIX, via ``getifaddrs``.

One libc call returns every interface with its addresses, netmasks and hardware
address, which is why this is preferred over reading ``/sys`` (Linux-only) or
shelling out to ``ifconfig`` (a subprocess, which this library never spawns).

Contents:
    list_interfaces: Enumerate every interface this host has.

Where Linux and BSD disagree, and why it matters:

    **The sockaddr header.** Linux begins a ``sockaddr`` with a two-byte
    ``sa_family``. BSD - and therefore macOS - begins it with a one-byte
    ``sa_len`` followed by a one-byte ``sa_family``. Read the wrong one and
    every address is attributed to the wrong family, usually silently.

    **The link-layer address.** Linux reports it as ``AF_PACKET`` in a
    ``sockaddr_ll``, where the address sits at a fixed offset. macOS reports it
    as ``AF_LINK`` in a ``sockaddr_dl``, where the address sits *after* a
    variable-length interface name and must be located by reading two length
    fields first.

    The address fields themselves happen to land at the same offsets in both
    (4 for IPv4, 8 for IPv6), because BSD's extra length byte replaces the high
    byte of the two-byte family. That coincidence is relied on deliberately and
    is noted here so nobody "simplifies" the family read to match.

Note:
    Every field is bounds-checked before it is read. A malformed or truncated
    entry is skipped rather than trusted, because this walks memory handed over
    by libc and a wrong length would otherwise read past the buffer.

"""

from __future__ import annotations

import ctypes
import ipaddress
import socket
import sys
from dataclasses import dataclass, field

from .models import Interface

__all__ = ["list_interfaces"]

#: BSD keeps a length byte in front of the family; Linux does not.
_BSD_SOCKADDR = sys.platform != "linux"

#: Interface flags, identical on Linux and BSD.
_IFF_UP = 0x1
_IFF_LOOPBACK = 0x8

#: Link-layer family. Linux spells it AF_PACKET, BSD spells it AF_LINK.
_AF_PACKET = getattr(socket, "AF_PACKET", 17)
_AF_LINK = getattr(socket, "AF_LINK", 18)

#: Offsets of the address bytes within each sockaddr. The same on both
#: platforms, for the reason set out in the module docstring.
_IPV4_ADDR_OFFSET = 4
_IPV6_ADDR_OFFSET = 8

_IPV4_LEN = 4
_IPV6_LEN = 16

#: sockaddr_ll (Linux): family(2) protocol(2) ifindex(4) hatype(2) pkttype(1)
#: halen(1) addr(8)
_LL_HALEN_OFFSET = 11
_LL_ADDR_OFFSET = 12

#: sockaddr_dl (BSD): len(1) family(1) index(2) type(1) nlen(1) alen(1) slen(1)
#: then the name followed by the address.
_DL_NLEN_OFFSET = 5
_DL_ALEN_OFFSET = 6
_DL_DATA_OFFSET = 8

#: Generous ceiling for how much of a sockaddr may be read.
_SOCKADDR_MAX = 128


class _SockAddr(ctypes.Structure):
    """Just enough of ``struct sockaddr`` to read the family and the bytes."""

    _fields_ = (
        ("sa_family", ctypes.c_uint16),
        ("sa_data", ctypes.c_ubyte * 126),
    )


class _IfAddrs(ctypes.Structure):
    """``struct ifaddrs``. The layout is the same on Linux and BSD."""


# A struct that points at itself cannot name its own type inside the class
# body, so ctypes requires the fields to be attached afterwards.
_IfAddrs._fields_ = (
    ("ifa_next", ctypes.POINTER(_IfAddrs)),
    ("ifa_name", ctypes.c_char_p),
    ("ifa_flags", ctypes.c_uint),
    ("ifa_addr", ctypes.POINTER(_SockAddr)),
    ("ifa_netmask", ctypes.POINTER(_SockAddr)),
    ("ifa_broadaddr", ctypes.POINTER(_SockAddr)),
    ("ifa_data", ctypes.c_void_p),
)


def _family_of(sockaddr: _SockAddr) -> int:
    """Return the address family, reading it where this platform keeps it."""

    if _BSD_SOCKADDR:
        # BSD: sa_len occupies byte 0, sa_family byte 1. Reading the 16-bit
        # field and taking the high byte gets the family on a little-endian
        # host without a second structure definition.
        return (sockaddr.sa_family >> 8) & 0xFF
    return sockaddr.sa_family


def _raw_bytes(sockaddr: _SockAddr) -> bytes:
    """Return the sockaddr as bytes, bounded so a bad length cannot overrun."""

    return bytes(bytearray(ctypes.string_at(ctypes.byref(sockaddr), _SOCKADDR_MAX)))


def _address_of(sockaddr: _SockAddr) -> tuple[int, str] | None:
    """Return the family and text address, or None if it is not IP."""

    family = _family_of(sockaddr)
    raw = _raw_bytes(sockaddr)
    if family == socket.AF_INET:
        chunk = raw[_IPV4_ADDR_OFFSET : _IPV4_ADDR_OFFSET + _IPV4_LEN]
        if len(chunk) != _IPV4_LEN:
            return None
        return family, socket.inet_ntop(socket.AF_INET, chunk)
    if family == socket.AF_INET6:
        chunk = raw[_IPV6_ADDR_OFFSET : _IPV6_ADDR_OFFSET + _IPV6_LEN]
        if len(chunk) != _IPV6_LEN:
            return None
        return family, socket.inet_ntop(socket.AF_INET6, chunk)
    return None


def _prefix_length(netmask: _SockAddr | None, family: int) -> int:
    """Return the prefix length a netmask represents.

    Counts set bits rather than assuming a contiguous mask, then reports the
    count. A non-contiguous mask is illegal in modern practice and would be
    misreported by any scheme, so the bit count is the honest summary.
    """

    if netmask is None:
        return _IPV6_LEN * 8 if family == socket.AF_INET6 else _IPV4_LEN * 8
    raw = _raw_bytes(netmask)
    offset, length = (_IPV6_ADDR_OFFSET, _IPV6_LEN) if family == socket.AF_INET6 else (_IPV4_ADDR_OFFSET, _IPV4_LEN)
    return sum(bin(byte).count("1") for byte in raw[offset : offset + length])


def _mac_of(sockaddr: _SockAddr) -> str | None:
    """Return the hardware address from a link-layer sockaddr, if it holds one."""

    family = _family_of(sockaddr)
    raw = _raw_bytes(sockaddr)

    if family == _AF_PACKET and not _BSD_SOCKADDR:
        halen = raw[_LL_HALEN_OFFSET]
        if not 1 <= halen <= 8:  # noqa: PLR2004 - a hardware address is never longer
            return None
        chunk = raw[_LL_ADDR_OFFSET : _LL_ADDR_OFFSET + halen]
    elif family == _AF_LINK and _BSD_SOCKADDR:
        # The address follows a variable-length interface name, so both
        # lengths have to be read before the address can be located at all.
        nlen = raw[_DL_NLEN_OFFSET]
        alen = raw[_DL_ALEN_OFFSET]
        if not 1 <= alen <= 8 or nlen > 64:  # noqa: PLR2004 - defensive bounds on libc-supplied lengths
            return None
        start = _DL_DATA_OFFSET + nlen
        chunk = raw[start : start + alen]
    else:
        return None

    if len(chunk) < 1 or not any(chunk):
        return None
    return ":".join(f"{byte:02x}" for byte in chunk)


def _libc() -> ctypes.CDLL:
    """Return a handle to libc with the two calls declared."""

    lib = ctypes.CDLL(None, use_errno=True)
    lib.getifaddrs.argtypes = (ctypes.POINTER(ctypes.POINTER(_IfAddrs)),)
    lib.getifaddrs.restype = ctypes.c_int
    lib.freeifaddrs.argtypes = (ctypes.POINTER(_IfAddrs),)
    lib.freeifaddrs.restype = None
    return lib


def _no_addresses() -> list[tuple[str, int]]:
    """Return an empty address list.

    A named factory rather than the bare ``list``, which a strict checker reads
    as ``list[Unknown]`` and cannot reconcile with the declared element type.
    """

    return []


@dataclass(slots=True)
class _Accumulator:
    """Fields gathered for one interface as the linked list is walked.

    A typed accumulator rather than a dict, so the address lists keep their
    element type all the way through to the frozen public record.
    """

    flags: int = 0
    ipv4: list[tuple[str, int]] = field(default_factory=_no_addresses)
    ipv6: list[tuple[str, int]] = field(default_factory=_no_addresses)
    mac: str | None = None

    def to_interface(self, name: str) -> Interface:
        """Return the immutable public record for this interface."""

        return Interface(
            name=name,
            ipv4=tuple(self.ipv4),
            ipv6=tuple(self.ipv6),
            mac=self.mac,
            is_up=bool(self.flags & _IFF_UP),
            is_loopback=bool(self.flags & _IFF_LOOPBACK),
        )


def _absorb(record: _Accumulator, entry: _IfAddrs) -> None:
    """Fold one linked-list entry into the interface being assembled."""

    if not entry.ifa_addr:
        return
    sockaddr = entry.ifa_addr.contents

    mac = _mac_of(sockaddr)
    if mac is not None:
        record.mac = mac
        return

    found = _address_of(sockaddr)
    if found is None:
        return
    family, text = found
    netmask = entry.ifa_netmask.contents if entry.ifa_netmask else None
    pair = (text, _prefix_length(netmask, family))
    if family == socket.AF_INET6:
        record.ipv6.append(pair)
    else:
        record.ipv4.append(pair)


def list_interfaces() -> list[Interface]:
    """Return every local interface with its addresses and hardware address.

    Returns:
        One :class:`~ipscout.models.Interface` per interface, in the order libc
        reports them. An interface with no addresses is still listed, because a
        down interface is a fact worth reporting.

    Examples:
        >>> interfaces = list_interfaces()
        >>> any(item.is_loopback for item in interfaces)
        True

    """

    lib = _libc()
    head = ctypes.POINTER(_IfAddrs)()
    if lib.getifaddrs(ctypes.byref(head)) != 0:  # pragma: no cover - libc failure
        return []

    collected: dict[str, _Accumulator] = {}
    try:
        cursor = head
        while cursor:
            entry = cursor.contents
            name = entry.ifa_name.decode(errors="replace") if entry.ifa_name else ""
            if name:
                record = collected.setdefault(name, _Accumulator(flags=entry.ifa_flags))
                _absorb(record, entry)
            cursor = entry.ifa_next
    finally:
        lib.freeifaddrs(head)

    return [record.to_interface(name) for name, record in collected.items()]


def network_of(address: str, prefix_len: int) -> str:
    """Return the CIDR network an address belongs to.

    Args:
        address: An IPv4 or IPv6 address.
        prefix_len: Prefix length in bits.

    Returns:
        The network in CIDR form.

    Examples:
        >>> network_of("192.168.1.55", 24)
        '192.168.1.0/24'
        >>> network_of("10.1.2.3", 8)
        '10.0.0.0/8'

    """

    return str(ipaddress.ip_network(f"{address}/{prefix_len}", strict=False))
