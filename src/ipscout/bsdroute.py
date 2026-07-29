"""BSD routing-socket plumbing shared by the macOS route and neighbour backends.

Contents:
    RT_MSGHDR: The fixed header every routing message starts with.
    split_sockaddrs: Split the self-describing addresses trailing a message.
    address_of: Read an IP address out of one sockaddr.
    link_address_of: Read a hardware address out of a ``sockaddr_dl``.
    sysctl: Read a kernel MIB into bytes.
    roundup: The alignment the routing socket uses between addresses.

Note:
    The walkers are pure functions over bytes, which is what lets the wire
    formats above them be tested on Linux, where none of this can execute.

"""

from __future__ import annotations

import ctypes
import ctypes.util
import socket
import struct

from pydantic import BaseModel, ConfigDict

__all__ = [
    "RTA_BRD",
    "RTA_DST",
    "RTA_GATEWAY",
    "RTA_IFA",
    "RTA_IFP",
    "RTA_NETMASK",
    "RTF_GATEWAY",
    "RTF_LLINFO",
    "RTF_UP",
    "RT_MSGHDR",
    "SockaddrSet",
    "address_of",
    "link_address_of",
    "roundup",
    "split_sockaddrs",
    "sysctl",
]

#: PF_ROUTE, and the sysctl selectors the dumps use.
CTL_NET = 4
PF_ROUTE = 17
NET_RT_DUMP = 1
NET_RT_FLAGS = 2

#: Bits in rtm_addrs saying which sockaddrs follow the header, in this order.
RTA_DST = 0x01
RTA_GATEWAY = 0x02
RTA_NETMASK = 0x04
RTA_GENMASK = 0x08
RTA_IFP = 0x10
RTA_IFA = 0x20
RTA_AUTHOR = 0x40
RTA_BRD = 0x80

#: The bits above, in the order their sockaddrs appear on the wire.
RTA_ORDER = (RTA_DST, RTA_GATEWAY, RTA_NETMASK, RTA_GENMASK, RTA_IFP, RTA_IFA, RTA_AUTHOR, RTA_BRD)

#: RTF_GATEWAY: reached through a next hop rather than on-link. RTF_LLINFO
#: marks the entries that make up the neighbour cache.
RTF_UP = 0x0001
RTF_GATEWAY = 0x0002
RTF_LLINFO = 0x0400

#: struct rt_msghdr, up to and including rtm_inits, then rt_metrics as opaque
#: bytes. The two pad bytes after rtm_index are the alignment the C compiler
#: inserts before the first int; naming them keeps the offsets honest.
RT_MSGHDR = struct.Struct("=HBBH2xiiiiiiI56s")

#: A BSD sockaddr leads with its own length, which is what makes walking a
#: list of them possible without knowing each type.
SOCKADDR_HEADER = struct.Struct("=BB")

#: Offset of the address bytes inside sockaddr_in and sockaddr_in6.
SIN_ADDR_OFFSET = 4
SIN6_ADDR_OFFSET = 8

#: AF_LINK, and the fixed part of sockaddr_dl before its variable data.
AF_LINK = 18
SOCKADDR_DL = struct.Struct("=BBHBBBB")

#: An Ethernet hardware address is six bytes.
MAC_LENGTH = 6


def roundup(length: int) -> int:
    """Return a sockaddr length rounded up the way the routing socket aligns it.

    A zero length still consumes one slot, which is why this cannot simply be
    an alignment mask: a route with an unspecified address carries a
    zero-length sockaddr, and treating it as zero bytes would slide every
    later address out of position.

    Examples:
        >>> [roundup(n) for n in (0, 1, 16, 17)]
        [4, 4, 16, 20]

    """

    if length <= 0:
        return 4
    return 1 + ((length - 1) | 3)


def address_of(chunk: bytes) -> str | None:
    """Return the IP address in one sockaddr, or None if it holds none.

    Examples:
        >>> address_of(b"") is None
        True

    """

    if len(chunk) < SOCKADDR_HEADER.size:
        return None
    _length, family = SOCKADDR_HEADER.unpack(chunk[: SOCKADDR_HEADER.size])

    if family == socket.AF_INET:
        offset, size, af = SIN_ADDR_OFFSET, 4, socket.AF_INET
    elif family == socket.AF_INET6:
        offset, size, af = SIN6_ADDR_OFFSET, 16, socket.AF_INET6
    else:
        # AF_LINK and friends carry no IP address.
        return None

    if len(chunk) < offset + size:
        return None
    try:
        return socket.inet_ntop(af, chunk[offset : offset + size])
    except (OSError, ValueError):  # pragma: no cover - malformed kernel data
        return None


def link_address_of(chunk: bytes) -> str | None:
    """Return the hardware address in a ``sockaddr_dl``, or None if absent.

    A ``sockaddr_dl`` stores the interface name and the hardware address back
    to back in one variable-length buffer, so both lengths must be read before
    either can be located. Reading the address at a fixed offset works only
    while the interface name happens to be the expected length.

    Examples:
        >>> link_address_of(b"") is None
        True

    """

    if len(chunk) < SOCKADDR_DL.size:
        return None
    _length, family, _index, _kind, name_length, address_length, _selector = SOCKADDR_DL.unpack(chunk[: SOCKADDR_DL.size])
    if family != AF_LINK or address_length != MAC_LENGTH:
        return None

    start = SOCKADDR_DL.size + name_length
    end = start + address_length
    if end > len(chunk):
        return None
    raw = chunk[start:end]
    if not any(raw):
        return None
    return ":".join(f"{octet:02x}" for octet in raw)


class SockaddrSet(BaseModel):
    """The addresses trailing one routing message, named rather than indexed.

    A record instead of a bitmask-keyed mapping: the caller wants "the
    gateway", and ``sockaddrs.gateway`` says that where ``sockaddrs[0x02]``
    needs the reader to know the bit. Absent means the message did not carry
    that address, which is different from carrying an empty one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    destination: bytes | None = None
    gateway: bytes | None = None
    netmask: bytes | None = None
    interface: bytes | None = None
    interface_address: bytes | None = None
    broadcast: bytes | None = None


#: Which field each RTA bit fills, in the order the sockaddrs appear.
_FIELD_FOR_BIT = (
    (RTA_DST, "destination"),
    (RTA_GATEWAY, "gateway"),
    (RTA_NETMASK, "netmask"),
    (RTA_GENMASK, None),
    (RTA_IFP, "interface"),
    (RTA_IFA, "interface_address"),
    (RTA_AUTHOR, None),
    (RTA_BRD, "broadcast"),
)


def split_sockaddrs(payload: bytes, addrs: int) -> SockaddrSet:
    """Split the sockaddrs trailing a routing message into a named record.

    The kernel says which addresses are present as a bitmask and then
    concatenates them in a fixed order, each self-describing its own length.
    Every slot in that order must be stepped over even when its field is not
    read, or every later address is taken from the wrong offset.

    Examples:
        >>> split_sockaddrs(b"", RTA_DST).gateway is None
        True

    """

    found: dict[str, bytes] = {}
    position = 0
    for bit, field in _FIELD_FOR_BIT:
        if not addrs & bit:
            continue
        if position + SOCKADDR_HEADER.size > len(payload):
            break
        length = payload[position]
        if length and position + length <= len(payload) and field is not None:
            found[field] = payload[position : position + length]
        position += roundup(length)
    return SockaddrSet(**found)


def sysctl(mib: list[int]) -> bytes | None:  # pragma: no cover - macOS only
    """Read a kernel MIB into bytes.

    Args:
        mib: The MIB selector, as the ``sysctl`` C call takes it.

    Returns:
        The value, or ``None`` when the call failed or this platform has no
        usable ``sysctl``.

    Note:
        Called twice, as the C interface requires: once with a null buffer to
        learn the size, then again to read it. The table can grow between the
        two calls, so the second failure is reported rather than retried
        forever.

    """

    libc_name = ctypes.util.find_library("c")
    if libc_name is None:
        return None
    libc = ctypes.CDLL(libc_name, use_errno=True)

    selector = (ctypes.c_int * len(mib))(*mib)
    size = ctypes.c_size_t(0)
    if libc.sysctl(selector, len(mib), None, ctypes.byref(size), None, 0) != 0 or size.value == 0:
        return None

    buffer = ctypes.create_string_buffer(size.value)
    if libc.sysctl(selector, len(mib), buffer, ctypes.byref(size), None, 0) != 0:
        return None
    return buffer.raw[: size.value]
