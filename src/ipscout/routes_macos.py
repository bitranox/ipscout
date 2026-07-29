"""Route lookup on macOS and the BSDs, via an ``RTM_GET`` on a route socket.

Asks the kernel which route it would actually use, exactly as the netlink
backend does on Linux, rather than dumping the table and re-implementing
longest-prefix matching. Policy routes, multiple tables and metrics all feed
the kernel's decision, so a hand-rolled match disagrees with reality on any
host that uses them.

Contents:
    query_route: Ask the kernel for the route to one destination.
    default_gateway: The route used when nothing more specific matches.
    parse_route_reply: Pure decoder for one routing message.

Note:
    A route socket is an ordinary socket and this query needs no privileges.
    The decoder is separated from the socket work so the wire format can be
    tested on any platform, which matters here: this parsing cannot be
    exercised on the Linux development host at all.

"""

from __future__ import annotations

import contextlib
import os
import socket
import struct

from .models import RouteInfo

__all__ = ["default_gateway", "parse_route_reply", "query_route"]

#: PF_ROUTE, and the message asking about a single route.
_PF_ROUTE = 17
_RTM_GET = 0x04
_RTM_VERSION = 5

#: Bits in rtm_addrs saying which sockaddrs follow the header, in this order.
_RTA_DST = 0x01
_RTA_GATEWAY = 0x02
_RTA_NETMASK = 0x04
_RTA_GENMASK = 0x08
_RTA_IFP = 0x10
_RTA_IFA = 0x20
_RTA_AUTHOR = 0x40
_RTA_BRD = 0x80

#: The bits above, in the order their sockaddrs appear on the wire.
_RTA_ORDER = (_RTA_DST, _RTA_GATEWAY, _RTA_NETMASK, _RTA_GENMASK, _RTA_IFP, _RTA_IFA, _RTA_AUTHOR, _RTA_BRD)

#: RTF_GATEWAY: the destination is reached through a next hop rather than
#: on-link. Without it a gateway sockaddr may still be present but describes
#: the link, not a router.
_RTF_UP = 0x0001
_RTF_GATEWAY = 0x0002

#: struct rt_msghdr, up to and including rtm_inits, then rt_metrics as opaque
#: bytes. The two pad bytes after rtm_index are the alignment the C compiler
#: inserts before the first int; naming them keeps the offsets honest.
_RT_MSGHDR = struct.Struct("=HBBH2xiiiiiiI56s")

#: A BSD sockaddr leads with its own length, which is what makes the walk
#: below possible without knowing each address type.
_SOCKADDR_HEADER = struct.Struct("=BB")

#: Offset of the address bytes inside sockaddr_in and sockaddr_in6.
_SIN_ADDR_OFFSET = 4
_SIN6_ADDR_OFFSET = 8


def _roundup(length: int) -> int:
    """Return a sockaddr length rounded up the way the route socket aligns it.

    A zero length still consumes one slot, which is why this cannot simply be
    an alignment mask: a route with an unspecified address (the default route)
    carries a zero-length sockaddr, and treating it as zero bytes would slide
    every later address out of position.
    """

    if length <= 0:
        return 4
    return 1 + ((length - 1) | 3)


def _address_of(chunk: bytes) -> str | None:
    """Return the printable address in one sockaddr, or None if it holds none."""

    if len(chunk) < _SOCKADDR_HEADER.size:
        return None
    _length, family = _SOCKADDR_HEADER.unpack(chunk[: _SOCKADDR_HEADER.size])

    if family == socket.AF_INET:
        offset, size, af = _SIN_ADDR_OFFSET, 4, socket.AF_INET
    elif family == socket.AF_INET6:
        offset, size, af = _SIN6_ADDR_OFFSET, 16, socket.AF_INET6
    else:
        # AF_LINK and friends carry no IP address; the interface is read from
        # rtm_index instead, which is always present and unambiguous.
        return None

    if len(chunk) < offset + size:
        return None
    try:
        return socket.inet_ntop(af, chunk[offset : offset + size])
    except (OSError, ValueError):  # pragma: no cover - malformed kernel data
        return None


def _split_sockaddrs(payload: bytes, addrs: int) -> dict[int, bytes]:
    """Split the sockaddrs trailing a routing message, keyed by their RTA bit.

    The kernel says which addresses are present as a bitmask and then
    concatenates them in a fixed order, each self-describing its own length.
    """

    found: dict[int, bytes] = {}
    position = 0
    for bit in _RTA_ORDER:
        if not addrs & bit:
            continue
        if position + _SOCKADDR_HEADER.size > len(payload):
            break
        length = payload[position]
        step = _roundup(length)
        if length and position + length <= len(payload):
            found[bit] = payload[position : position + length]
        position += step
    return found


def parse_route_reply(data: bytes, *, pid: int | None = None, seq: int | None = None) -> RouteInfo | None:
    """Decode one routing message into a route.

    Args:
        data: The bytes read from the route socket.
        pid: Only accept a reply carrying this process id, when given.
        seq: Only accept a reply carrying this sequence number, when given.

    Returns:
        The route, or ``None`` when the message is malformed, is somebody
        else's, or describes no usable route.

    Note:
        A route socket is shared, so every listener sees every message. The
        pid and sequence check is what keeps another process's route out of
        this answer.

    Examples:
        >>> parse_route_reply(b"") is None
        True

    """

    if len(data) < _RT_MSGHDR.size:
        return None
    (
        message_length,
        _version,
        message_type,
        index,
        flags,
        addrs,
        message_pid,
        message_seq,
        errno,
        _use,
        _inits,
        _metrics,
    ) = _RT_MSGHDR.unpack(data[: _RT_MSGHDR.size])

    if message_type != _RTM_GET or errno != 0:
        return None
    if pid is not None and message_pid != pid:
        return None
    if seq is not None and message_seq != seq:
        return None
    if not flags & _RTF_UP:
        return None

    end = min(message_length, len(data)) if message_length else len(data)
    sockaddrs = _split_sockaddrs(data[_RT_MSGHDR.size : end], addrs)

    # A gateway sockaddr is present on on-link routes too, where it holds the
    # link address rather than a router, so the flag decides whether there is
    # a next hop to report.
    gateway = _address_of(sockaddrs[_RTA_GATEWAY]) if flags & _RTF_GATEWAY and _RTA_GATEWAY in sockaddrs else None
    source = _address_of(sockaddrs[_RTA_IFA]) if _RTA_IFA in sockaddrs else None

    interface: str | None = None
    if index:
        with contextlib.suppress(OSError, ValueError):
            interface = socket.if_indextoname(index)

    return RouteInfo(gateway=gateway, interface=interface, source=source)


def _build_request(packed_destination: bytes, family: int, seq: int) -> bytes:
    """Build the RTM_GET message asking about one destination."""

    if family == socket.AF_INET6:
        # sockaddr_in6: len, family, port, flowinfo, addr, scope_id.
        sockaddr = struct.pack("=BBHI16sI", 28, family, 0, 0, packed_destination, 0)
    else:
        # sockaddr_in: len, family, port, addr, then 8 bytes of zero padding.
        sockaddr = struct.pack("=BBH4s8s", 16, family, 0, packed_destination, b"\x00" * 8)

    header = _RT_MSGHDR.pack(
        _RT_MSGHDR.size + len(sockaddr),
        _RTM_VERSION,
        _RTM_GET,
        0,
        0,
        _RTA_DST,
        os.getpid(),
        seq,
        0,
        0,
        0,
        b"\x00" * 56,
    )
    return header + sockaddr


def _open_route_socket() -> socket.socket | None:
    """Return a route socket, or None where the platform has none."""

    af_route = getattr(socket, "AF_ROUTE", _PF_ROUTE)
    try:
        return socket.socket(af_route, socket.SOCK_RAW, 0)
    except OSError:  # pragma: no cover - platform without PF_ROUTE
        return None


def query_route(destination: str, family: int = socket.AF_INET) -> RouteInfo | None:  # pragma: no cover - macOS only
    """Ask the kernel which route reaches ``destination``.

    Args:
        destination: The address to look up.
        family: ``AF_INET`` or ``AF_INET6``.

    Returns:
        The route, or ``None`` if the kernel reported no usable route or the
        query could not be made at all.

    """

    try:
        packed = socket.inet_pton(family, destination)
    except OSError:
        return None

    sock = _open_route_socket()
    if sock is None:
        return None

    pid = os.getpid()
    seq = 1
    try:
        sock.settimeout(2.0)
        sock.send(_build_request(packed, family, seq))
        # Other processes share this socket, so read until our own reply
        # arrives rather than trusting the first message to be ours.
        deadline_reads = 8
        for _ in range(deadline_reads):
            route = parse_route_reply(sock.recv(4096), pid=pid, seq=seq)
            if route is not None:
                return route
    except OSError:
        return None
    finally:
        with contextlib.suppress(OSError):
            sock.close()
    return None


def default_gateway(family: int = socket.AF_INET) -> RouteInfo | None:  # pragma: no cover - macOS only
    """Return the route used for traffic with no more specific destination.

    Args:
        family: ``AF_INET`` or ``AF_INET6``.

    Returns:
        The default route, or ``None`` when this host has none.

    """

    # The unspecified address is the lookup key the default route matches on;
    # it is never bound to.
    unspecified = "::" if family == socket.AF_INET6 else "0.0.0.0"  # noqa: S104  # nosec B104
    return query_route(unspecified, family)
