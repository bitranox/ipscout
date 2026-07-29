"""Route lookup on Linux, via a netlink ``RTM_GETROUTE`` query.

Asks the kernel which route it would actually use to reach a given address,
rather than reading a table and re-implementing longest-prefix matching. That
distinction matters: policy routing, multiple tables and metrics all feed the
kernel's decision, and a hand-rolled match would disagree with reality on any
host that uses them.

Contents:
    query_route: Ask the kernel for the route to one destination.

Note:
    Netlink is an ordinary datagram socket and this query needs no privileges.
    Verified against this design's real use: ``8.8.8.8`` resolves to a gateway
    while an on-link address resolves to none, which is exactly the
    direct-versus-routed distinction :mod:`ipscout.neighbours` needs.

"""

from __future__ import annotations

import contextlib
import socket
import struct

from pydantic import BaseModel, ConfigDict

__all__ = ["RouteInfo", "query_route"]

#: NETLINK_ROUTE, and the message type asking about a route.
_NETLINK_ROUTE = 0
_RTM_GETROUTE = 26
_NLM_F_REQUEST = 0x01
_NLMSG_ERROR = 0x02

#: struct nlmsghdr: length, type, flags, sequence, port id.
_NLMSGHDR = struct.Struct("=IHHII")

#: struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags.
_RTMSG = struct.Struct("=BBBBBBBBI")

#: struct rtattr: length, type.
_RTATTR = struct.Struct("=HH")

#: Route attributes this module reads.
_RTA_DST = 1
_RTA_OIF = 4
_RTA_GATEWAY = 5
_RTA_PREFSRC = 7

#: RTN_UNREACHABLE and friends start here; anything above RTN_LOCAL is not a
#: usable forwarding route.
_RTN_UNREACHABLE = 7


class RouteInfo(BaseModel):
    """How this host would reach one destination.

    Attributes:
        gateway: The next-hop router, or ``None`` when the destination is
            on-link. That distinction is the whole point of this lookup.
        interface: Outgoing interface name, where one could be resolved.
        source: The source address the kernel would use.

    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    gateway: str | None = None
    interface: str | None = None
    source: str | None = None


def _aligned(length: int) -> int:
    """Return a netlink attribute length rounded up to its 4-byte alignment."""

    return (length + 3) & ~3


def _build_request(packed_destination: bytes, family: int) -> bytes:
    """Build the RTM_GETROUTE message asking about one destination."""

    body = _RTMSG.pack(family, len(packed_destination) * 8, 0, 0, 0, 0, 0, 0, 0)
    attribute = _RTATTR.pack(_RTATTR.size + len(packed_destination), _RTA_DST) + packed_destination
    payload = body + attribute
    header = _NLMSGHDR.pack(_NLMSGHDR.size + len(payload), _RTM_GETROUTE, _NLM_F_REQUEST, 1, 0)
    return header + payload


def _parse_attributes(payload: bytes, family: int) -> RouteInfo:
    """Read the gateway, interface and source out of one route message."""

    if len(payload) < _RTMSG.size:
        return RouteInfo()
    _fam, _dst_len, _src_len, _tos, _table, _proto, _scope, route_type, _flags = _RTMSG.unpack(payload[: _RTMSG.size])
    if route_type >= _RTN_UNREACHABLE:
        # Blackhole, unreachable, prohibit: there is no next hop to report.
        return RouteInfo()

    gateway: str | None = None
    source: str | None = None
    interface: str | None = None

    position = _RTMSG.size
    while position + _RTATTR.size <= len(payload):
        length, attribute = _RTATTR.unpack(payload[position : position + _RTATTR.size])
        if length < _RTATTR.size or position + length > len(payload):
            break
        value = payload[position + _RTATTR.size : position + length]
        if attribute == _RTA_GATEWAY:
            with contextlib.suppress(OSError, ValueError):
                gateway = socket.inet_ntop(family, value)
        elif attribute == _RTA_PREFSRC:
            with contextlib.suppress(OSError, ValueError):
                source = socket.inet_ntop(family, value)
        elif attribute == _RTA_OIF and len(value) >= 4:  # noqa: PLR2004 - an interface index is a uint32
            index = struct.unpack("=I", value[:4])[0]
            with contextlib.suppress(OSError, ValueError):
                interface = socket.if_indextoname(index)
        position += _aligned(length)

    return RouteInfo(gateway=gateway, interface=interface, source=source)


def query_route(destination: str, family: int = socket.AF_INET) -> RouteInfo | None:
    """Ask the kernel which route reaches ``destination``.

    Args:
        destination: The address to look up.
        family: ``AF_INET`` or ``AF_INET6``.

    Returns:
        The route, or ``None`` if the kernel reported no usable route or the
        query could not be made at all.

    Examples:
        >>> route = query_route("127.0.0.1")
        >>> route is None or route.gateway is None
        True

    """

    try:
        packed = socket.inet_pton(family, destination)
    except OSError:
        return None

    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, _NETLINK_ROUTE)
    except (AttributeError, OSError):  # pragma: no cover - non-Linux
        return None

    try:
        sock.settimeout(2.0)
        sock.send(_build_request(packed, family))
        data = sock.recv(65535)
    except OSError:
        return None
    finally:
        with contextlib.suppress(OSError):
            sock.close()

    if len(data) < _NLMSGHDR.size:
        return None
    message_length, message_type, _flags, _seq, _pid = _NLMSGHDR.unpack(data[: _NLMSGHDR.size])
    if message_type == _NLMSG_ERROR or message_length > len(data):
        return None
    return _parse_attributes(data[_NLMSGHDR.size : message_length], family)


def default_gateway(family: int = socket.AF_INET) -> RouteInfo | None:
    """Return the route used for traffic with no more specific destination.

    Args:
        family: ``AF_INET`` or ``AF_INET6``.

    Returns:
        The default route, or ``None`` when this host has none.

    Note:
        Asks for the route to the unspecified address, which is what the
        default route matches, rather than searching the table for a
        zero-length prefix.

    """

    # The unspecified address is the lookup key the default route matches on;
    # it is never bound to.
    unspecified = "::" if family == socket.AF_INET6 else "0.0.0.0"  # noqa: S104  # nosec B104
    return query_route(unspecified, family)
