"""Route lookup on Linux, via netlink ``RTM_GETROUTE``.

Asks the kernel which route it would actually use to reach a given address,
rather than reading a table and re-implementing longest-prefix matching. That
distinction matters: policy routing, multiple tables and metrics all feed the
kernel's decision, and a hand-rolled match would disagree with reality on any
host that uses them.

Contents:
    query_route: Ask the kernel for the route to one destination.
    default_gateway: The route used when nothing more specific matches.

Note:
    Netlink is an ordinary datagram socket and these queries need no
    privileges. Verified against this design's real use: ``8.8.8.8`` resolves
    to a gateway while an on-link address resolves to none, which is exactly
    the direct-versus-routed distinction :mod:`ipscout.neighbours` needs.

"""

from __future__ import annotations

import contextlib
import socket
import struct

from .models import RouteInfo
from .netlink import (
    NLM_F_DUMP,
    NLM_F_REQUEST,
    NLMSG_DONE,
    NLMSG_ERROR,
    build_message,
    iter_attributes,
    iter_messages,
    open_socket,
)

__all__ = ["default_gateway", "query_route"]

_RTM_NEWROUTE = 24
_RTM_GETROUTE = 26

#: struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags.
_RTMSG = struct.Struct("=BBBBBBBBI")

#: Route attributes this module reads.
_RTA_DST = 1
_RTA_OIF = 4
_RTA_GATEWAY = 5
_RTA_PREFSRC = 7

#: RTN_UNREACHABLE and friends start here; anything from it up is not a usable
#: forwarding route.
_RTN_UNREACHABLE = 7

#: RT_TABLE_MAIN: the ordinary routing table, as opposed to a policy table.
_RT_TABLE_MAIN = 254

#: A dump longer than this would be a pathological routing table; the bound
#: stops a truncated or hostile stream from looping forever.
_MAX_DUMP_CHUNKS = 64

#: An interface index is a uint32.
_IFINDEX_SIZE = 4


def _build_query(packed_destination: bytes, family: int) -> bytes:
    """Build the RTM_GETROUTE message asking about one destination."""

    body = _RTMSG.pack(family, len(packed_destination) * 8, 0, 0, 0, 0, 0, 0, 0)
    attribute = struct.pack("=HH", 4 + len(packed_destination), _RTA_DST) + packed_destination
    return build_message(_RTM_GETROUTE, NLM_F_REQUEST, body + attribute)


def _build_dump(family: int) -> bytes:
    """Build the RTM_GETROUTE message asking for the whole table."""

    return build_message(_RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, _RTMSG.pack(family, 0, 0, 0, 0, 0, 0, 0, 0))


def _parse_route(payload: bytes, family: int) -> RouteInfo:
    """Read the gateway, interface and source out of one route message."""

    gateway: str | None = None
    source: str | None = None
    interface: str | None = None

    for attribute, value in iter_attributes(payload, _RTMSG.size):
        if attribute == _RTA_GATEWAY:
            with contextlib.suppress(OSError, ValueError):
                gateway = socket.inet_ntop(family, value)
        elif attribute == _RTA_PREFSRC:
            with contextlib.suppress(OSError, ValueError):
                source = socket.inet_ntop(family, value)
        elif attribute == _RTA_OIF and len(value) >= _IFINDEX_SIZE:
            index = struct.unpack("=I", value[:_IFINDEX_SIZE])[0]
            with contextlib.suppress(OSError, ValueError):
                interface = socket.if_indextoname(index)

    return RouteInfo(gateway=gateway, interface=interface, source=source)


def _route_in(data: bytes, family: int) -> RouteInfo | None:
    """Return the route in a single-message netlink reply."""

    for message_type, payload in iter_messages(data):
        if message_type == NLMSG_ERROR or len(payload) < _RTMSG.size:
            return None
        route_type = _RTMSG.unpack(payload[: _RTMSG.size])[7]
        if route_type >= _RTN_UNREACHABLE:
            # Blackhole, unreachable, prohibit: there is no next hop to report.
            return None
        return _parse_route(payload, family)
    return None


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

    sock = open_socket()
    if sock is None:  # pragma: no cover - non-Linux, or netlink unavailable
        return None

    try:
        sock.settimeout(2.0)
        sock.send(_build_query(packed, family))
        data = sock.recv(65535)
    except OSError:
        return None
    finally:
        with contextlib.suppress(OSError):
            sock.close()

    return _route_in(data, family)


def _default_route_in(data: bytes, family: int) -> RouteInfo | None:
    """Return the zero-length-prefix route in one netlink dump chunk."""

    for message_type, payload in iter_messages(data):
        if message_type in (NLMSG_DONE, NLMSG_ERROR):
            return None
        if message_type != _RTM_NEWROUTE or len(payload) < _RTMSG.size:
            continue
        _fam, dst_len, _src, _tos, table, _proto, _scope, route_type, _flags = _RTMSG.unpack(payload[: _RTMSG.size])
        # A zero-length destination prefix IS the default route. Restricted to
        # the main table so a policy-routing rule in another table cannot
        # masquerade as the host's default.
        if dst_len == 0 and table == _RT_TABLE_MAIN and route_type < _RTN_UNREACHABLE:
            route = _parse_route(payload, family)
            if route.gateway is not None:
                return route
    return None


def default_gateway(family: int = socket.AF_INET) -> RouteInfo | None:
    """Return the route used for traffic with no more specific destination.

    Args:
        family: ``AF_INET`` or ``AF_INET6``.

    Returns:
        The default route, or ``None`` when this host has none.

    Note:
        Dumps the table and selects the zero-length prefix, rather than asking
        for a route to the unspecified address. Those are not the same question
        on Linux: ``0.0.0.0`` matches the *local* table first, so that lookup
        answers with loopback and never reaches the default route.

    Examples:
        >>> route = default_gateway()
        >>> route is None or route.gateway is not None
        True

    """

    sock = open_socket()
    if sock is None:  # pragma: no cover - non-Linux, or netlink unavailable
        return None

    try:
        sock.settimeout(2.0)
        sock.send(_build_dump(family))
        # A dump arrives as several multipart messages; read until the default
        # route turns up or the kernel says it is done.
        for _ in range(_MAX_DUMP_CHUNKS):
            route = _default_route_in(sock.recv(65535), family)
            if route is not None:
                return route
    except OSError:
        return None
    finally:
        with contextlib.suppress(OSError):
            sock.close()
    return None
