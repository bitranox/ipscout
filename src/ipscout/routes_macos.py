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

from .bsdroute import (
    NO_METRICS,
    RT_MSGHDR,
    RTA_DST,
    RTF_GATEWAY,
    RTF_UP,
    RTM_GET,
    RTM_VERSION,
    address_of,
    open_route_socket,
    pack_sockaddr_in,
    pack_sockaddr_in6,
    split_sockaddrs,
)
from .models import DEFAULT_TIMEOUT, AddressFamily, RouteInfo

__all__ = ["default_gateway", "parse_route_reply", "query_route"]

#: Bytes asked for per read. A reply is one rt_msghdr plus at most eight
#: sockaddrs, none larger than a 128-byte sockaddr_storage, so it fits with
#: room to spare; a longer message on this shared socket is another process's
#: and is discarded whatever part of it is read.
_RECEIVE_SIZE = 4096

#: Messages read while waiting for ours. Every route socket sees every routing
#: message on the host, so the first one read need not be the reply; the bound
#: stops a busy table from keeping the query waiting forever.
_MAX_REPLY_READS = 8


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

    if len(data) < RT_MSGHDR.size:
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
    ) = RT_MSGHDR.unpack(data[: RT_MSGHDR.size])

    if message_type != RTM_GET or errno != 0:
        return None
    if pid is not None and message_pid != pid:
        return None
    if seq is not None and message_seq != seq:
        return None
    if not flags & RTF_UP:
        return None

    end = min(message_length, len(data)) if message_length else len(data)
    sockaddrs = split_sockaddrs(data[RT_MSGHDR.size : end], addrs)

    # A gateway sockaddr is present on on-link routes too, where it holds the
    # link address rather than a router, so the flag decides whether there is
    # a next hop to report.
    gateway = address_of(sockaddrs.gateway) if flags & RTF_GATEWAY and sockaddrs.gateway else None
    source = address_of(sockaddrs.interface_address) if sockaddrs.interface_address else None

    interface: str | None = None
    if index:
        with contextlib.suppress(OSError, ValueError):
            interface = socket.if_indextoname(index)

    return RouteInfo(gateway=gateway, interface=interface, source=source)


def _build_request(packed_destination: bytes, family: AddressFamily, seq: int) -> bytes:
    """Build the RTM_GET message asking about one destination."""

    sockaddr = pack_sockaddr_in6(packed_destination) if family is AddressFamily.IPV6 else pack_sockaddr_in(packed_destination)
    header = RT_MSGHDR.pack(
        RT_MSGHDR.size + len(sockaddr),
        RTM_VERSION,
        RTM_GET,
        0,
        0,
        RTA_DST,
        os.getpid(),
        seq,
        0,
        0,
        0,
        NO_METRICS,
    )
    return header + sockaddr


def query_route(destination: str, family: AddressFamily = AddressFamily.IPV4) -> RouteInfo | None:  # pragma: no cover - macOS only
    """Ask the kernel which route reaches ``destination``.

    Args:
        destination: The address to look up.
        family: Which address family ``destination`` belongs to.

    Returns:
        The route, or ``None`` if the kernel reported no usable route or the
        query could not be made at all.

    """

    try:
        packed = socket.inet_pton(family.socket_family, destination)
    except OSError:
        return None

    try:
        sock = open_route_socket()
    except OSError:
        return None

    pid = os.getpid()
    seq = 1
    try:
        sock.settimeout(DEFAULT_TIMEOUT)
        sock.send(_build_request(packed, family, seq))
        # Other processes share this socket, so read until our own reply
        # arrives rather than trusting the first message to be ours.
        for _ in range(_MAX_REPLY_READS):
            route = parse_route_reply(sock.recv(_RECEIVE_SIZE), pid=pid, seq=seq)
            if route is not None:
                return route
    except OSError:
        return None
    finally:
        with contextlib.suppress(OSError):
            sock.close()
    return None


def default_gateway(family: AddressFamily = AddressFamily.IPV4) -> RouteInfo | None:  # pragma: no cover - macOS only
    """Return the route used for traffic with no more specific destination.

    Args:
        family: Which address family to ask about.

    Returns:
        The default route, or ``None`` when this host has none.

    """

    # The unspecified address is the lookup key the default route matches on;
    # it is never bound to.
    return query_route(family.unspecified_address, family)
