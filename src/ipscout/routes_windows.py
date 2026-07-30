"""Route lookup on Windows, via ``GetBestRoute2`` in ``iphlpapi.dll``.

Asks the stack which route it would actually use, the same question the
netlink and route-socket backends ask on Linux and macOS, so all three agree
about what "the next hop" means without any of them re-implementing route
selection.

Contents:
    query_route: Ask the stack for the route to one destination.
    default_gateway: The route used when nothing more specific matches.

Note:
    ``GetBestRoute2`` needs no elevation. It reports an on-link destination by
    leaving the next hop unspecified rather than by omitting it, so a family
    of zero is the answer "no router involved" rather than a failure.

"""

from __future__ import annotations

import contextlib
import ctypes
import socket

from .errors import IPScoutUnsupportedError
from .models import RouteInfo
from .winapi import (
    MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2,
    SOCKADDR_INET,
    WIN_AF_INET,
    WIN_AF_INET6,
    iphlpapi,
    sockaddr_inet_to_string,
)

__all__ = ["default_gateway", "query_route"]

#: NO_ERROR, the only success value GetBestRoute2 returns.
_NO_ERROR = 0

#: An all-zero next hop means the destination is on-link, not that a router
#: lives at address zero.
_UNSPECIFIED = frozenset({"0.0.0.0", "::"})  # noqa: S104  # nosec B104


def _destination(address: str, family: int) -> SOCKADDR_INET | None:
    """Pack an address into the union ``GetBestRoute2`` takes."""

    sockaddr = SOCKADDR_INET()
    try:
        if family == socket.AF_INET6:
            sockaddr.si_family = WIN_AF_INET6
            sockaddr.Ipv6.sin6_addr[:] = socket.inet_pton(socket.AF_INET6, address)
        else:
            sockaddr.si_family = WIN_AF_INET
            sockaddr.Ipv4.sin_addr[:] = socket.inet_pton(socket.AF_INET, address)
    except OSError:
        return None
    return sockaddr


def _next_hop(sockaddr: SOCKADDR_INET) -> str | None:
    """Return the router in a next-hop field, or None when there is none.

    An on-link destination does not come back with an empty next hop. Windows
    fills the field in with the *unspecified* address of the right family, so
    it decodes as a perfectly valid "0.0.0.0" that would read as a router at
    address zero. Measured on a Windows runner, where the loopback route
    reported exactly that.
    """

    address = sockaddr_inet_to_string(sockaddr)
    if address is None:
        return None
    return None if address in _UNSPECIFIED else address


def query_route(destination: str, family: int = socket.AF_INET) -> RouteInfo | None:  # pragma: no cover - Windows only
    """Ask the stack which route reaches ``destination``.

    Args:
        destination: The address to look up.
        family: ``AF_INET`` or ``AF_INET6``.

    Returns:
        The route, or ``None`` if the stack reported no usable route or the
        address could not be parsed.

    """

    target = _destination(destination, family)
    if target is None:
        return None

    try:
        library = iphlpapi()
    except IPScoutUnsupportedError:
        return None

    row = MIB_IPFORWARD_ROW2()
    best_source = SOCKADDR_INET()
    status = library.GetBestRoute2(None, 0, None, ctypes.byref(target), 0, ctypes.byref(row), ctypes.byref(best_source))
    if status != _NO_ERROR:
        return None

    interface: str | None = None
    if row.InterfaceIndex:
        with contextlib.suppress(OSError, ValueError):
            interface = socket.if_indextoname(row.InterfaceIndex)

    return RouteInfo(
        gateway=_next_hop(row.NextHop),
        interface=interface,
        source=sockaddr_inet_to_string(best_source),
    )


def default_gateway(family: int = socket.AF_INET) -> RouteInfo | None:  # pragma: no cover - Windows only
    """Return the route used for traffic with no more specific destination.

    Args:
        family: ``AF_INET`` or ``AF_INET6``.

    Returns:
        The default route, or ``None`` when this host has none.

    Note:
        Reads the forwarding table and selects the zero-length destination
        prefix, rather than asking for the best route to the unspecified
        address. The latter is the obvious implementation and it is a guess
        about how the stack resolves ``0.0.0.0``; on Linux the equivalent guess
        was measurably wrong, answering with loopback. Selecting the prefix
        that *defines* the default route needs no such assumption.

    """

    try:
        library = iphlpapi()
    except IPScoutUnsupportedError:
        return None

    win_family = WIN_AF_INET6 if family == socket.AF_INET6 else WIN_AF_INET
    table = ctypes.POINTER(MIB_IPFORWARD_TABLE2)()
    if library.GetIpForwardTable2(win_family, ctypes.byref(table)) != _NO_ERROR:
        return None

    try:
        count = int(table.contents.NumEntries)
        # The declared array holds one row; the real table is however many the
        # call reported. Walking a pointer of known element type keeps every
        # field typed, which casting to a runtime-sized array does not.
        rows = ctypes.cast(table.contents.Table, ctypes.POINTER(MIB_IPFORWARD_ROW2))
        best: RouteInfo | None = None
        best_metric: int | None = None
        for index in range(count):
            row: MIB_IPFORWARD_ROW2 = rows[index]
            if int(row.DestinationPrefix.PrefixLength) != 0:
                continue
            gateway = _next_hop(row.NextHop)
            if gateway is None:
                continue
            # Several default routes can coexist, one per interface; the stack
            # prefers the lowest metric, so reporting anything else would name
            # a router this host does not actually use.
            if best_metric is None or int(row.Metric) < best_metric:
                interface: str | None = None
                if int(row.InterfaceIndex):
                    with contextlib.suppress(OSError, ValueError):
                        interface = socket.if_indextoname(int(row.InterfaceIndex))
                best, best_metric = RouteInfo(gateway=gateway, interface=interface), int(row.Metric)
        return best
    finally:
        library.FreeMibTable(table)
