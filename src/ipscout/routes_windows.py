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
from typing import Any

from .errors import IPScoutUnsupportedError
from .models import RouteInfo
from .winapi import (
    MIB_IPFORWARD_ROW2,
    SOCKADDR_INET,
    WIN_AF_INET,
    WIN_AF_INET6,
    iphlpapi,
    sockaddr_inet_to_string,
)

__all__ = ["default_gateway", "query_route"]

#: NO_ERROR, the only success value GetBestRoute2 returns.
_NO_ERROR = 0


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
        library: Any = iphlpapi()
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

    # An on-link destination comes back with the next hop left unspecified,
    # which reads as family zero and therefore as no gateway.
    return RouteInfo(
        gateway=sockaddr_inet_to_string(row.NextHop),
        interface=interface,
        source=sockaddr_inet_to_string(best_source),
    )


def default_gateway(family: int = socket.AF_INET) -> RouteInfo | None:  # pragma: no cover - Windows only
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
