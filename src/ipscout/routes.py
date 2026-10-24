"""Chooses the route-lookup backend for this platform.

Contents:
    query_route: How this host would reach one destination.
    default_gateway: The route used when nothing more specific matches.

Note:
    All three backends ask the kernel the same question - netlink
    ``RTM_GETROUTE`` on Linux, an ``RTM_GET`` on a route socket on macOS,
    ``GetBestRoute2`` on Windows - rather than reading a table and
    re-implementing longest-prefix matching, so all three agree with the
    routing the host will actually perform. Every one of them needs no
    elevation, and every one returns the same frozen
    :class:`~ipscout.models.RouteInfo`.

"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Protocol

from .models import AddressFamily
from .resolve import split_zone

if TYPE_CHECKING:
    from .models import RouteInfo

__all__ = ["default_gateway", "query_route"]

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"


class _RouteBackend(Protocol):
    """The two lookups every per-platform route module provides."""

    def query_route(self, destination: str, family: AddressFamily) -> RouteInfo | None:
        """Return how this host would reach ``destination``."""
        ...

    def default_gateway(self, family: AddressFamily) -> RouteInfo | None:
        """Return the route used when nothing more specific matches."""
        ...


def _backend() -> _RouteBackend:
    """Return this platform's route module.

    Imported on first use rather than at module top, so a process loads only
    the backend for the platform it runs on.
    """

    if IS_WINDOWS:  # pragma: no cover - exercised on Windows CI only
        from . import routes_windows as backend  # noqa: PLC0415 - load only this platform's backend
    elif IS_MACOS:  # pragma: no cover - exercised on macOS CI only
        from . import routes_macos as backend  # noqa: PLC0415 - load only this platform's backend
    else:
        from . import routes_linux as backend  # noqa: PLC0415 - load only this platform's backend
    return backend


def query_route(destination: str, family: AddressFamily = AddressFamily.IPV4) -> RouteInfo | None:
    """Return how this host would reach ``destination``.

    Args:
        destination: The address to look up. A literal, not a name: routing is
            a per-address question and resolving here would hide which of a
            name's addresses the answer describes.
        family: Which address family the destination belongs to.

    Returns:
        The route, or ``None`` when this host has none to that destination, or
        when the platform cannot answer.

    Examples:
        >>> route = query_route("127.0.0.1")
        >>> route is None or route.gateway is None
        True

    """

    # The routing table is asked about an address, not about an address on an
    # interface, and every backend packs the destination with inet_pton, which
    # refuses scoped text. Left in, the refusal is indistinguishable from an
    # honest "no route to there".
    bare = split_zone(destination).address
    return _backend().query_route(bare, family)


def default_gateway(family: AddressFamily = AddressFamily.IPV4) -> RouteInfo | None:
    """Return the route this host uses when nothing more specific matches.

    Args:
        family: Which address family to ask about. Availability genuinely
            differs: a host routing IPv4 through a gateway may reach IPv6
            on-link only, or not at all.

    Returns:
        The default route, or ``None`` when this host has none for that
        family. A host with no IPv6 default route is an ordinary
        configuration, not an error, so it is reported rather than raised.

    Examples:
        >>> route = default_gateway()
        >>> route is None or isinstance(route.gateway, (str, type(None)))
        True

    """

    return _backend().default_gateway(family)
