"""Chooses the interface-enumeration backend for this platform.

Contents:
    local_interfaces: Every local interface, on any supported platform.

Note:
    The two backends read the same facts through entirely different APIs -
    ``getifaddrs`` on POSIX, ``GetAdaptersAddresses`` on Windows - and both
    return the same frozen :class:`~ipscout.models.Interface`, so callers above
    this line never branch on platform. Both import safely everywhere; only the
    calls themselves are platform-specific.

"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from .interfaces_posix import list_interfaces as _posix_interfaces
from .interfaces_windows import list_interfaces as _windows_interfaces

if TYPE_CHECKING:
    from .models import Interface

__all__ = ["local_interfaces"]

IS_WINDOWS = sys.platform == "win32"


def local_interfaces() -> list[Interface]:
    """Return every local network interface.

    Returns:
        One record per interface, including those that are down, since a down
        interface is a fact worth reporting rather than an omission.

    Examples:
        >>> interfaces = local_interfaces()
        >>> any(item.is_loopback for item in interfaces)
        True

    """

    if IS_WINDOWS:  # pragma: no cover - exercised on Windows CI only
        return _windows_interfaces()
    return _posix_interfaces()
