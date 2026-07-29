"""Chooses the transport backend for this platform, family and options.

One place decides which concrete transport a probe will use, so the layers
above never branch on ``sys.platform``. That keeps :mod:`ipscout.service` and
:mod:`ipscout.traceroute` free of platform knowledge and therefore testable
with an injected fake on any machine.

Contents:
    make_transport: Build a synchronous transport.
    make_async_transport: Build an asyncio transport.
    icmp_available: Report whether ICMP can be used without raising.

"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from .errors import IPScoutPermissionError
from .models import AddressFamily
from .transport_posix import AsyncPosixEchoTransport, PosixEchoTransport, open_socket
from .transport_tcp import AsyncTcpEchoTransport, TcpEchoTransport
from .transport_windows import AsyncWindowsEchoTransport, WindowsEchoTransport, windows_icmp_available

if TYPE_CHECKING:
    from .ports import AsyncEchoTransport, EchoTransport

__all__ = ["icmp_available", "make_async_transport", "make_transport"]

#: True on Windows, where ICMP goes through iphlpapi rather than a socket.
IS_WINDOWS = sys.platform == "win32"


def icmp_available(family: AddressFamily = AddressFamily.IPV4) -> bool:
    """Return whether an ICMP probe could be made right now.

    Args:
        family: Family to test. Availability can genuinely differ between the
            two, so the answer is per-family rather than global.

    Returns:
        True when a transport could be constructed, False when the privilege
        or the backend is missing.

    Note:
        Provided so callers such as ``is_reachable`` can decide to use TCP
        without provoking and swallowing an exception, and so the CLI can
        explain the situation rather than showing a traceback.

    Examples:
        >>> isinstance(icmp_available(), bool)
        True

    """

    if IS_WINDOWS:  # pragma: no cover - exercised on Windows CI only
        return windows_icmp_available()
    try:
        open_socket(family).close()
    except IPScoutPermissionError:
        return False
    return True


def make_transport(
    address: str,
    family: AddressFamily,
    *,
    payload_size: int = 56,
    use_tcp: bool = False,
    tcp_port: int = 443,
) -> EchoTransport:
    """Return a synchronous transport for these parameters.

    Args:
        address: Resolved address to probe.
        family: Address family of ``address``.
        payload_size: Bytes of ICMP payload. Ignored by the TCP transport.
        use_tcp: Probe with a TCP connect instead of ICMP.
        tcp_port: Port for the TCP probe.

    Returns:
        A ready transport. The caller owns it and must close it.

    Raises:
        IPScoutPermissionError: ICMP was requested but no socket can be opened.
        IPScoutUnsupportedError: No ICMP backend exists for this platform.

    """

    if use_tcp:
        return TcpEchoTransport(address, family, port=tcp_port)
    if IS_WINDOWS:  # pragma: no cover - exercised on Windows CI only
        return WindowsEchoTransport(address, family, payload_size=payload_size)
    return PosixEchoTransport(address, family, payload_size=payload_size)


def make_async_transport(
    address: str,
    family: AddressFamily,
    *,
    payload_size: int = 56,
    use_tcp: bool = False,
    tcp_port: int = 443,
) -> AsyncEchoTransport:
    """Return an asyncio transport for these parameters.

    Args:
        address: Resolved address to probe.
        family: Address family of ``address``.
        payload_size: Bytes of ICMP payload. Ignored by the TCP transport.
        use_tcp: Probe with a TCP connect instead of ICMP.
        tcp_port: Port for the TCP probe.

    Returns:
        A ready transport. The caller owns it and must close it.

    Raises:
        IPScoutPermissionError: ICMP was requested but no socket can be opened.
        IPScoutUnsupportedError: No ICMP backend exists for this platform.

    """

    if use_tcp:
        return AsyncTcpEchoTransport(address, family, port=tcp_port)
    if IS_WINDOWS:  # pragma: no cover - exercised on Windows CI only
        return AsyncWindowsEchoTransport(address, family, payload_size=payload_size)
    return AsyncPosixEchoTransport(address, family, payload_size=payload_size)
