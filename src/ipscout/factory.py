"""Chooses the transport backend for this platform, family and options.

One place decides which concrete transport a probe will use, so the layers
above never branch on ``sys.platform``. That keeps :mod:`ipscout.service` and
:mod:`ipscout.traceroute` free of platform knowledge and therefore testable
with an injected fake on any machine.

Contents:
    make_transport: Build a synchronous transport.
    make_async_transport: Build an asyncio transport.
    make_hop_transport: Build a synchronous ICMP transport that sees expired hops.
    make_async_hop_transport: Build an asyncio ICMP transport that sees expired hops.
    icmp_available: Report whether ICMP can be used without raising.

"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from .errors import IPScoutPermissionError
from .models import AddressFamily, ProbeMethod
from .packet import DEFAULT_PAYLOAD_SIZE
from .transport_posix import AsyncPosixEchoTransport, PosixEchoTransport, open_hop_socket, open_socket
from .transport_tcp import DEFAULT_TCP_PORT, AsyncTcpEchoTransport, TcpEchoTransport
from .transport_windows import AsyncWindowsEchoTransport, WindowsEchoTransport, windows_icmp_available

if TYPE_CHECKING:
    from .ports import AsyncEchoTransport, EchoTransport

__all__ = ["icmp_available", "make_async_hop_transport", "make_async_transport", "make_hop_transport", "make_transport"]

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
    payload_size: int = DEFAULT_PAYLOAD_SIZE,
    method: ProbeMethod = ProbeMethod.ICMP,
    tcp_port: int = DEFAULT_TCP_PORT,
) -> EchoTransport:
    """Return a synchronous transport for these parameters.

    Args:
        address: Resolved address to probe.
        family: Address family of ``address``.
        payload_size: Bytes of ICMP payload. Ignored by the TCP transport.
        method: How to probe: an ICMP echo, or a TCP connect to ``tcp_port``.
        tcp_port: Port for the TCP probe.

    Returns:
        A ready transport. The caller owns it and must close it.

    Raises:
        IPScoutPermissionError: ICMP was requested but no socket can be opened.
        IPScoutUnsupportedError: No ICMP backend exists for this platform.

    """

    if method is ProbeMethod.TCP:
        return TcpEchoTransport(address, family, port=tcp_port)
    if IS_WINDOWS:  # pragma: no cover - exercised on Windows CI only
        return WindowsEchoTransport(address, family, payload_size=payload_size)
    return PosixEchoTransport(address, family, payload_size=payload_size)


def make_async_transport(
    address: str,
    family: AddressFamily,
    *,
    payload_size: int = DEFAULT_PAYLOAD_SIZE,
    method: ProbeMethod = ProbeMethod.ICMP,
    tcp_port: int = DEFAULT_TCP_PORT,
) -> AsyncEchoTransport:
    """Return an asyncio transport for these parameters.

    Args:
        address: Resolved address to probe.
        family: Address family of ``address``.
        payload_size: Bytes of ICMP payload. Ignored by the TCP transport.
        method: How to probe: an ICMP echo, or a TCP connect to ``tcp_port``.
        tcp_port: Port for the TCP probe.

    Returns:
        A ready transport. The caller owns it and must close it.

    Raises:
        IPScoutPermissionError: ICMP was requested but no socket can be opened.
        IPScoutUnsupportedError: No ICMP backend exists for this platform.

    """

    if method is ProbeMethod.TCP:
        return AsyncTcpEchoTransport(address, family, port=tcp_port)
    if IS_WINDOWS:  # pragma: no cover - exercised on Windows CI only
        return AsyncWindowsEchoTransport(address, family, payload_size=payload_size)
    return AsyncPosixEchoTransport(address, family, payload_size=payload_size)


def make_hop_transport(address: str, family: AddressFamily) -> EchoTransport:
    """Return a synchronous ICMP transport that can observe expired hops, for a hop walk.

    On macOS that is a raw socket when the process may open one: the datagram
    socket there has no error queue, so it never sees Time Exceeded.

    Args:
        address: Resolved address to walk towards.
        family: Address family of ``address``.

    Returns:
        A ready transport. The caller owns it and must close it.

    Raises:
        IPScoutPermissionError: No ICMP socket can be opened.
        IPScoutUnsupportedError: No ICMP backend exists for this platform.

    """

    if IS_WINDOWS:  # pragma: no cover - exercised on Windows CI only
        return WindowsEchoTransport(address, family)
    return PosixEchoTransport(address, family, socket_factory=open_hop_socket)


def make_async_hop_transport(address: str, family: AddressFamily) -> AsyncEchoTransport:
    """Return an asyncio ICMP transport that can observe expired hops, for a hop walk.

    As :func:`make_hop_transport`.

    Args:
        address: Resolved address to walk towards.
        family: Address family of ``address``.

    Returns:
        A ready transport. The caller owns it and must close it.

    Raises:
        IPScoutPermissionError: No ICMP socket can be opened.
        IPScoutUnsupportedError: No ICMP backend exists for this platform.

    """

    if IS_WINDOWS:  # pragma: no cover - exercised on Windows CI only
        return AsyncWindowsEchoTransport(address, family)
    return AsyncPosixEchoTransport(address, family, socket_factory=open_hop_socket)
