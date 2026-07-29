"""ICMP on Windows through the IP Helper API, without administrator rights.

Windows has no unprivileged ICMP socket, so this backend calls
``IcmpSendEcho`` / ``Icmp6SendEcho2`` instead. Those are ordinary user-mode
calls; the elevation requirement that applies to raw sockets does not apply
here, which is what keeps the no-admin promise on this platform.

Contents:
    WindowsEchoTransport: Synchronous transport.
    AsyncWindowsEchoTransport: Executor-backed asyncio transport.

Two honest limitations, stated rather than hidden:

    **The async transport is not natively asynchronous.** ``IcmpSendEcho`` is a
    blocking C call with no asyncio integration, so the async variant runs it
    in a bounded thread pool. Behaviour matches the POSIX path exactly; scaling
    does not. On Linux and macOS a thousand concurrent probes share one socket
    on one thread, whereas here they are limited by the pool.

    **The API reports round-trip time in whole milliseconds.** Anything faster
    than 1 ms reads as 0. This module therefore measures with
    ``time.perf_counter`` around the call and uses the API's own value only as
    a fallback, so loopback and LAN timings stay meaningful.

Note:
    Reply matching does not need the payload token here. Unlike a shared ICMP
    socket, each call owns its request and the API correlates the reply itself,
    so a foreign reply cannot be delivered to us. The token is still sent, so
    the payload is identical across backends.

"""

from __future__ import annotations

import asyncio
import concurrent.futures
import ctypes
import socket
import time
from typing import TYPE_CHECKING, Protocol, cast

from . import packet, winapi
from .errors import IPScoutPermissionError, IPScoutUnsupportedError
from .models import AddressFamily
from .ports import EchoResult

if TYPE_CHECKING:
    from types import TracebackType

__all__ = ["AsyncWindowsEchoTransport", "WindowsEchoTransport", "windows_icmp_available"]

#: Headroom above the echoed payload, as the API documentation requires: the
#: reply buffer must also be able to hold an ICMP error message.
_REPLY_HEADROOM = 64

#: Threads serving the async variant. Bounded, because each in-flight probe
#: occupies one for the duration of its timeout.
_MAX_WORKERS = 32


class _LastErrorGetter(Protocol):
    """The shape of ``ctypes.get_last_error``."""

    def __call__(self) -> int: ...


def _last_error() -> int:
    """Return the thread's last Win32 error code, or 0 where there is none.

    ``ctypes.get_last_error`` is declared Windows-only in the type stubs, so a
    direct attribute access would fail type checking on every other platform
    even though the call is guarded. Reaching it dynamically through a typed
    facade keeps the call site fully typed without silencing the checker.
    """

    getter = cast("_LastErrorGetter | None", getattr(ctypes, "get_last_error", None))
    return getter() if getter is not None else 0


def windows_icmp_available() -> bool:
    """Return whether the IP Helper ICMP entry points can be used here.

    Returns:
        True when the DLL loads and a handle can be opened.

    """

    try:
        library = winapi.iphlpapi()
    except IPScoutUnsupportedError:
        return False
    handle = library.IcmpCreateFile()  # pragma: no cover - Windows only
    if not handle or handle == winapi.INVALID_HANDLE_VALUE:  # pragma: no cover - Windows only
        return False
    library.IcmpCloseHandle(handle)  # pragma: no cover - Windows only
    return True  # pragma: no cover - Windows only


class WindowsEchoTransport:
    """Send ICMP echoes through ``iphlpapi.dll``.

    One handle is opened per transport and reused for every probe in a burst,
    mirroring how the POSIX backend reuses one socket.

    Args:
        address: The resolved address to probe.
        family: Address family of ``address``.
        payload_size: Bytes of payload per echo.

    Raises:
        IPScoutUnsupportedError: Not running on Windows, or the DLL is absent.
        IPScoutPermissionError: The ICMP handle could not be opened.

    """

    def __init__(self, address: str, family: AddressFamily, *, payload_size: int = 56) -> None:
        self._address = address
        self._family = family
        self._is_ipv6 = family is AddressFamily.IPV6
        self._payload_size = payload_size
        self._library = winapi.iphlpapi()
        self._handle = self._open_handle()

    def _open_handle(self) -> int:  # pragma: no cover - Windows only
        """Open the ICMP handle for this transport's address family."""

        opener = self._library.Icmp6CreateFile if self._is_ipv6 else self._library.IcmpCreateFile
        handle = opener()
        if not handle or handle == winapi.INVALID_HANDLE_VALUE:
            msg = f"could not open an ICMP handle via iphlpapi (error {_last_error()})"
            raise IPScoutPermissionError(msg)
        return int(handle)

    @property
    def supports_ttl(self) -> bool:
        """Return True: the API accepts a per-request TTL."""

        return True

    def _options(self, ttl: int | None) -> winapi.IP_OPTION_INFORMATION:
        """Build the request options carrying the requested hop limit."""

        return winapi.IP_OPTION_INFORMATION(
            Ttl=ttl if ttl is not None else 128,
            Tos=0,
            Flags=0,
            OptionsSize=0,
            OptionsData=None,
        )

    def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:
        """Send one echo and wait for its reply.

        Args:
            sequence: Sequence number, carried in the payload token for parity
                with the POSIX backend. The API does its own correlation.
            timeout: Seconds to wait, converted to the whole milliseconds the
                API accepts, with a floor of 1 ms so a small value is never
                rounded down to "no wait at all".
            ttl: Hop limit, or ``None`` for the system default.

        Returns:
            The outcome. A timeout or an unreachable destination yields an
            unanswered result rather than raising.

        """

        datagram, _token = packet.build_echo_request(
            sequence=sequence,
            payload_size=self._payload_size,
            is_ipv6=self._is_ipv6,
        )
        payload = datagram[packet.HEADER_SIZE :]
        timeout_ms = max(1, int(timeout * 1000))
        if self._is_ipv6:  # pragma: no cover - Windows only
            return self._probe_v6(payload, timeout_ms, ttl)
        return self._probe_v4(payload, timeout_ms, ttl)  # pragma: no cover - Windows only

    def _probe_v4(self, payload: bytes, timeout_ms: int, ttl: int | None) -> EchoResult:  # pragma: no cover - Windows only
        """Issue an IPv4 echo through ``IcmpSendEcho``."""

        request = ctypes.create_string_buffer(payload, len(payload))
        reply_size = ctypes.sizeof(winapi.ICMP_ECHO_REPLY) + len(payload) + _REPLY_HEADROOM
        reply_buffer = ctypes.create_string_buffer(reply_size)
        options = self._options(ttl)

        started = time.perf_counter()
        replies = self._library.IcmpSendEcho(
            ctypes.c_void_p(self._handle),
            winapi.string_to_ipv4(self._address),
            ctypes.cast(request, ctypes.c_void_p),
            ctypes.c_uint16(len(payload)),
            ctypes.byref(options),
            ctypes.cast(reply_buffer, ctypes.c_void_p),
            ctypes.c_uint32(reply_size),
            ctypes.c_uint32(timeout_ms),
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if not replies:
            return EchoResult()

        reply = ctypes.cast(reply_buffer, ctypes.POINTER(winapi.ICMP_ECHO_REPLY)).contents
        source = winapi.ipv4_to_string(reply.Address)
        return self._interpret(reply.Status, elapsed_ms, reply.RoundTripTime, source)

    def _probe_v6(self, payload: bytes, timeout_ms: int, ttl: int | None) -> EchoResult:  # pragma: no cover - Windows only
        """Issue an IPv6 echo through ``Icmp6SendEcho2``."""

        request = ctypes.create_string_buffer(payload, len(payload))
        reply_size = ctypes.sizeof(winapi.ICMPV6_ECHO_REPLY) + len(payload) + _REPLY_HEADROOM
        reply_buffer = ctypes.create_string_buffer(reply_size)
        options = self._options(ttl)

        source_address = winapi.SOCKADDR_IN6(sin6_family=socket.AF_INET6)
        destination = winapi.SOCKADDR_IN6(sin6_family=socket.AF_INET6)
        packed = socket.inet_pton(socket.AF_INET6, self._address)
        ctypes.memmove(destination.sin6_addr, packed, len(packed))

        started = time.perf_counter()
        replies = self._library.Icmp6SendEcho2(
            ctypes.c_void_p(self._handle),
            None,
            None,
            None,
            ctypes.byref(source_address),
            ctypes.byref(destination),
            ctypes.cast(request, ctypes.c_void_p),
            ctypes.c_uint16(len(payload)),
            ctypes.byref(options),
            ctypes.cast(reply_buffer, ctypes.c_void_p),
            ctypes.c_uint32(reply_size),
            ctypes.c_uint32(timeout_ms),
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if not replies:
            return EchoResult()

        reply = ctypes.cast(reply_buffer, ctypes.POINTER(winapi.ICMPV6_ECHO_REPLY)).contents
        source = winapi.ipv6_words_to_string(reply.Address.sin6_addr)
        return self._interpret(reply.Status, elapsed_ms, reply.RoundTripTime, source)

    @staticmethod
    def _interpret(status: int, elapsed_ms: float, api_rtt_ms: int, source: str) -> EchoResult:  # pragma: no cover - Windows only
        """Turn an ``IP_STATUS`` plus timings into a transport-level result.

        Prefers the measured elapsed time over the API's own figure, which is
        quantised to whole milliseconds and so reports 0 for anything on a LAN.
        """

        measured = elapsed_ms if elapsed_ms > 0 else float(api_rtt_ms)
        if status == winapi.IP_SUCCESS:
            return EchoResult(rtt_ms=measured, source=source)
        if status == winapi.IP_TTL_EXPIRED_TRANSIT:
            # A router answered. Not a reply to ping, but exactly what
            # traceroute needs, so it is reported rather than discarded.
            return EchoResult(rtt_ms=measured, source=source, ttl_expired=True)
        return EchoResult()

    def close(self) -> None:
        """Release the ICMP handle."""

        if self._handle:  # pragma: no cover - Windows only
            self._library.IcmpCloseHandle(ctypes.c_void_p(self._handle))
            self._handle = 0

    def __enter__(self) -> WindowsEchoTransport:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class AsyncWindowsEchoTransport:
    """The Windows transport driven from asyncio, via a bounded thread pool.

    Not natively asynchronous, and deliberately not pretending to be: the
    underlying call blocks and has no event-loop integration. Each in-flight
    probe holds a worker thread for the duration of its timeout, so throughput
    is bounded by the pool rather than by the socket as it is on POSIX.

    Args:
        address: The resolved address to probe.
        family: Address family of ``address``.
        payload_size: Bytes of payload per echo.
        max_workers: Size of the thread pool.

    """

    def __init__(
        self,
        address: str,
        family: AddressFamily,
        *,
        payload_size: int = 56,
        max_workers: int = _MAX_WORKERS,
    ) -> None:
        self._inner = WindowsEchoTransport(address, family, payload_size=payload_size)
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="ipscout-icmp",
        )

    @property
    def supports_ttl(self) -> bool:
        """Return True: the API accepts a per-request TTL."""

        return self._inner.supports_ttl

    async def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:
        """Run one blocking probe on the pool and await its outcome."""

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._pool,
            lambda: self._inner.probe(sequence=sequence, timeout=timeout, ttl=ttl),
        )

    async def aclose(self) -> None:
        """Shut the pool down and release the ICMP handle."""

        self._inner.close()
        self._pool.shutdown(wait=False)

    async def __aenter__(self) -> AsyncWindowsEchoTransport:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
