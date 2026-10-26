"""ICMP on Windows through the IP Helper API, without administrator rights.

Windows has no unprivileged ICMP socket, so this backend calls
``IcmpSendEcho`` / ``Icmp6SendEcho2`` instead. Those are ordinary user-mode
calls; the elevation requirement that applies to raw sockets does not apply
here, which is what keeps the no-admin promise on this platform.

Contents:
    WindowsEchoTransport: Synchronous transport.
    AsyncWindowsEchoTransport: Executor-backed asyncio transport.
    ipv6_destination: The ``SOCKADDR_IN6`` an IPv6 echo is sent to.
    api_destination: The destination in the form the echo call takes.
    echo_outcome: An ``IP_STATUS`` plus timings, as a transport result.

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
import time
from typing import TYPE_CHECKING

from . import packet, winapi
from .errors import IPScoutPermissionError, IPScoutUnsupportedError
from .models import AddressFamily, require_address
from .ports import EchoResult
from .resolve import split_zone, zone_index

if TYPE_CHECKING:
    from types import TracebackType

__all__ = ["AsyncWindowsEchoTransport", "WindowsEchoTransport", "api_destination", "echo_outcome", "ipv6_destination", "windows_icmp_available"]

#: Threads serving the async variant. Bounded, because each in-flight probe
#: occupies one for the duration of its timeout.
_MAX_WORKERS = 32


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


def ipv6_destination(address: str) -> winapi.SOCKADDR_IN6:
    """Build the ``SOCKADDR_IN6`` an ``Icmp6SendEcho2`` request is sent to.

    Args:
        address: An IPv6 literal, optionally with a ``%zone`` suffix.

    Returns:
        The structure, carrying Windows' ``AF_INET6`` number and the zone's
        interface index as its scope id.

    Raises:
        ValueError: ``address`` is not an IPv6 address literal.
        IPScoutResolutionError: The zone names no interface this host has.

    Examples:
        >>> sockaddr = ipv6_destination("2001:db8::1")
        >>> sockaddr.sin6_family == winapi.WIN_AF_INET6, sockaddr.sin6_scope_id
        (True, 0)
        >>> ipv6_destination("192.0.2.1")
        Traceback (most recent call last):
        ...
        ValueError: '192.0.2.1' is not an ipv6 address

    """

    # The packed bytes cannot carry a zone, so the zone travels in the one
    # field that can: the scope id, as the interface index it names.
    packed = require_address(address, AddressFamily.IPV6).packed
    zone = split_zone(address).zone
    return winapi.sockaddr_in6(packed, scope_id=zone_index(zone) if zone is not None else 0)


def api_destination(address: str, family: AddressFamily) -> int | winapi.SOCKADDR_IN6:
    """Return ``address`` in the form the echo call for ``family`` takes.

    Args:
        address: An address literal of ``family``; an IPv6 one may carry a
            ``%zone``.
        family: Which call the destination is for.

    Returns:
        The ``IPAddr`` ``IcmpSendEcho`` takes for IPv4, or the
        ``SOCKADDR_IN6`` ``Icmp6SendEcho2`` takes for IPv6.

    Raises:
        ValueError: ``address`` is not an address literal of ``family``.
        IPScoutResolutionError: The zone names no interface this host has.

    Examples:
        >>> api_destination("127.0.0.1", AddressFamily.IPV4) == 0x0100007F
        True
        >>> isinstance(api_destination("2001:db8::1", AddressFamily.IPV6), winapi.SOCKADDR_IN6)
        True

    """

    if family is AddressFamily.IPV6:
        return ipv6_destination(address)
    # Checked through require_address so the refusal reads as it does in every
    # other entry point; string_to_ipv4 then only converts.
    return winapi.string_to_ipv4(str(require_address(address, family)))


def echo_outcome(status: winapi.IpStatus | None, *, elapsed_ms: float, api_rtt_ms: int, source: str) -> EchoResult:
    """Turn a decoded ``IP_STATUS`` plus timings into a transport-level result.

    Prefers the measured elapsed time over the API's own figure, which is
    quantised to whole milliseconds and so reports 0 for anything on a LAN.

    Args:
        status: The reply's status as :meth:`~ipscout.winapi.IpStatus.parse`
            decoded it; ``None`` for a code with no member.
        elapsed_ms: Wall time measured around the call.
        api_rtt_ms: The round-trip time the API reported.
        source: The address the reply came from.

    Returns:
        An answered result for ``SUCCESS``, an expired-hop result for
        ``TTL_EXPIRED_TRANSIT``, and an unanswered one for every other status,
        an unlisted code included.

    Examples:
        >>> echo_outcome(winapi.IpStatus.SUCCESS, elapsed_ms=1.5, api_rtt_ms=1, source="192.0.2.1").rtt_ms
        1.5
        >>> echo_outcome(None, elapsed_ms=1.5, api_rtt_ms=1, source="192.0.2.1").rtt_ms is None
        True

    """

    measured = elapsed_ms if elapsed_ms > 0 else float(api_rtt_ms)
    if status is winapi.IpStatus.SUCCESS:
        return EchoResult(rtt_ms=measured, source=source)
    if status is winapi.IpStatus.TTL_EXPIRED_TRANSIT:
        # A router answered. Not a reply to ping, but exactly what
        # traceroute needs, so it is reported rather than discarded.
        return EchoResult(rtt_ms=measured, source=source, ttl_expired=True)
    return EchoResult()


class WindowsEchoTransport:
    """Send ICMP echoes through ``iphlpapi.dll``.

    One handle is opened per transport and reused for every probe in a burst,
    mirroring how the POSIX backend reuses one socket.

    Args:
        address: The resolved address to probe.
        family: Address family of ``address``.
        payload_size: Bytes of payload per echo.

    Raises:
        ValueError: ``address`` is not an address literal of ``family``.
        IPScoutResolutionError: An IPv6 zone names no interface this host has.
        IPScoutUnsupportedError: Not running on Windows, or the DLL is absent.
        IPScoutPermissionError: The ICMP handle could not be opened.

    """

    def __init__(self, address: str, family: AddressFamily, *, payload_size: int = packet.DEFAULT_PAYLOAD_SIZE) -> None:
        # Parsed once, before the library loads: every probe of a burst reuses
        # it, and a malformed address is refused here on every platform rather
        # than on the first probe.
        self._destination = api_destination(address, family)
        self._family = family
        self._payload_size = payload_size
        self._library = winapi.iphlpapi()
        self._handle = self._open_handle()

    def _open_handle(self) -> int:  # pragma: no cover - Windows only
        """Open the ICMP handle for this transport's address family."""

        opener = self._library.Icmp6CreateFile if self._family is AddressFamily.IPV6 else self._library.IcmpCreateFile
        handle = opener()
        if not handle or handle == winapi.INVALID_HANDLE_VALUE:
            msg = f"could not open an ICMP handle via iphlpapi (error {winapi.last_error()})"
            raise IPScoutPermissionError(msg)
        return int(handle)

    @property
    def supports_ttl(self) -> bool:
        """Return True: the API accepts a per-request TTL."""

        return True

    @property
    def supports_ttl_discovery(self) -> bool:
        """Return True: the API reports ``IpStatus.TTL_EXPIRED_TRANSIT`` with the router."""

        return True

    def _options(self, ttl: int | None) -> winapi.IP_OPTION_INFORMATION:
        """Build the request options carrying the requested hop limit."""

        return winapi.IP_OPTION_INFORMATION(
            Ttl=ttl if ttl is not None else winapi.DEFAULT_TTL,
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

        datagram = packet.build_echo_request(
            sequence=sequence,
            payload_size=self._payload_size,
            family=self._family,
        ).datagram
        payload = datagram[packet.HEADER_SIZE :]
        timeout_ms = max(1, int(timeout * 1000))
        # Dispatched on the destination's type, which api_destination chose by
        # family, so the type checker sees each call get the form it takes.
        if isinstance(self._destination, winapi.SOCKADDR_IN6):  # pragma: no cover - Windows only
            return self._probe_v6(payload, timeout_ms, ttl, self._destination)
        return self._probe_v4(payload, timeout_ms, ttl, self._destination)  # pragma: no cover - Windows only

    def _probe_v4(self, payload: bytes, timeout_ms: int, ttl: int | None, destination: int) -> EchoResult:  # pragma: no cover - Windows only
        """Issue an IPv4 echo through ``IcmpSendEcho``."""

        request = ctypes.create_string_buffer(payload, len(payload))
        reply_size = winapi.reply_buffer_size(winapi.ICMP_ECHO_REPLY, len(payload))
        reply_buffer = ctypes.create_string_buffer(reply_size)
        options = self._options(ttl)

        started = time.perf_counter()
        replies = self._library.IcmpSendEcho(
            ctypes.c_void_p(self._handle),
            destination,
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
        status = winapi.IpStatus.parse(int(reply.Status))
        return echo_outcome(status, elapsed_ms=elapsed_ms, api_rtt_ms=int(reply.RoundTripTime), source=source)

    def _probe_v6(self, payload: bytes, timeout_ms: int, ttl: int | None, destination: winapi.SOCKADDR_IN6) -> EchoResult:  # pragma: no cover - Windows only
        """Issue an IPv6 echo through ``Icmp6SendEcho2``."""

        request = ctypes.create_string_buffer(payload, len(payload))
        reply_size = winapi.reply_buffer_size(winapi.ICMPV6_ECHO_REPLY, len(payload))
        reply_buffer = ctypes.create_string_buffer(reply_size)
        options = self._options(ttl)

        source_address = winapi.sockaddr_in6()

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
        status = winapi.IpStatus.parse(int(reply.Status))
        return echo_outcome(status, elapsed_ms=elapsed_ms, api_rtt_ms=int(reply.RoundTripTime), source=source)

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
        payload_size: int = packet.DEFAULT_PAYLOAD_SIZE,
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

    @property
    def supports_ttl_discovery(self) -> bool:
        """Return whether expired hops can be observed, as the inner one says."""

        return self._inner.supports_ttl_discovery

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
