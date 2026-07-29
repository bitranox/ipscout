"""ICMP over unprivileged datagram sockets, sync and asyncio.

This is the module that delivers the no-administrator-rights promise on Linux
and macOS. ``SOCK_DGRAM`` with ``IPPROTO_ICMP`` is the "ping socket": the
kernel does the privileged part and hands user space an ordinary datagram
socket, so no ``CAP_NET_RAW`` and no setuid binary is involved.

Contents:
    PosixEchoTransport: Synchronous transport.
    AsyncPosixEchoTransport: The same, driven by the event loop.
    open_socket: Socket acquisition, with the permission diagnosis.

Two behaviours of these sockets shape everything here:

    The kernel rewrites the identifier. It substitutes its own value, so a
    reply never carries the identifier that was sent. Matching therefore keys
    on the sequence number plus the payload token from :mod:`ipscout.packet`.

    There is no IP header. Unlike a raw socket, a received datagram starts at
    the ICMP header, so nothing here skips a variable-length IHL prefix.

Note:
    When the datagram socket is unavailable - a hardened
    ``net.ipv4.ping_group_range``, or a kernel without ping sockets - a raw
    socket is tried, which succeeds for root or ``CAP_NET_RAW``. Only when both
    fail is :class:`~ipscout.errors.IPScoutPermissionError` raised, carrying
    the concrete remediation rather than a bare refusal.

"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import time
from typing import TYPE_CHECKING

from . import packet
from .errors import IPScoutPermissionError
from .models import AddressFamily
from .ports import EchoResult

if TYPE_CHECKING:
    from types import TracebackType

__all__ = ["AsyncPosixEchoTransport", "PosixEchoTransport", "open_socket"]

_FAMILY_TO_SOCKET = {
    AddressFamily.IPV4: (socket.AF_INET, socket.IPPROTO_ICMP),
    AddressFamily.IPV6: (socket.AF_INET6, socket.IPPROTO_ICMPV6),
}

#: Guidance attached to a permission failure, because "denied" alone is useless.
_REMEDIATION = (
    "unprivileged ICMP is unavailable and no raw socket could be opened. Fix any one of:\n"
    '  - Linux: sysctl -w net.ipv4.ping_group_range="0 2147483647"\n'
    "    (persist it in /etc/sysctl.d/ to survive a reboot)\n"
    "  - grant the process CAP_NET_RAW\n"
    "  - pass allow_tcp_fallback=True to probe over TCP instead of ICMP"
)


def open_socket(family: AddressFamily) -> socket.socket:
    """Return an ICMP socket, preferring the unprivileged datagram flavour.

    Args:
        family: Which address family the socket should carry.

    Returns:
        A connected-less ICMP socket ready for ``sendto``.

    Raises:
        IPScoutPermissionError: Neither a datagram nor a raw ICMP socket could
            be opened. The message names every way to fix it.

    Note:
        The raw fallback exists so that running as root keeps working rather
        than failing on a machine where ping sockets are disabled. It is a
        fallback, never the first choice.

    """

    sock_family, proto = _FAMILY_TO_SOCKET[family]
    try:
        return socket.socket(sock_family, socket.SOCK_DGRAM, proto)
    except OSError as dgram_error:
        try:
            return socket.socket(sock_family, socket.SOCK_RAW, proto)
        except OSError as raw_error:
            msg = f"{_REMEDIATION}\n  (datagram socket: {dgram_error}; raw socket: {raw_error})"
            raise IPScoutPermissionError(msg) from raw_error


def _matches(parsed: packet.ParsedReply, *, sequence: int, token: bytes, is_ipv6: bool) -> bool:
    """Return whether a decoded datagram answers this specific probe.

    Deliberately ignores ``parsed.identifier``: the kernel rewrites that field
    on an unprivileged socket, so comparing it would reject every real reply.
    """

    return packet.is_echo_reply(parsed, is_ipv6=is_ipv6) and parsed.sequence == sequence and parsed.token == token


class PosixEchoTransport:
    """Send ICMP echoes and collect replies over one reused socket.

    One socket serves every probe in a burst, which keeps the kernel's chosen
    identifier stable and avoids the cost of re-opening per packet.

    Args:
        address: The resolved address to probe.
        family: Address family of ``address``.
        payload_size: Bytes of payload per echo.

    Examples:
        >>> with PosixEchoTransport("127.0.0.1", AddressFamily.IPV4) as transport:
        ...     result = transport.probe(sequence=1, timeout=2.0)
        >>> result.answered
        True

    """

    def __init__(self, address: str, family: AddressFamily, *, payload_size: int = 56) -> None:
        self._address = address
        self._family = family
        self._is_ipv6 = family is AddressFamily.IPV6
        self._payload_size = payload_size
        self._socket = open_socket(family)

    @property
    def supports_ttl(self) -> bool:
        """Return True: POSIX sockets expose a per-probe hop limit."""

        return True

    def _apply_ttl(self, ttl: int | None) -> None:
        """Set the outgoing hop limit for subsequent packets."""

        if ttl is None:
            return
        if self._is_ipv6:
            self._socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
        else:
            self._socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:
        """Send one echo and wait for the matching reply.

        Args:
            sequence: Sequence number identifying this probe.
            timeout: Seconds to wait in total, across however many foreign
                datagrams arrive first.
            ttl: Hop limit, or ``None`` for the system default.

        Returns:
            The outcome. A timeout yields an unanswered result rather than
            raising, because a silent host is an answer.

        Note:
            The receive loop keeps waiting after a non-matching datagram
            instead of treating it as failure. Another process on the same
            host can hold an ICMP socket and have its replies copied to ours,
            and discarding the remaining budget on the first stranger would
            turn a healthy target into a phantom timeout.

        """

        self._apply_ttl(ttl)
        datagram, token = packet.build_echo_request(
            sequence=sequence,
            payload_size=self._payload_size,
            is_ipv6=self._is_ipv6,
        )

        started = time.perf_counter()
        try:
            self._socket.sendto(datagram, (self._address, 0))
        except OSError:
            # An unreachable network refuses at send time; that is a result.
            return EchoResult()

        deadline = started + timeout
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return EchoResult()
            self._socket.settimeout(remaining)
            try:
                raw, peer = self._socket.recvfrom(65535)
            except (TimeoutError, OSError):
                return EchoResult()

            elapsed_ms = (time.perf_counter() - started) * 1000.0
            parsed = packet.parse_echo_reply(raw)
            if parsed is not None and _matches(parsed, sequence=sequence, token=token, is_ipv6=self._is_ipv6):
                return EchoResult(rtt_ms=elapsed_ms, source=str(peer[0]))

    def close(self) -> None:
        """Close the underlying socket."""

        with contextlib.suppress(OSError):
            self._socket.close()

    def __enter__(self) -> PosixEchoTransport:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class AsyncPosixEchoTransport:
    """The same probing contract, driven by the event loop rather than blocking.

    One socket is registered with ``loop.add_reader`` and every outstanding
    probe waits on its own future, keyed by token. That is what lets a sweep of
    thousands of targets run on a single socket in a single thread instead of
    one thread per host.

    Args:
        address: The resolved address to probe.
        family: Address family of ``address``.
        payload_size: Bytes of payload per echo.

    """

    def __init__(self, address: str, family: AddressFamily, *, payload_size: int = 56) -> None:
        self._address = address
        self._family = family
        self._is_ipv6 = family is AddressFamily.IPV6
        self._payload_size = payload_size
        self._socket = open_socket(family)
        # settimeout(0) is setblocking(False) without a boolean positional arg.
        self._socket.settimeout(0)
        self._waiters: dict[bytes, asyncio.Future[tuple[float, str]]] = {}
        self._reader_installed = False

    @property
    def supports_ttl(self) -> bool:
        """Return True: POSIX sockets expose a per-probe hop limit."""

        return True

    def _ensure_reader(self) -> None:
        """Register the socket with the running loop, once."""

        if not self._reader_installed:
            asyncio.get_running_loop().add_reader(self._socket.fileno(), self._on_readable)
            self._reader_installed = True

    def _on_readable(self) -> None:
        """Drain the socket and hand each matching datagram to its waiter."""

        while True:
            try:
                raw, peer = self._socket.recvfrom(65535)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return

            parsed = packet.parse_echo_reply(raw)
            if parsed is None or not packet.is_echo_reply(parsed, is_ipv6=self._is_ipv6):
                continue
            token = parsed.token
            if token is None:
                continue
            waiter = self._waiters.get(token)
            # A token with no waiter is a late reply to a probe that already
            # timed out, or another process's traffic. Both are simply dropped.
            if waiter is not None and not waiter.done():
                waiter.set_result((time.perf_counter(), str(peer[0])))

    def _apply_ttl(self, ttl: int | None) -> None:
        """Set the outgoing hop limit for subsequent packets."""

        if ttl is None:
            return
        if self._is_ipv6:
            self._socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
        else:
            self._socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    async def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:
        """Send one echo and await the matching reply.

        Args:
            sequence: Sequence number identifying this probe.
            timeout: Seconds to wait for a reply.
            ttl: Hop limit, or ``None`` for the system default.

        Returns:
            The outcome, unanswered on timeout.

        """

        self._ensure_reader()
        self._apply_ttl(ttl)
        datagram, token = packet.build_echo_request(
            sequence=sequence,
            payload_size=self._payload_size,
            is_ipv6=self._is_ipv6,
        )

        loop = asyncio.get_running_loop()
        waiter: asyncio.Future[tuple[float, str]] = loop.create_future()
        self._waiters[token] = waiter
        started = time.perf_counter()
        try:
            try:
                self._socket.sendto(datagram, (self._address, 0))
            except OSError:
                return EchoResult()

            try:
                finished, source = await asyncio.wait_for(waiter, timeout)
            except (TimeoutError, asyncio.TimeoutError):
                return EchoResult()
            return EchoResult(rtt_ms=(finished - started) * 1000.0, source=source)
        finally:
            # Always unregister, so a timed-out probe cannot leak its entry and
            # a later reply to it cannot resolve a future nobody is awaiting.
            self._waiters.pop(token, None)

    async def aclose(self) -> None:
        """Unregister from the loop and close the socket."""

        if self._reader_installed:
            with contextlib.suppress(RuntimeError, ValueError, OSError):
                asyncio.get_running_loop().remove_reader(self._socket.fileno())
            self._reader_installed = False
        with contextlib.suppress(OSError):
            self._socket.close()

    async def __aenter__(self) -> AsyncPosixEchoTransport:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
