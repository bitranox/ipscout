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
import struct
import sys
import time
from typing import TYPE_CHECKING, Protocol, cast

from . import packet
from .errors import IPScoutPermissionError
from .models import AddressFamily
from .ports import EchoResult
from .resolve import split_zone, zone_index

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    #: How a transport obtains its socket. Injecting this is the seam that lets
    #: the matching, timeout and drain logic be exercised over ordinary UDP on
    #: hosts where opening an ICMP socket is not permitted at all.
    SocketFactory = Callable[[AddressFamily], socket.socket]

__all__ = ["AsyncPosixEchoTransport", "PosixEchoTransport", "RecvMsg", "open_socket", "recvmsg_of", "socket_const"]

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


def _is_raw_socket(sock: socket.socket) -> bool:
    """Return whether this is a raw socket rather than a datagram one.

    Worth knowing because the two see different things: a raw ICMP socket
    receives Time Exceeded messages directly, which is what lets traceroute
    work on macOS when the process is privileged.
    """

    try:
        return sock.type == socket.SOCK_RAW
    except (AttributeError, OSError):  # pragma: no cover - exotic socket doubles
        return False


class RecvMsg(Protocol):
    """The shape of ``socket.recvmsg``, which exists only on POSIX."""

    def __call__(self, bufsize: int, ancbufsize: int = ..., flags: int = ..., /) -> tuple[bytes, list[tuple[int, int, bytes]], int, object]: ...


#: Linux socket options that CPython only began exposing in 3.14. The values
#: are kernel ABI (``linux/in.h``: ``IP_RECVERR 11``, ``linux/in6.h``:
#: ``IPV6_RECVERR 25``) and therefore fixed forever - changing one would break
#: every compiled binary on the platform.
#:
#: Without this fallback traceroute silently reported itself unsupported on
#: Linux for every Python below 3.14, because the option lookup came back empty
#: and the capability check honestly answered "no". The failure was invisible on
#: a 3.14 development machine and invisible in CI, whose Linux runners refuse
#: ICMP outright and skip those tests.
_LINUX_ABI_FALLBACK = {
    "IP_RECVERR": 11,
    "IPV6_RECVERR": 25,
}


def socket_const(name: str) -> int | None:
    """Return a socket constant that only some platforms or versions define.

    ``IP_RECVERR`` and ``MSG_ERRQUEUE`` are Linux-only and absent from the
    macOS and Windows type stubs, so a direct attribute access fails type
    checking there even when it is guarded at runtime. Looking them up by name
    keeps every call site typed without silencing the checker per platform.

    Falls back to the kernel ABI value on Linux when the running CPython is too
    old to expose the name. The fallback is Linux-only: on a platform where the
    option does not exist as a concept, inventing a number would only turn a
    clean "unsupported" into a confusing ``setsockopt`` failure.

    Args:
        name: The constant's name in the ``socket`` module.

    Returns:
        The value, or ``None`` where this platform genuinely lacks it.

    Examples:
        >>> socket_const("SO_REUSEADDR") is not None
        True
        >>> socket_const("NO_SUCH_SOCKET_CONSTANT") is None
        True

    """

    value = getattr(socket, name, None)
    if isinstance(value, int):
        return value
    if sys.platform.startswith("linux"):
        return _LINUX_ABI_FALLBACK.get(name)
    return None


def recvmsg_of(sock: socket.socket) -> RecvMsg | None:
    """Return the socket's ``recvmsg``, or None where the platform lacks it.

    Windows has no ``recvmsg`` at all, so reading the error queue - and with it
    unprivileged traceroute - is simply unavailable there and is served by the
    IP Helper API instead.

    Args:
        sock: The socket to take the bound method from.

    Returns:
        The bound method, or ``None`` on a platform without it.

    """

    return cast("RecvMsg | None", getattr(sock, "recvmsg", None))


#: ``struct sock_extended_err``: errno, origin, type, code, pad, info, data.
#: Native byte order and alignment, as the kernel writes it.
_EXTENDED_ERR = struct.Struct("=IBBBBII")

#: ``SO_EE_ORIGIN_ICMP`` / ``SO_EE_ORIGIN_ICMP6``: the error came from a router
#: rather than from the local stack.
_ORIGIN_ICMP = 2
_ORIGIN_ICMP6 = 3

#: ICMP "Time Exceeded" in each family. A router sends this when it discards a
#: packet whose hop limit ran out, which is the entire basis of traceroute.
_TIME_EXCEEDED_V4 = 11
_TIME_EXCEEDED_V6 = 3


def _destination_for(address: str, *, is_ipv6: bool) -> tuple[str, int] | tuple[str, int, int, int]:
    """Return the sockaddr to send to, carrying the interface when scoped.

    An ICMPv6 socket refuses a zone written into the address string: measured
    on Linux, ``sendto(datagram, ("fe80::1%eth0", 0))`` fails with EINVAL, and
    so does the bare form, while the same address with the interface index in
    the sockaddr's scope-id field is answered. So the zone travels as a number
    here rather than as text, even though ``getaddrinfo`` accepts either.
    """

    if not is_ipv6:
        return (address, 0)
    bare, zone = split_zone(address)
    if zone is None:
        return (bare, 0)
    return (bare, 0, 0, zone_index(zone))


def _offender_address(control: bytes, *, is_ipv6: bool) -> str | None:
    """Return the router named by ``SO_EE_OFFENDER``, if the message carries one.

    The control message is ``struct sock_extended_err`` followed immediately by
    the offending peer's ``sockaddr``. Verified against live routers: a hop
    limit of 1 toward a public address yields origin 2, type 11, and the first
    router's address.

    Args:
        control: One ancillary control-message payload.
        is_ipv6: Which family's Time Exceeded type number to expect.

    Returns:
        The router address, or ``None`` when this message is not a Time
        Exceeded from a router.

    """

    if len(control) < _EXTENDED_ERR.size:
        return None
    _errno, origin, ee_type, _code, _pad, _info, _data = _EXTENDED_ERR.unpack(control[: _EXTENDED_ERR.size])
    expected_origin = _ORIGIN_ICMP6 if is_ipv6 else _ORIGIN_ICMP
    expected_type = _TIME_EXCEEDED_V6 if is_ipv6 else _TIME_EXCEEDED_V4
    if origin != expected_origin or ee_type != expected_type:
        return None

    offender = control[_EXTENDED_ERR.size :]
    # sockaddr_in:  family(2) port(2) addr(4)
    # sockaddr_in6: family(2) port(2) flowinfo(4) addr(16)
    if is_ipv6:
        if len(offender) < 24:  # noqa: PLR2004 - sockaddr_in6 through the address field
            return None
        return socket.inet_ntop(socket.AF_INET6, offender[8:24])
    if len(offender) < 8:  # noqa: PLR2004 - sockaddr_in through the address field
        return None
    return socket.inet_ntop(socket.AF_INET, offender[4:8])


def _enable_error_queue(sock: socket.socket, *, is_ipv6: bool) -> tuple[RecvMsg, int] | None:
    """Turn on the error queue, returning how to read it, or None if unavailable.

    ``IP_RECVERR`` asks the kernel to keep ICMP errors - including Time
    Exceeded - on a queue the process can read, which is how unprivileged
    traceroute works on Linux. Neither the option nor ``recvmsg`` exists on
    macOS or Windows, so this returns ``None`` there and the caller reports
    the capability as absent rather than pretending to have it.

    Args:
        sock: The ICMP socket to configure.
        is_ipv6: Selects the IPv6 spelling of the option.

    Returns:
        A ``(recvmsg, MSG_ERRQUEUE)`` pair, or ``None`` where the platform has
        no error queue.

    """

    flag = socket_const("MSG_ERRQUEUE")
    option = socket_const("IPV6_RECVERR" if is_ipv6 else "IP_RECVERR")
    recvmsg = recvmsg_of(sock)
    if flag is None or option is None or recvmsg is None:
        return None
    level = socket.IPPROTO_IPV6 if is_ipv6 else socket.IPPROTO_IP
    try:
        sock.setsockopt(level, option, 1)
    except OSError:
        return None
    return recvmsg, flag


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

    def __init__(
        self,
        address: str,
        family: AddressFamily,
        *,
        payload_size: int = 56,
        socket_factory: SocketFactory | None = None,
    ) -> None:
        self._address = address
        self._family = family
        self._is_ipv6 = family is AddressFamily.IPV6
        # Resolved once: an unknown interface name is a setup problem, so it
        # must raise while the transport is being built, not per probe.
        self._destination = _destination_for(address, is_ipv6=self._is_ipv6)
        self._payload_size = payload_size
        self._socket = (socket_factory or open_socket)(family)
        self._errqueue = _enable_error_queue(self._socket, is_ipv6=self._is_ipv6)
        self._is_raw = _is_raw_socket(self._socket)

    @property
    def supports_ttl(self) -> bool:
        """Return True: POSIX sockets expose a per-probe hop limit."""

        return True

    @property
    def supports_ttl_discovery(self) -> bool:
        """Return whether expired hops can actually be *observed* here.

        Setting a hop limit and seeing what a router says about it are separate
        capabilities, and they come apart by socket type rather than by
        platform.

        Linux surfaces them on the error queue, on any socket. macOS surfaces
        them nowhere on an unprivileged datagram socket - measured on a macOS
        runner - but delivers them as ordinary ICMP Time Exceeded packets on a
        *raw* socket, which a privileged process gets. So this is asked of the
        socket in hand rather than of ``sys.platform``.
        """

        return self._errqueue is not None or self._is_raw

    def _read_ttl_expired(self) -> str | None:
        """Return the router that discarded the packet, if one reported doing so."""

        if self._errqueue is None:
            return self._read_ttl_expired_raw() if self._is_raw else None
        recvmsg, flag = self._errqueue
        try:
            _data, ancillary, _flags, _addr = recvmsg(4096, 4096, flag)
        except (TimeoutError, OSError):
            return None
        for _level, _ctype, control in ancillary:
            offender = _offender_address(control, is_ipv6=self._is_ipv6)
            if offender is not None:
                return offender
        return None

    def _read_ttl_expired_raw(self) -> str | None:
        """Return the router named by a Time Exceeded packet on a raw socket.

        Where there is no error queue, a raw socket still receives the ICMP
        Time Exceeded message itself, and its source address is the router
        that discarded the probe. This is the path macOS traceroute runs on
        when the process is privileged enough to hold a raw socket.
        """

        try:
            data, address = self._socket.recvfrom(4096)
        except (TimeoutError, OSError):
            return None
        if not packet.is_time_exceeded(data, is_ipv6=self._is_ipv6):
            return None
        # recvfrom's address element type is unknown to the checker, so the
        # tuple is cast rather than the value read out of it: indexing an
        # untyped tuple stays untyped however the target is annotated.
        if not isinstance(address, tuple) or not address:
            return None
        return cast("tuple[str, ...]", address)[0]

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
            self._socket.sendto(datagram, self._destination)
        except OSError:
            # An unreachable network refuses at send time; that is a result.
            return EchoResult()

        deadline = started + timeout
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return self._expired_or_silent(started, ttl)
            self._socket.settimeout(remaining)
            try:
                raw, peer = self._socket.recvfrom(65535)
            except (TimeoutError, OSError):
                # A hop limit that expired arrives as an error, not as data.
                return self._expired_or_silent(started, ttl)

            elapsed_ms = (time.perf_counter() - started) * 1000.0
            parsed = packet.parse_echo_reply(raw)
            if parsed is not None and _matches(parsed, sequence=sequence, token=token, is_ipv6=self._is_ipv6):
                return EchoResult(rtt_ms=elapsed_ms, source=str(peer[0]))

    def _expired_or_silent(self, started: float, ttl: int | None) -> EchoResult:
        """Return a TTL-expired hop when a router reported one, else silence."""

        if ttl is None:
            return EchoResult()
        router = self._read_ttl_expired()
        if router is None:
            return EchoResult()
        return EchoResult(rtt_ms=(time.perf_counter() - started) * 1000.0, source=router, ttl_expired=True)

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

    def __init__(
        self,
        address: str,
        family: AddressFamily,
        *,
        payload_size: int = 56,
        socket_factory: SocketFactory | None = None,
    ) -> None:
        self._address = address
        self._family = family
        self._is_ipv6 = family is AddressFamily.IPV6
        # Resolved once: an unknown interface name is a setup problem, so it
        # must raise while the transport is being built, not per probe.
        self._destination = _destination_for(address, is_ipv6=self._is_ipv6)
        self._payload_size = payload_size
        self._socket = (socket_factory or open_socket)(family)
        # settimeout(0) is setblocking(False) without a boolean positional arg.
        self._socket.settimeout(0)
        self._waiters: dict[bytes, asyncio.Future[tuple[float, str]]] = {}
        self._reader_installed = False
        self._errqueue = _enable_error_queue(self._socket, is_ipv6=self._is_ipv6)
        self._is_raw = _is_raw_socket(self._socket)

    @property
    def supports_ttl(self) -> bool:
        """Return True: POSIX sockets expose a per-probe hop limit."""

        return True

    @property
    def supports_ttl_discovery(self) -> bool:
        """Return whether expired hops can actually be observed here."""

        return self._errqueue is not None or self._is_raw

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
                self._socket.sendto(datagram, self._destination)
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
