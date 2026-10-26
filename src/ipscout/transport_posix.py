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
from typing import TYPE_CHECKING, NamedTuple, Protocol, cast

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


class _IcmpFamily(NamedTuple):
    """The ICMP and IP-layer facts that differ between IPv4 and IPv6.

    Kept as one row per family so that a family's protocol, option names and
    message numbers cannot drift apart across separate if/else expressions.

    Attributes:
        protocol: The ICMP protocol number the socket is opened with.
        recverr_option: The *name* of the error-queue option. It stays a name
            because it is resolved through :func:`socket_const`: CPython only
            began exposing it in 3.14, so a direct attribute would be absent on
            every older Python.
        origin: ``SO_EE_ORIGIN_ICMP`` / ``SO_EE_ORIGIN_ICMP6``, marking an
            error-queue entry that came from a router rather than from the
            local stack.
        time_exceeded: The ICMP "Time Exceeded" type. A router sends it when
            it discards a packet whose hop limit ran out, which is the entire
            basis of traceroute.
        hop_option: The ``setsockopt`` option that sets the outgoing hop limit.
        offender_address: Where the address sits inside the offender
            ``sockaddr`` that follows ``struct sock_extended_err``:
            ``sockaddr_in`` is family(2) port(2) addr(4), ``sockaddr_in6`` is
            family(2) port(2) flowinfo(4) addr(16).

    """

    protocol: int
    recverr_option: str
    origin: int
    time_exceeded: int
    hop_option: int
    offender_address: slice


_ICMP_FAMILY: dict[AddressFamily, _IcmpFamily] = {
    AddressFamily.IPV4: _IcmpFamily(
        protocol=socket.IPPROTO_ICMP,
        recverr_option="IP_RECVERR",
        origin=2,
        time_exceeded=packet.TIME_EXCEEDED_V4,
        hop_option=socket.IP_TTL,
        offender_address=slice(4, 8),
    ),
    AddressFamily.IPV6: _IcmpFamily(
        protocol=socket.IPPROTO_ICMPV6,
        recverr_option="IPV6_RECVERR",
        origin=3,
        time_exceeded=packet.TIME_EXCEEDED_V6,
        hop_option=socket.IPV6_UNICAST_HOPS,
        offender_address=slice(8, 24),
    ),
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

    sock_family, proto = family.socket_family, _ICMP_FAMILY[family].protocol
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

#: Bytes offered for the ancillary data of one error-queue read. The control
#: message wanted is a cmsg header, ``sock_extended_err`` and the offender's
#: sockaddr - under a hundred bytes - but the kernel truncates (``MSG_CTRUNC``)
#: rather than fails when the space is short, which would silently cut off the
#: offender address, so the buffer is sized for several control messages, not
#: for that one exactly.
_ANCILLARY_SIZE = 4096


class _Arrival(NamedTuple):
    """What ends a probe's wait with an answer: a reply, or a router's report.

    Attributes:
        finished: ``time.perf_counter()`` reading taken when the answer was read.
        source: The address that answered: the target, or the router that
            discarded the probe.
        ttl_expired: True when a router reported Time Exceeded.

    """

    finished: float
    source: str
    ttl_expired: bool = False


class _Waiter(NamedTuple):
    """One outstanding async probe: what identifies it, and where its answer goes.

    Attributes:
        sequence: The probe's sequence number.
        token: The probe's payload token.
        answer: Resolved with the answer, or with ``None`` when an error says
            no answer will come.

    """

    sequence: int
    token: bytes
    answer: asyncio.Future[_Arrival | None]


class _IcmpError(NamedTuple):
    """An ICMP error about one of our probes, and what it means for that probe.

    Attributes:
        probe: The echo request the error quotes; it is all that says which
            probe the error is about.
        arrival: The router's answer for a Time Exceeded. ``None`` for any
            other error (unreachable, refused): the probe will get no answer,
            so its wait ends without one.

    """

    probe: packet.ParsedReply
    arrival: _Arrival | None


def _destination_for(address: str, *, family: AddressFamily) -> tuple[str, int] | tuple[str, int, int, int]:
    """Return the sockaddr to send to, carrying the interface when scoped.

    An ICMPv6 socket refuses a zone written into the address string: measured
    on Linux, ``sendto(datagram, ("fe80::1%eth0", 0))`` fails with EINVAL, and
    so does the bare form, while the same address with the interface index in
    the sockaddr's scope-id field is answered. So the zone travels as a number
    here rather than as text, even though ``getaddrinfo`` accepts either.
    """

    if family is not AddressFamily.IPV6:
        return (address, 0)
    bare, zone = split_zone(address)
    if zone is None:
        return (bare, 0)
    return (bare, 0, 0, zone_index(zone))


def _offender_address(control: bytes, *, family: AddressFamily) -> str | None:
    """Return the router named by ``SO_EE_OFFENDER``, if the message carries one.

    The control message is ``struct sock_extended_err`` followed immediately by
    the offending peer's ``sockaddr``. Verified against live routers: a hop
    limit of 1 toward a public address yields origin 2, type 11, and the first
    router's address.

    Args:
        control: One ancillary control-message payload.
        family: Which family's Time Exceeded type number to expect.

    Returns:
        The router address, or ``None`` when this message is not a Time
        Exceeded from a router.

    """

    if len(control) < _EXTENDED_ERR.size:
        return None
    _errno, origin, ee_type, _code, _pad, _info, _data = _EXTENDED_ERR.unpack(control[: _EXTENDED_ERR.size])
    facts = _ICMP_FAMILY[family]
    if origin != facts.origin or ee_type != facts.time_exceeded:
        return None

    offender = control[_EXTENDED_ERR.size :]
    if len(offender) < facts.offender_address.stop:
        return None
    return socket.inet_ntop(family.socket_family, offender[facts.offender_address])


class ErrorQueueReader(NamedTuple):
    """What reading a socket's error queue takes: the call, and the flag to pass it.

    The two only make sense together - ``recvmsg`` without ``MSG_ERRQUEUE``
    reads ordinary datagrams, not the queued ICMP errors - so they travel as
    one record, and one ``None`` says the platform has no error queue at all.

    Attributes:
        recvmsg: The socket's bound ``recvmsg``.
        flag: The platform's ``MSG_ERRQUEUE`` value, passed as ``recvmsg``'s
            flags argument to read the queue rather than the socket.

    """

    recvmsg: RecvMsg
    flag: int


def _enable_error_queue(sock: socket.socket, *, family: AddressFamily) -> ErrorQueueReader | None:
    """Turn on the error queue, returning how to read it, or None if unavailable.

    ``IP_RECVERR`` asks the kernel to keep ICMP errors - including Time
    Exceeded - on a queue the process can read, which is how unprivileged
    traceroute works on Linux. Neither the option nor ``recvmsg`` exists on
    macOS or Windows, so this returns ``None`` there and the caller reports
    the capability as absent rather than pretending to have it.

    Args:
        sock: The ICMP socket to configure.
        family: ``AddressFamily.IPV6`` selects the IPv6 spelling of the option.

    Returns:
        An :class:`ErrorQueueReader`, or ``None`` where the platform has no
        error queue.

    """

    flag = socket_const("MSG_ERRQUEUE")
    option = socket_const(_ICMP_FAMILY[family].recverr_option)
    recvmsg = recvmsg_of(sock)
    if flag is None or option is None or recvmsg is None:
        return None
    try:
        sock.setsockopt(family.ip_option_level, option, 1)
    except OSError:
        return None
    return ErrorQueueReader(recvmsg, flag)


def _apply_ttl(sock: socket.socket, ttl: int | None, *, family: AddressFamily) -> None:
    """Set the outgoing hop limit for subsequent packets; ``None`` leaves the default."""

    if ttl is None:
        return
    sock.setsockopt(family.ip_option_level, _ICMP_FAMILY[family].hop_option, ttl)


def _matches(parsed: packet.ParsedReply, *, sequence: int, token: bytes, family: AddressFamily) -> bool:
    """Return whether a decoded datagram answers this specific probe.

    Deliberately ignores ``parsed.identifier``: the kernel rewrites that field
    on an unprivileged socket, so comparing it would reject every real reply.
    """

    return packet.is_echo_reply(parsed, family=family) and parsed.sequence == sequence and parsed.token == token


def _quotes(error: _IcmpError, *, sequence: int, token: bytes) -> bool:
    """Return whether an error quotes this probe.

    The token counts only where the quote reaches it: a Linux ping socket's
    error queue hands back just the eight header bytes, and RFC 792 routers
    quote no more, so there the sequence is all there is.
    """

    return error.probe.sequence == sequence and error.probe.token in (None, token)


def _quoting(errors: list[_IcmpError], *, sequence: int, token: bytes) -> _IcmpError | None:
    """Return the first of ``errors`` that quotes this probe, or None."""

    return next((error for error in errors if _quotes(error, sequence=sequence, token=token)), None)


def _queued_error(data: bytes, ancillary: list[tuple[int, int, bytes]], *, family: AddressFamily) -> _IcmpError | None:
    """Return the error one error-queue entry reports, or None if it quotes no echo request."""

    probe = packet.parse_echo_request(data, family=family)
    if probe is None:
        return None
    for _level, _ctype, control in ancillary:
        router = _offender_address(control, family=family)
        if router is not None:
            return _IcmpError(probe, _Arrival(finished=time.perf_counter(), source=router, ttl_expired=True))
    return _IcmpError(probe, None)


def _drain_errors(reader: ErrorQueueReader | None, *, family: AddressFamily) -> list[_IcmpError]:
    """Read every entry on the error queue, oldest first, and return the errors they report.

    Reading the queue is what clears the socket's pending error. While one
    entry sits unread the kernel keeps the socket readable (``POLLERR``) and
    refuses the next send with that entry's errno, so an entry nobody reads
    turns an event loop into a busy loop and the next probe into a loss that
    was never sent. The socket must not block: the queue is read until empty.

    Args:
        reader: The socket's error-queue reader, or ``None`` where there is no
            error queue.
        family: Which family's message numbers apply.

    Returns:
        The errors that quote one of this family's echo requests.

    """

    errors: list[_IcmpError] = []
    if reader is None:
        return errors
    while True:
        try:
            data, ancillary, _flags, _addr = reader.recvmsg(packet.MAX_IP_LENGTH, _ANCILLARY_SIZE, reader.flag)
        except OSError:
            # EAGAIN: the queue is empty.
            return errors
        error = _queued_error(data, ancillary, family=family)
        if error is not None:
            errors.append(error)


def _time_exceeded_datagram(raw: bytes, peer: object, *, family: AddressFamily) -> _IcmpError | None:
    """Return the Time Exceeded a received datagram carries, or None.

    A raw socket receives the router's message as data; its source is the
    router that discarded the probe.
    """

    probe = packet.quoted_echo_request(raw, family=family)
    # recvfrom's address element type is unknown to the checker, so the
    # tuple is cast rather than the value read out of it: indexing an
    # untyped tuple stays untyped however the target is annotated.
    if probe is None or not isinstance(peer, tuple) or not peer:
        return None
    router = str(cast("tuple[object, ...]", peer)[0])
    return _IcmpError(probe, _Arrival(finished=time.perf_counter(), source=router, ttl_expired=True))


def _result(arrival: _Arrival | None, *, started: float, ttl: int | None) -> EchoResult:
    """Turn what ended a probe's wait into its result.

    A Time Exceeded for a probe sent without a hop limit (a routing loop) is
    no answer: there was no hop to report.
    """

    if arrival is None or (arrival.ttl_expired and ttl is None):
        return EchoResult()
    return EchoResult(rtt_ms=(arrival.finished - started) * 1000.0, source=arrival.source, ttl_expired=arrival.ttl_expired)


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
        payload_size: int = packet.DEFAULT_PAYLOAD_SIZE,
        socket_factory: SocketFactory | None = None,
    ) -> None:
        self._family = family
        # Resolved once: an unknown interface name is a setup problem, so it
        # must raise while the transport is being built, not per probe.
        self._destination = _destination_for(address, family=family)
        self._payload_size = payload_size
        self._socket = (socket_factory or open_socket)(family)
        self._errqueue = _enable_error_queue(self._socket, family=family)
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

    def _take_errors(self) -> list[_IcmpError]:
        """Drain the error queue without blocking."""

        self._socket.settimeout(0)
        return _drain_errors(self._errqueue, family=self._family)

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
            turn a healthy target into a phantom timeout. An ICMP error is
            treated the same way: it ends the wait only when it quotes this
            probe.

        """

        _apply_ttl(self._socket, ttl, family=self._family)
        datagram, token = packet.build_echo_request(
            sequence=sequence,
            payload_size=self._payload_size,
            family=self._family,
        )
        # Errors still queued are about earlier probes, answered or given up
        # on; one left unread would refuse this send with its errno.
        self._take_errors()

        started = time.perf_counter()
        try:
            self._socket.sendto(datagram, self._destination)
        except OSError:
            # An unreachable network refuses at send time; that is a result.
            return EchoResult()
        arrival = self._await(sequence=sequence, token=token, deadline=started + timeout)
        return _result(arrival, started=started, ttl=ttl)

    def _await(self, *, sequence: int, token: bytes, deadline: float) -> _Arrival | None:
        """Wait until ``deadline`` for this probe's answer; None is no answer."""

        while (remaining := deadline - time.perf_counter()) > 0:
            self._socket.settimeout(remaining)
            try:
                raw, peer = self._socket.recvfrom(packet.MAX_IP_LENGTH)
            except TimeoutError:
                return None
            except OSError:
                # A queued error, raised here as its errno; the queue says
                # which probe it is about. An error with no entry behind it
                # cannot be about another probe, so it ends this wait.
                errors = self._take_errors()
                mine = _quoting(errors, sequence=sequence, token=token)
                if mine is not None or not errors:
                    return None if mine is None else mine.arrival
                continue
            arrival = self._answer_in(raw, peer, sequence=sequence, token=token)
            if arrival is not None:
                return arrival
        return None

    def _answer_in(self, raw: bytes, peer: object, *, sequence: int, token: bytes) -> _Arrival | None:
        """Return the answer a received datagram gives this probe, or None if it is not one."""

        parsed = packet.parse_echo_reply(raw)
        if parsed is not None and _matches(parsed, sequence=sequence, token=token, family=self._family):
            return _Arrival(finished=time.perf_counter(), source=str(cast("tuple[object, ...]", peer)[0]))
        error = _time_exceeded_datagram(raw, peer, family=self._family)
        return error.arrival if error is not None and _quotes(error, sequence=sequence, token=token) else None

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
        payload_size: int = packet.DEFAULT_PAYLOAD_SIZE,
        socket_factory: SocketFactory | None = None,
    ) -> None:
        self._family = family
        # Resolved once: an unknown interface name is a setup problem, so it
        # must raise while the transport is being built, not per probe.
        self._destination = _destination_for(address, family=family)
        self._payload_size = payload_size
        self._socket = (socket_factory or open_socket)(family)
        # settimeout(0) is setblocking(False) without a boolean positional arg.
        self._socket.settimeout(0)
        self._waiters: dict[bytes, _Waiter] = {}
        self._reader_installed = False
        self._errqueue = _enable_error_queue(self._socket, family=family)
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
        """Drain the error queue and the socket, handing each answer to its probe."""

        self._settle_errors()
        while True:
            try:
                raw, peer = self._socket.recvfrom(packet.MAX_IP_LENGTH)
            except OSError:
                # EAGAIN once the socket is empty, or the errno of an error
                # queued since the drain above. Readiness is level-triggered,
                # so the loop calls back at once and that call reads it.
                return
            self._settle_datagram(raw, peer)

    def _settle_errors(self) -> None:
        """Hand every queued error to the probe it quotes."""

        for error in _drain_errors(self._errqueue, family=self._family):
            self._settle(error)

    def _settle_datagram(self, raw: bytes, peer: object) -> None:
        """Hand a received datagram to the probe it answers, if any."""

        parsed = packet.parse_echo_reply(raw)
        if parsed is not None and packet.is_echo_reply(parsed, family=self._family) and parsed.token is not None:
            waiter = self._waiters.get(parsed.token)
            # A token with no waiter is a late reply to a probe that already
            # timed out, or another process's traffic. Both are simply dropped.
            if waiter is not None and not waiter.answer.done():
                waiter.answer.set_result(_Arrival(finished=time.perf_counter(), source=str(cast("tuple[object, ...]", peer)[0])))
            return
        error = _time_exceeded_datagram(raw, peer, family=self._family)
        if error is not None:
            self._settle(error)

    def _settle(self, error: _IcmpError) -> None:
        """Resolve the one outstanding probe an error quotes.

        A quote without the token names a probe by sequence alone; if two
        outstanding probes share that sequence the error cannot say which,
        and it is dropped rather than credited to either.
        """

        named = [waiter for waiter in self._waiters.values() if _quotes(error, sequence=waiter.sequence, token=waiter.token)]
        if len(named) == 1 and not named[0].answer.done():
            named[0].answer.set_result(error.arrival)

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
        _apply_ttl(self._socket, ttl, family=self._family)
        datagram, token = packet.build_echo_request(
            sequence=sequence,
            payload_size=self._payload_size,
            family=self._family,
        )
        # Errors still queued are about earlier probes; one the reader has not
        # reached yet would refuse this send with its errno.
        self._settle_errors()

        waiter = _Waiter(sequence, token, asyncio.get_running_loop().create_future())
        self._waiters[token] = waiter
        started = time.perf_counter()
        try:
            try:
                self._socket.sendto(datagram, self._destination)
            except OSError:
                return EchoResult()

            try:
                arrival = await asyncio.wait_for(waiter.answer, timeout)
            except (TimeoutError, asyncio.TimeoutError):
                return EchoResult()
            return _result(arrival, started=started, ttl=ttl)
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
