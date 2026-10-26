"""ICMP errors reach the probe they name, and only that probe.

A router that discards a probe answers with an ICMP error quoting it. On Linux
the kernel files that error on the socket's error queue; on a raw socket it
also arrives as an ordinary datagram. Either way the quote is the only thing
that says which probe the error is about, and an error nobody reads does
damage: while one sits queued the kernel keeps the socket readable and refuses
the next send with its errno.

The errors here are real. A UDP socket with ``IP_RECVERR`` sending to a closed
loopback port gets a genuine kernel-queued ICMP port unreachable that quotes
the bytes sent, which is the same mechanism a ping socket uses for Time
Exceeded. Where a test needs a router's Time Exceeded instead, the socket seam
rewrites that one entry's type byte and nothing else; the raw-socket form is a
crafted Time Exceeded datagram sent back by a real UDP peer.
"""

from __future__ import annotations

import asyncio
import errno
import select
import socket
import sys
import threading
import time
from typing import TYPE_CHECKING, cast

import pytest

from ipscout import packet
from ipscout.models import AddressFamily
from ipscout.transport_posix import AsyncPosixEchoTransport, PosixEchoTransport, socket_const

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from _typeshed import ReadableBuffer

    from ipscout.ports import EchoResult

pytestmark = [
    pytest.mark.os_posix,
    pytest.mark.skipif(
        sys.platform == "win32",
        reason="PosixEchoTransport is POSIX-only, and loop.add_reader is unsupported on the Windows Proactor loop",
    ),
]

#: Only Linux has an error queue, so only there can the kernel produce the
#: queued error these tests are about.
linux_error_queue = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the ICMP error queue is Linux-only")

_LOOPBACK = "127.0.0.1"

#: Where the origin and the ICMP type sit in ``struct sock_extended_err``:
#: after the 4-byte errno, one byte each.
_EE_ORIGIN_OFFSET = 4
_EE_TYPE_OFFSET = 5

#: ``SO_EE_ORIGIN_LOCAL``: the local stack refused the send.
_ORIGIN_LOCAL = 1

#: How long a test waits for the kernel to queue an error that loopback
#: delivers in microseconds.
_ERROR_ARRIVAL_WAIT = 1.0

#: ``socket.socket.recvmsg``, which the Windows type stubs do not declare.
#: Typed once here so the override below stays typed on every platform; the
#: tests that reach it run only where it exists.
_BASE_RECVMSG = cast("Callable[..., tuple[bytes, list[tuple[int, int, bytes]], int, object]]", getattr(socket.socket, "recvmsg", None))


def _closed_port() -> int:
    """Return a loopback UDP port nothing listens on, so a send to it is refused."""

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind((_LOOPBACK, 0))
        return int(probe.getsockname()[1])


class _Wiring:
    """Real UDP sockets for a transport, sending to one fixed loopback port.

    Attributes:
        created: Every socket handed to a transport, so a test can send a stray
            datagram on the transport's own socket.

    """

    def __init__(self, port: int, *, error_type: int | None = None, error_origin: int | None = None, as_raw: bool = False) -> None:
        self.created: list[socket.socket] = []
        self._port = port
        self._rewrite = {_EE_TYPE_OFFSET: error_type, _EE_ORIGIN_OFFSET: error_origin}
        self._as_raw = as_raw

    def factory(self) -> Callable[[AddressFamily], socket.socket]:
        port, as_raw = self._port, self._as_raw
        rewrite = {offset: value for offset, value in self._rewrite.items() if value is not None}
        errqueue = socket_const("MSG_ERRQUEUE") or 0

        class _RoutedSocket(socket.socket):
            """A real UDP socket: sends reach the fixed port; queued errors may read as a router's."""

            @property
            def type(self) -> socket.SocketKind:
                # A raw socket keeps the identifier a probe was sent with, so
                # the transport compares it; UDP keeps it too, which is what
                # lets a UDP socket stand in for one here.
                return socket.SOCK_RAW if as_raw else super().type

            def sendto(self, data: ReadableBuffer, /, *args: object) -> int:
                del args
                return super().sendto(data, (_LOOPBACK, port))

            def recvmsg(self, bufsize: int, ancbufsize: int = 0, flags: int = 0, /) -> tuple[bytes, list[tuple[int, int, bytes]], int, object]:
                data, ancillary, msg_flags, address = _BASE_RECVMSG(self, bufsize, ancbufsize, flags)
                if rewrite and flags & errqueue:
                    ancillary = [(level, kind, _rewritten(control, rewrite)) for level, kind, control in ancillary]
                return data, ancillary, msg_flags, address

        def make(family: AddressFamily) -> socket.socket:
            del family
            sock = _RoutedSocket(socket.AF_INET, socket.SOCK_DGRAM)
            self.created.append(sock)
            return sock

        return make

    def send_stray(self, *, sequence: int, to: tuple[str, int], header_only: bool = False) -> None:
        """Send an echo request the transport never asked for, and wait until its error is queued."""

        sock = self.created[-1]
        socket.socket.sendto(sock, _stray(sequence, header_only=header_only), to)
        # A queued error makes the socket readable, before any datagram does.
        readable, _writable, _failed = select.select([sock], [], [], _ERROR_ARRIVAL_WAIT)
        assert readable, "the kernel queued no error for the stray send"

    def send_stray_during(self, *, sequence: int, to: tuple[str, int], after: float, header_only: bool = False) -> threading.Timer:
        """Send a stray echo request ``after`` seconds from now, while a probe is waiting."""

        sock = self.created[-1]
        timer = threading.Timer(after, socket.socket.sendto, args=(sock, _stray(sequence, header_only=header_only), to))
        timer.start()
        return timer


def _stray(sequence: int, *, header_only: bool) -> bytes:
    """Return an echo request nobody waits for; header-only, its error quotes no token."""

    datagram, _token = packet.build_echo_request(sequence=sequence)
    return datagram[: packet.HEADER_SIZE] if header_only else datagram


def _closed(host: str = _LOOPBACK) -> tuple[str, int]:
    return (host, _closed_port())


def _rewritten(control: bytes, rewrite: dict[int, int]) -> bytes:
    """Return a queued error's control message with the given ``sock_extended_err`` bytes replaced."""

    changed = bytearray(control)
    for offset, value in rewrite.items():
        changed[offset] = value
    return bytes(changed)


class _Peer:
    """A real UDP peer that answers echoes, late or at once, stays silent, or acts as a router.

    As a router it sends back a Time Exceeded datagram the way a raw socket
    receives one: an IPv4 header, the ICMP header, then the quoted IPv4 header
    (protocol ICMP, destination loopback) and the first eight bytes of the
    request.
    """

    def __init__(
        self,
        *,
        answer: bool = True,
        answer_after: float = 0.0,
        as_router: bool = False,
        quote_sequence_shift: int = 0,
        quote_identifier_shift: int = 0,
    ) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((_LOOPBACK, 0))
        self.port = int(self.socket.getsockname()[1])
        self._answer, self._answer_after, self._as_router = answer, answer_after, as_router
        self._shifts = (quote_identifier_shift, quote_sequence_shift)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self.socket.settimeout(0.2)
        while not self._stop.is_set():
            try:
                raw, peer = self.socket.recvfrom(65535)
            except (TimeoutError, OSError):
                continue
            if self._as_router:
                self.socket.sendto(self._time_exceeded(raw), peer)
            elif self._answer:
                self._stop.wait(self._answer_after)
                self.socket.sendto(bytes([packet.ECHO_REPLY_V4]) + raw[1:], peer)

    def _time_exceeded(self, request: bytes) -> bytes:
        quoted = bytearray(request[: packet.HEADER_SIZE])
        for offset, shift in zip((4, 6), self._shifts, strict=True):
            quoted[offset : offset + 2] = ((int.from_bytes(quoted[offset : offset + 2], "big") + shift) & 0xFFFF).to_bytes(2, "big")
        outer = b"\x45" + bytes(packet.IPV4_MIN_HEADER_SIZE - 1)
        inner = b"\x45" + bytes(8) + b"\x01" + bytes(6) + socket.inet_aton(_LOOPBACK)
        return outer + bytes([packet.TIME_EXCEEDED_V4]) + bytes(packet.HEADER_SIZE - 1) + inner + bytes(quoted)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.socket.close()


@pytest.fixture
def answering() -> Iterator[_Peer]:
    peer = _Peer()
    try:
        yield peer
    finally:
        peer.close()


@pytest.fixture
def silent() -> Iterator[_Peer]:
    peer = _Peer(answer=False)
    try:
        yield peer
    finally:
        peer.close()


def _async_probe(make: Callable[[AddressFamily], socket.socket], *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:
    async def attempt() -> EchoResult:
        async with AsyncPosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=make) as transport:
            return await transport.probe(sequence=sequence, timeout=timeout, ttl=ttl)

    return asyncio.run(attempt())


def _probe_while_a_stray_errs(wiring: _Wiring, *, probe: str, to: tuple[str, int], ttl: int | None) -> EchoResult:
    """Probe sequence 2 while a header-only stray with the same sequence errs at ``to``.

    Header-only, the stray's error quotes no token, as an error from a router
    that quotes eight bytes does: the sequence and the destination are all it
    carries. The stray is sent 0.05 s into a 1 s wait.
    """

    if probe == "sync":
        with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
            stray = wiring.send_stray_during(sequence=2, to=to, after=0.05, header_only=True)
            result = transport.probe(sequence=2, timeout=1.0, ttl=ttl)
            stray.join()
        return result

    async def attempt() -> EchoResult:
        async with AsyncPosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
            stray = wiring.send_stray_during(sequence=2, to=to, after=0.05, header_only=True)
            result = await transport.probe(sequence=2, timeout=1.0, ttl=ttl)
            stray.join()
            return result

    return asyncio.run(attempt())


# --- a Time Exceeded on the error queue -------------------------------------------------


@linux_error_queue
def test_a_queued_time_exceeded_is_reported_as_the_hop_by_the_sync_transport() -> None:
    wiring = _Wiring(_closed_port(), error_type=packet.TIME_EXCEEDED_V4)

    with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
        result = transport.probe(sequence=1, timeout=2.0, ttl=1)

    assert (result.ttl_expired, result.source) == (True, _LOOPBACK)


@linux_error_queue
def test_a_queued_time_exceeded_is_reported_as_the_hop_by_the_async_transport() -> None:
    # Before, the async transport never read the error queue: every hop of an
    # async traceroute read as silent while the sync walk found the routers.
    wiring = _Wiring(_closed_port(), error_type=packet.TIME_EXCEEDED_V4)

    result = _async_probe(wiring.factory(), sequence=1, timeout=2.0, ttl=1)

    assert (result.ttl_expired, result.source) == (True, _LOOPBACK)


@linux_error_queue
@pytest.mark.parametrize("ttl", [None, 3], ids=["ping", "hop"])
def test_an_error_saying_the_probe_was_not_delivered_ends_the_wait(ttl: int | None) -> None:
    # A port unreachable quoting the probe: no answer will come, so the wait
    # ends at once rather than at the deadline, with or without a hop limit.
    wiring = _Wiring(_closed_port())

    with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
        started = time.perf_counter()
        result = transport.probe(sequence=1, timeout=2.0, ttl=ttl)
        elapsed = time.perf_counter() - started

    assert (result.answered, result.ttl_expired) == (False, False)
    assert elapsed < 1.0, "an error saying the probe was not delivered ends the wait"


@linux_error_queue
@pytest.mark.parametrize("error_type", [5, 4], ids=["redirect", "source-quench"])
@pytest.mark.parametrize("probe", ["sync", "async"])
def test_an_error_that_is_no_failure_to_deliver_leaves_the_wait_running(error_type: int, probe: str) -> None:
    # A router that redirects still forwards the packet, and the reply comes
    # after its redirect. Before, any queued error ended the wait, so the
    # reply arrived to nobody.
    late = _Peer(answer_after=0.3)
    wiring = _Wiring(late.port, error_type=error_type)
    try:
        result = _probe_while_a_stray_errs(wiring, probe=probe, to=_closed(), ttl=None)
    finally:
        late.close()

    assert (result.answered, result.ttl_expired) == (True, False)


@linux_error_queue
def test_a_local_error_about_the_probe_ends_the_wait() -> None:
    # The local stack refused the probe (a datagram too large to leave, for
    # one), whatever ICMP type byte the entry carries.
    late = _Peer(answer_after=0.6)
    wiring = _Wiring(late.port, error_origin=_ORIGIN_LOCAL, error_type=0)
    try:
        started = time.perf_counter()
        result = _probe_while_a_stray_errs(wiring, probe="sync", to=_closed(), ttl=None)
        elapsed = time.perf_counter() - started
    finally:
        late.close()

    assert not result.answered
    assert elapsed < 0.5, "a local error about the probe ends the wait"


@linux_error_queue
def test_a_time_exceeded_is_no_answer_to_a_probe_sent_without_a_hop_limit() -> None:
    # Without a hop limit an expired hop is another probe's or a loop's.
    # Before, it ended a ping's wait, so a host answering a moment later read
    # as lost.
    late = _Peer(answer_after=0.3)
    wiring = _Wiring(late.port, error_type=packet.TIME_EXCEEDED_V4)
    try:
        result = _probe_while_a_stray_errs(wiring, probe="async", to=_closed(), ttl=None)
    finally:
        late.close()

    # The host's reply, not the router's report: answered alone counts both.
    assert (result.answered, result.ttl_expired) == (True, False)


@linux_error_queue
@pytest.mark.parametrize("probe", ["sync", "async"])
def test_an_error_about_a_probe_to_another_destination_is_not_this_probe(silent: _Peer, probe: str) -> None:
    # A raw socket sees every ICMP error on the host, so another socket's probe
    # with the same sequence and a quote too short for the token must still
    # not be credited: its destination differs.
    wiring = _Wiring(silent.port, error_type=packet.TIME_EXCEEDED_V4)

    result = _probe_while_a_stray_errs(wiring, probe=probe, to=_closed("127.0.0.2"), ttl=2)

    assert (result.ttl_expired, result.source) == (False, None)


@linux_error_queue
def test_the_same_quote_to_the_probe_s_own_destination_is_its_hop(silent: _Peer) -> None:
    # The control for the test above: only the destination differs.
    wiring = _Wiring(silent.port, error_type=packet.TIME_EXCEEDED_V4)

    result = _probe_while_a_stray_errs(wiring, probe="sync", to=_closed(), ttl=2)

    assert (result.ttl_expired, result.source) == (True, _LOOPBACK)


# --- an error about an EARLIER probe ------------------------------------------------------


@linux_error_queue
def test_a_late_error_about_an_earlier_probe_does_not_refuse_the_next_send(answering: _Peer) -> None:
    # The kernel refuses a send with the errno of any queued error. Before,
    # that refusal read as a lost probe that was never sent.
    wiring = _Wiring(answering.port)

    with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
        wiring.send_stray(sequence=99, to=_closed())
        result = transport.probe(sequence=2, timeout=2.0)

    assert result.answered


@linux_error_queue
def test_a_late_time_exceeded_is_not_pinned_on_a_later_silent_hop(silent: _Peer) -> None:
    # Before, an entry left on the queue was read as the answer of whichever
    # later probe next timed out: that hop showed an earlier hop's router.
    wiring = _Wiring(silent.port, error_type=packet.TIME_EXCEEDED_V4)

    with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
        wiring.send_stray(sequence=99, to=_closed())
        first = transport.probe(sequence=2, timeout=0.3, ttl=2)
        second = transport.probe(sequence=3, timeout=0.3, ttl=3)

    assert (first.ttl_expired, first.source) == (False, None)
    assert (second.ttl_expired, second.source) == (False, None)


@linux_error_queue
def test_an_error_quoting_the_same_sequence_with_another_token_is_not_this_probe(silent: _Peer) -> None:
    wiring = _Wiring(silent.port, error_type=packet.TIME_EXCEEDED_V4)

    with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
        stray = wiring.send_stray_during(sequence=2, to=_closed(), after=0.05)
        started = time.perf_counter()
        result = transport.probe(sequence=2, timeout=1.0, ttl=2)
        elapsed = time.perf_counter() - started
        stray.join()

    assert (result.ttl_expired, result.source) == (False, None)
    # The wait ran to its deadline, so it was still running when the stray's
    # error arrived and read it as another probe's.
    assert elapsed >= 0.9


@linux_error_queue
def test_the_async_transport_sends_past_a_late_error_about_an_earlier_probe(answering: _Peer) -> None:
    wiring = _Wiring(answering.port)

    async def attempt() -> EchoResult:
        async with AsyncPosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
            wiring.send_stray(sequence=99, to=_closed())
            return await transport.probe(sequence=2, timeout=2.0)

    assert asyncio.run(attempt()).answered


@linux_error_queue
def test_an_unread_error_does_not_spin_the_event_loop(silent: _Peer) -> None:
    # A queued error keeps the socket readable until it is read, so a reader
    # that never reads the queue is called again at once, for the whole wait.
    wait = 0.6
    wiring = _Wiring(silent.port)

    async def attempt() -> EchoResult:
        async with AsyncPosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
            probe = asyncio.create_task(transport.probe(sequence=2, timeout=wait))
            await asyncio.sleep(0.05)
            wiring.send_stray(sequence=99, to=_closed())
            return await probe

    started = time.process_time()
    result = asyncio.run(attempt())
    cpu = time.process_time() - started

    assert not result.answered
    assert cpu < wait / 3, f"the wait burned {cpu:.2f}s of CPU in {wait}s"


# --- a Time Exceeded datagram, as a raw socket receives it ---------------------------------


def test_a_time_exceeded_datagram_quoting_the_probe_is_its_hop_on_the_sync_transport() -> None:
    # A raw socket receives the router's message as data. Before, the receive
    # loop discarded it as a stranger and the hop read as silent.
    router = _Peer(as_router=True)
    wiring = _Wiring(router.port)
    try:
        with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
            result = transport.probe(sequence=4, timeout=2.0, ttl=1)
    finally:
        router.close()

    assert (result.ttl_expired, result.source) == (True, _LOOPBACK)


def test_a_time_exceeded_datagram_quoting_the_probe_is_its_hop_on_the_async_transport() -> None:
    router = _Peer(as_router=True)
    wiring = _Wiring(router.port)
    try:
        result = _async_probe(wiring.factory(), sequence=4, timeout=2.0, ttl=1)
    finally:
        router.close()

    assert (result.ttl_expired, result.source) == (True, _LOOPBACK)


@pytest.mark.parametrize("probe", ["sync", "async"])
def test_a_time_exceeded_datagram_quoting_another_probe_is_not_this_hop(probe: str) -> None:
    # A raw socket sees every ICMP message for the host, another process's
    # traceroute included; the quoted sequence is what says whose it is.
    router = _Peer(as_router=True, quote_sequence_shift=1)
    wiring = _Wiring(router.port)
    try:
        if probe == "sync":
            with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
                result = transport.probe(sequence=4, timeout=0.4, ttl=1)
        else:
            result = _async_probe(wiring.factory(), sequence=4, timeout=0.4, ttl=1)
    finally:
        router.close()

    assert (result.ttl_expired, result.source) == (False, None)


def test_a_quote_without_a_token_naming_two_outstanding_probes_is_credited_to_neither() -> None:
    # The router quotes only the header, so the sequence is all that names a
    # probe; two probes sharing it cannot be told apart, and crediting either
    # could put one hop's router on the other hop.
    router = _Peer(as_router=True)
    wiring = _Wiring(router.port)

    async def attempt() -> list[EchoResult]:
        async with AsyncPosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
            return list(await asyncio.gather(*(transport.probe(sequence=4, timeout=0.4, ttl=ttl) for ttl in (1, 2))))

    try:
        results = asyncio.run(attempt())
    finally:
        router.close()

    assert [(result.ttl_expired, result.source) for result in results] == [(False, None), (False, None)]


def test_a_receive_error_with_nothing_queued_behind_it_ends_the_wait(silent: _Peer) -> None:
    # Only a queued error is known to be about another probe; any other
    # receive failure ends the wait rather than retrying it until the deadline.
    class _FailingSocket(socket.socket):
        def sendto(self, data: ReadableBuffer, /, *args: object) -> int:
            del args
            return super().sendto(data, (_LOOPBACK, silent.port))

        def recvfrom(self, bufsize: int, flags: int = 0, /) -> tuple[bytes, object]:
            del bufsize, flags
            raise OSError(errno.EIO, "the receive failed")

    def make(family: AddressFamily) -> socket.socket:
        del family
        return _FailingSocket(socket.AF_INET, socket.SOCK_DGRAM)

    wait = 1.0
    with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=make) as transport:
        started = time.perf_counter()
        result = transport.probe(sequence=1, timeout=wait, ttl=1)
        elapsed = time.perf_counter() - started

    assert not result.answered
    assert elapsed < wait / 2, f"the wait ran {elapsed:.2f}s against a failing receive"


@linux_error_queue
def test_a_queued_error_with_no_pending_errno_is_still_read(silent: _Peer) -> None:
    # A queued entry keeps the socket readable whether or not it set the
    # socket's errno (a local-origin error does not), so the reader must read
    # the queue on every call, not only when a receive raises.
    wait = 0.6
    wiring = _Wiring(silent.port)

    async def attempt() -> EchoResult:
        async with AsyncPosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
            probe = asyncio.create_task(transport.probe(sequence=2, timeout=wait))
            await asyncio.sleep(0.05)
            # No await from here on: the loop cannot run the reader until the
            # entry is queued and its errno cleared (reading SO_ERROR clears it
            # and leaves the queue as it is).
            wiring.send_stray(sequence=99, to=_closed())
            wiring.created[-1].getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            return await probe

    started = time.process_time()
    result = asyncio.run(attempt())
    cpu = time.process_time() - started

    assert not result.answered
    assert cpu < wait / 3, f"the wait burned {cpu:.2f}s of CPU in {wait}s"


@pytest.mark.parametrize("probe", ["sync", "async"])
def test_on_a_raw_socket_a_quote_with_another_identifier_is_not_this_probe(probe: str) -> None:
    # A raw socket keeps the identifier, so another process's probe with the
    # same sequence to the same host is told apart by it.
    router = _Peer(as_router=True, quote_identifier_shift=1)
    wiring = _Wiring(router.port, as_raw=True)
    try:
        if probe == "sync":
            with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
                result = transport.probe(sequence=4, timeout=0.4, ttl=1)
        else:
            result = _async_probe(wiring.factory(), sequence=4, timeout=0.4, ttl=1)
    finally:
        router.close()

    assert (result.ttl_expired, result.source) == (False, None)


def test_on_a_raw_socket_a_quote_with_the_probe_s_identifier_is_its_hop() -> None:
    router = _Peer(as_router=True)
    wiring = _Wiring(router.port, as_raw=True)
    try:
        with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
            result = transport.probe(sequence=4, timeout=2.0, ttl=1)
    finally:
        router.close()

    assert (result.ttl_expired, result.source) == (True, _LOOPBACK)


@linux_error_queue
@pytest.mark.parametrize("probe", ["sync", "async"])
def test_a_send_refused_for_an_error_queued_after_the_drain_is_sent_again(answering: _Peer, probe: str) -> None:
    # An error can be queued between the pre-send drain and the send, which
    # the kernel then refuses with its errno. Here the first send queues one
    # first, deterministically: it waits for the stray's error, then sends.
    stray_to = _closed()

    class _ErrsFirst(socket.socket):
        sends = 0

        def sendto(self, data: ReadableBuffer, /, *args: object) -> int:
            del args
            type(self).sends += 1
            if type(self).sends == 1:
                socket.socket.sendto(self, _stray(99, header_only=False), stray_to)
                select.select([self], [], [], _ERROR_ARRIVAL_WAIT)
            return super().sendto(data, (_LOOPBACK, answering.port))

    def make(family: AddressFamily) -> socket.socket:
        del family
        return _ErrsFirst(socket.AF_INET, socket.SOCK_DGRAM)

    if probe == "sync":
        with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=make) as transport:
            result = transport.probe(sequence=2, timeout=2.0)
    else:
        result = _async_probe(make, sequence=2, timeout=2.0)

    assert result.answered
    assert _ErrsFirst.sends == 2, "the first send was refused and the second went out"


def test_a_time_exceeded_quoting_a_datagram_that_is_not_icmp_is_not_one_of_ours() -> None:
    request, _token = packet.build_echo_request(sequence=3)
    inner = b"\x45" + bytes(8) + b"\x11" + bytes(6) + socket.inet_aton(_LOOPBACK)
    message = bytes([packet.TIME_EXCEEDED_V4]) + bytes(packet.HEADER_SIZE - 1) + inner + request[: packet.HEADER_SIZE]

    assert packet.quoted_echo_request(message, family=AddressFamily.IPV4) is None
    icmp = inner[:9] + b"\x01" + inner[10:]
    quoted = packet.quoted_echo_request(
        bytes([packet.TIME_EXCEEDED_V4]) + bytes(packet.HEADER_SIZE - 1) + icmp + request[: packet.HEADER_SIZE], family=AddressFamily.IPV4
    )
    assert quoted is not None
    assert (quoted.request.sequence, quoted.destination) == (3, socket.inet_aton(_LOOPBACK))
