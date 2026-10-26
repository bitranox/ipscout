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

#: Where the ICMP type sits in ``struct sock_extended_err``: after the 4-byte
#: errno and the 1-byte origin.
_EE_TYPE_OFFSET = 5

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

    def __init__(self, port: int, *, as_time_exceeded: bool) -> None:
        self.created: list[socket.socket] = []
        self._port = port
        self._as_time_exceeded = as_time_exceeded

    def factory(self) -> Callable[[AddressFamily], socket.socket]:
        port, rewrite = self._port, self._as_time_exceeded
        errqueue = socket_const("MSG_ERRQUEUE") or 0

        class _RoutedSocket(socket.socket):
            """A real UDP socket: sends reach the fixed port; queued errors may read as a router's."""

            def sendto(self, data: ReadableBuffer, /, *args: object) -> int:
                del args
                return super().sendto(data, (_LOOPBACK, port))

            def recvmsg(self, bufsize: int, ancbufsize: int = 0, flags: int = 0, /) -> tuple[bytes, list[tuple[int, int, bytes]], int, object]:
                data, ancillary, msg_flags, address = _BASE_RECVMSG(self, bufsize, ancbufsize, flags)
                if rewrite and flags & errqueue:
                    ancillary = [(level, kind, _as_time_exceeded(control)) for level, kind, control in ancillary]
                return data, ancillary, msg_flags, address

        def make(family: AddressFamily) -> socket.socket:
            del family
            sock = _RoutedSocket(socket.AF_INET, socket.SOCK_DGRAM)
            self.created.append(sock)
            return sock

        return make

    def send_stray(self, *, sequence: int, to_port: int) -> None:
        """Send an echo request the transport never asked for, and wait until its error is queued."""

        sock = self.created[-1]
        datagram, _token = packet.build_echo_request(sequence=sequence)
        socket.socket.sendto(sock, datagram, (_LOOPBACK, to_port))
        # A queued error makes the socket readable, before any datagram does.
        readable, _writable, _failed = select.select([sock], [], [], _ERROR_ARRIVAL_WAIT)
        assert readable, "the kernel queued no error for the stray send"

    def send_stray_during(self, *, sequence: int, to_port: int, after: float) -> threading.Timer:
        """Send a stray echo request ``after`` seconds from now, while a probe is waiting."""

        datagram, _token = packet.build_echo_request(sequence=sequence)
        sock = self.created[-1]
        timer = threading.Timer(after, socket.socket.sendto, args=(sock, datagram, (_LOOPBACK, to_port)))
        timer.start()
        return timer


def _as_time_exceeded(control: bytes) -> bytes:
    """Return a queued ICMP error's control message with its type made Time Exceeded."""

    return control[:_EE_TYPE_OFFSET] + bytes([packet.TIME_EXCEEDED_V4]) + control[_EE_TYPE_OFFSET + 1 :]


class _Peer:
    """A real UDP peer that answers echoes, or stays silent, or acts as a router.

    As a router it sends back a Time Exceeded datagram the way a raw socket
    receives one: an IPv4 header, the ICMP header, then the IP header and the
    first eight bytes of the request it quotes.
    """

    def __init__(self, *, answer: bool = True, as_router: bool = False, quote_sequence_shift: int = 0) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((_LOOPBACK, 0))
        self.port = int(self.socket.getsockname()[1])
        self._answer, self._as_router, self._shift = answer, as_router, quote_sequence_shift
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
                self.socket.sendto(bytes([packet.ECHO_REPLY_V4]) + raw[1:], peer)

    def _time_exceeded(self, request: bytes) -> bytes:
        quoted = bytearray(request[: packet.HEADER_SIZE])
        quoted[6:8] = ((int.from_bytes(quoted[6:8], "big") + self._shift) & 0xFFFF).to_bytes(2, "big")
        ip_header = b"\x45" + bytes(packet.IPV4_MIN_HEADER_SIZE - 1)
        return ip_header + bytes([packet.TIME_EXCEEDED_V4]) + bytes(packet.HEADER_SIZE - 1) + ip_header + bytes(quoted)

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


# --- a Time Exceeded on the error queue -------------------------------------------------


@linux_error_queue
def test_a_queued_time_exceeded_is_reported_as_the_hop_by_the_sync_transport() -> None:
    wiring = _Wiring(_closed_port(), as_time_exceeded=True)

    with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
        result = transport.probe(sequence=1, timeout=2.0, ttl=1)

    assert (result.ttl_expired, result.source) == (True, _LOOPBACK)


@linux_error_queue
def test_a_queued_time_exceeded_is_reported_as_the_hop_by_the_async_transport() -> None:
    # Before, the async transport never read the error queue: every hop of an
    # async traceroute read as silent while the sync walk found the routers.
    wiring = _Wiring(_closed_port(), as_time_exceeded=True)

    result = _async_probe(wiring.factory(), sequence=1, timeout=2.0, ttl=1)

    assert (result.ttl_expired, result.source) == (True, _LOOPBACK)


@linux_error_queue
def test_a_ping_without_a_hop_limit_reads_a_queued_error_as_no_answer() -> None:
    wiring = _Wiring(_closed_port(), as_time_exceeded=True)

    with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
        started = time.perf_counter()
        result = transport.probe(sequence=1, timeout=2.0)
        elapsed = time.perf_counter() - started

    assert not result.answered
    assert result.ttl_expired is False
    assert elapsed < 1.0, "an error that names the probe ends the wait"


# --- an error about an EARLIER probe ------------------------------------------------------


@linux_error_queue
def test_a_late_error_about_an_earlier_probe_does_not_refuse_the_next_send(answering: _Peer) -> None:
    # The kernel refuses a send with the errno of any queued error. Before,
    # that refusal read as a lost probe that was never sent.
    wiring = _Wiring(answering.port, as_time_exceeded=False)

    with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
        wiring.send_stray(sequence=99, to_port=_closed_port())
        result = transport.probe(sequence=2, timeout=2.0)

    assert result.answered


@linux_error_queue
def test_a_late_time_exceeded_is_not_pinned_on_a_later_silent_hop(silent: _Peer) -> None:
    # Before, an entry left on the queue was read as the answer of whichever
    # later probe next timed out: that hop showed an earlier hop's router.
    wiring = _Wiring(silent.port, as_time_exceeded=True)

    with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
        wiring.send_stray(sequence=99, to_port=_closed_port())
        first = transport.probe(sequence=2, timeout=0.3, ttl=2)
        second = transport.probe(sequence=3, timeout=0.3, ttl=3)

    assert (first.ttl_expired, first.source) == (False, None)
    assert (second.ttl_expired, second.source) == (False, None)


@linux_error_queue
def test_an_error_quoting_the_same_sequence_with_another_token_is_not_this_probe(silent: _Peer) -> None:
    wiring = _Wiring(silent.port, as_time_exceeded=True)

    with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
        stray = wiring.send_stray_during(sequence=2, to_port=_closed_port(), after=0.05)
        result = transport.probe(sequence=2, timeout=0.4, ttl=2)
        stray.join()

    assert (result.ttl_expired, result.source) == (False, None)


@linux_error_queue
def test_the_async_transport_sends_past_a_late_error_about_an_earlier_probe(answering: _Peer) -> None:
    wiring = _Wiring(answering.port, as_time_exceeded=False)

    async def attempt() -> EchoResult:
        async with AsyncPosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
            wiring.send_stray(sequence=99, to_port=_closed_port())
            return await transport.probe(sequence=2, timeout=2.0)

    assert asyncio.run(attempt()).answered


@linux_error_queue
def test_an_unread_error_does_not_spin_the_event_loop(silent: _Peer) -> None:
    # A queued error keeps the socket readable until it is read, so a reader
    # that never reads the queue is called again at once, for the whole wait.
    wait = 0.6
    wiring = _Wiring(silent.port, as_time_exceeded=False)

    async def attempt() -> EchoResult:
        async with AsyncPosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
            probe = asyncio.create_task(transport.probe(sequence=2, timeout=wait))
            await asyncio.sleep(0.05)
            wiring.send_stray(sequence=99, to_port=_closed_port())
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
    wiring = _Wiring(router.port, as_time_exceeded=False)
    try:
        with PosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
            result = transport.probe(sequence=4, timeout=2.0, ttl=1)
    finally:
        router.close()

    assert (result.ttl_expired, result.source) == (True, _LOOPBACK)


def test_a_time_exceeded_datagram_quoting_the_probe_is_its_hop_on_the_async_transport() -> None:
    router = _Peer(as_router=True)
    wiring = _Wiring(router.port, as_time_exceeded=False)
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
    wiring = _Wiring(router.port, as_time_exceeded=False)
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
    wiring = _Wiring(router.port, as_time_exceeded=False)

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
    wiring = _Wiring(silent.port, as_time_exceeded=False)

    async def attempt() -> EchoResult:
        async with AsyncPosixEchoTransport(_LOOPBACK, AddressFamily.IPV4, socket_factory=wiring.factory()) as transport:
            probe = asyncio.create_task(transport.probe(sequence=2, timeout=wait))
            await asyncio.sleep(0.05)
            # No await from here on: the loop cannot run the reader until the
            # entry is queued and its errno cleared (reading SO_ERROR clears it
            # and leaves the queue as it is).
            wiring.send_stray(sequence=99, to_port=_closed_port())
            wiring.created[-1].getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            return await probe

    started = time.process_time()
    result = asyncio.run(attempt())
    cpu = time.process_time() - started

    assert not result.answered
    assert cpu < wait / 3, f"the wait burned {cpu:.2f}s of CPU in {wait}s"
