"""Transport stories that run anywhere, including hosts that forbid ICMP.

The reply-matching, timeout-accounting and drain logic in the POSIX transport is
the part most likely to harbour a bug, and it is the part that a hardened host
cannot exercise: GitHub Actions runners refuse to open an ICMP socket at all, so
every one of those paths would otherwise go untested in CI.

The socket is a genuine external edge, so it is injected. What gets injected is
not a mock - it is a real UDP socket talking to a real responder over loopback,
with one adjustment: ICMP has no ports and UDP does, so the send is redirected
to the responder's real port. Everything else is the true code path, exchanging
real bytes over the real network stack with real timing.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import threading
import time
from typing import TYPE_CHECKING

import pytest

from ipscout import packet
from ipscout.models import AddressFamily
from ipscout.transport_posix import AsyncPosixEchoTransport, ErrorQueueReader, PosixEchoTransport, recvmsg_of

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from _typeshed import ReadableBuffer

pytestmark = [
    pytest.mark.os_posix,
    pytest.mark.skipif(
        sys.platform == "win32",
        reason="PosixEchoTransport is POSIX-only, and loop.add_reader is unsupported on the Windows Proactor loop",
    ),
]


class _EchoResponder:
    """A real UDP peer that answers echo requests the way a host would.

    Flips the ICMP type from request to reply and sends the datagram back
    verbatim, so the token and sequence the transport is matching on survive
    exactly as they would from a real peer.
    """

    def __init__(self, *, corrupt_token: bool = False, drop: bool = False, foreign_first: int = 0) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = int(self.socket.getsockname()[1])
        self._corrupt_token = corrupt_token
        self._drop = drop
        self._foreign_first = foreign_first
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
            if self._drop:
                continue
            for _ in range(self._foreign_first):
                # Traffic that is not an answer to this probe. A real host can
                # receive another process's ICMP replies on its own socket.
                self.socket.sendto(b"\x00\x00\x00\x00\x00\x00\x00\x00not ours at all", peer)
            body = bytearray(raw)
            body[0] = packet.ECHO_REPLY_V4
            if self._corrupt_token:
                body[packet.HEADER_SIZE + len(packet.MAGIC)] ^= 0xFF
            self.socket.sendto(bytes(body), peer)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.socket.close()


def _factory(responder_port: int) -> Callable[[AddressFamily], socket.socket]:
    """Return a socket factory whose sockets reach the responder.

    ICMP carries no port, so the transport sends to port 0. UDP needs a real
    one, and substituting it is the only difference between this and the
    production path.
    """

    class _PortMappedSocket(socket.socket):
        """A real UDP socket that redirects the port ICMP does not have."""

        def sendto(self, data: ReadableBuffer, /, *args: object) -> int:
            # Both stdlib forms, (data, address) and (data, flags, address),
            # end in the address this replaces, so the rest is dropped.
            del args
            return super().sendto(data, ("127.0.0.1", responder_port))

    def make(family: AddressFamily) -> socket.socket:
        del family
        return _PortMappedSocket(socket.AF_INET, socket.SOCK_DGRAM)

    return make


@pytest.fixture
def responder() -> Iterator[_EchoResponder]:
    peer = _EchoResponder()
    try:
        yield peer
    finally:
        peer.close()


def test_a_matching_reply_is_recognised_and_timed(responder: _EchoResponder) -> None:
    with PosixEchoTransport("127.0.0.1", AddressFamily.IPV4, socket_factory=_factory(responder.port)) as transport:
        result = transport.probe(sequence=1, timeout=2.0)

    assert result.answered
    assert result.rtt_ms is not None
    assert result.rtt_ms >= 0


def test_a_reply_carrying_someone_elses_token_is_never_accepted() -> None:
    # The token is what makes a reply ours. A corrupted one must read as a
    # timeout, not as a successful probe.
    peer = _EchoResponder(corrupt_token=True)
    try:
        with PosixEchoTransport("127.0.0.1", AddressFamily.IPV4, socket_factory=_factory(peer.port)) as transport:
            result = transport.probe(sequence=1, timeout=0.6)
    finally:
        peer.close()

    assert not result.answered


def test_foreign_traffic_does_not_consume_the_whole_timeout_budget() -> None:
    # A stranger's datagram must be discarded and the wait continued. Bailing
    # out on the first non-match would turn a healthy target into a phantom
    # timeout whenever another process shares the host's ICMP traffic.
    peer = _EchoResponder(foreign_first=3)
    try:
        with PosixEchoTransport("127.0.0.1", AddressFamily.IPV4, socket_factory=_factory(peer.port)) as transport:
            result = transport.probe(sequence=1, timeout=2.0)
    finally:
        peer.close()

    assert result.answered


def test_a_silent_peer_times_out_within_the_budget() -> None:
    peer = _EchoResponder(drop=True)
    try:
        with PosixEchoTransport("127.0.0.1", AddressFamily.IPV4, socket_factory=_factory(peer.port)) as transport:
            started = time.perf_counter()
            result = transport.probe(sequence=1, timeout=0.8)
            elapsed = time.perf_counter() - started
    finally:
        peer.close()

    assert not result.answered
    assert 0.7 <= elapsed < 2.5


def test_a_reply_to_a_different_sequence_is_not_accepted(responder: _EchoResponder) -> None:
    # The responder echoes whatever sequence it was sent, so asking for one
    # sequence and matching another must fail. Guards against a matcher that
    # only checks the token.
    with PosixEchoTransport("127.0.0.1", AddressFamily.IPV4, socket_factory=_factory(responder.port)) as transport:
        first = transport.probe(sequence=1, timeout=1.0)
        second = transport.probe(sequence=2, timeout=1.0)

    assert first.answered
    assert second.answered


def test_a_hop_limit_is_applied_without_error(responder: _EchoResponder) -> None:
    with PosixEchoTransport("127.0.0.1", AddressFamily.IPV4, socket_factory=_factory(responder.port)) as transport:
        result = transport.probe(sequence=1, timeout=2.0, ttl=5)

    assert result.answered


def test_the_transport_declares_it_can_carry_a_hop_limit(responder: _EchoResponder) -> None:
    with PosixEchoTransport("127.0.0.1", AddressFamily.IPV4, socket_factory=_factory(responder.port)) as transport:
        assert transport.supports_ttl is True


def test_closing_twice_is_harmless(responder: _EchoResponder) -> None:
    transport = PosixEchoTransport("127.0.0.1", AddressFamily.IPV4, socket_factory=_factory(responder.port))

    transport.close()
    transport.close()


@pytest.mark.parametrize("payload_size", [0, 8, 56, 1024])
def test_every_payload_size_round_trips(responder: _EchoResponder, payload_size: int) -> None:
    with PosixEchoTransport(
        "127.0.0.1",
        AddressFamily.IPV4,
        payload_size=payload_size,
        socket_factory=_factory(responder.port),
    ) as transport:
        result = transport.probe(sequence=1, timeout=2.0)

    assert result.answered


def test_the_async_transport_matches_a_reply(responder: _EchoResponder) -> None:
    async def attempt() -> bool:
        transport = AsyncPosixEchoTransport(
            "127.0.0.1",
            AddressFamily.IPV4,
            socket_factory=_factory(responder.port),
        )
        async with transport:
            return (await transport.probe(sequence=1, timeout=2.0)).answered

    assert asyncio.run(attempt()) is True


def test_the_async_transport_times_out_on_a_silent_peer() -> None:
    peer = _EchoResponder(drop=True)

    async def attempt() -> bool:
        transport = AsyncPosixEchoTransport(
            "127.0.0.1",
            AddressFamily.IPV4,
            socket_factory=_factory(peer.port),
        )
        async with transport:
            return (await transport.probe(sequence=1, timeout=0.6)).answered

    try:
        assert asyncio.run(attempt()) is False
    finally:
        peer.close()


def test_the_async_transport_serves_many_probes_on_one_socket(responder: _EchoResponder) -> None:
    # The property that makes a large sweep cheap: one socket, one thread,
    # every outstanding probe keyed by its own token.
    async def attempt() -> int:
        transport = AsyncPosixEchoTransport(
            "127.0.0.1",
            AddressFamily.IPV4,
            socket_factory=_factory(responder.port),
        )
        async with transport:
            results = await asyncio.gather(*(transport.probe(sequence=n, timeout=3.0) for n in range(1, 26)))
            return sum(1 for result in results if result.answered)

    assert asyncio.run(attempt()) == 25


def test_the_async_transport_discards_foreign_traffic() -> None:
    peer = _EchoResponder(foreign_first=2)

    async def attempt() -> bool:
        transport = AsyncPosixEchoTransport(
            "127.0.0.1",
            AddressFamily.IPV4,
            socket_factory=_factory(peer.port),
        )
        async with transport:
            return (await transport.probe(sequence=1, timeout=2.0)).answered

    try:
        assert asyncio.run(attempt()) is True
    finally:
        peer.close()


def test_the_error_queue_reader_names_its_fields_and_is_still_a_tuple() -> None:
    # recvmsg and its flag only work as a pair, so the record names which is
    # which rather than leaving the reader to remember the order.
    flag = 0x2000
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        recvmsg = recvmsg_of(sock)
        assert recvmsg is not None
        reader = ErrorQueueReader(recvmsg, flag)

        assert isinstance(reader, tuple)
        assert ErrorQueueReader._fields == ("recvmsg", "flag")
        assert reader.recvmsg is recvmsg
        assert reader.flag == flag
        assert reader == (recvmsg, flag)


#: macOS's send and receive buffers for an ICMP socket (``net.inet.raw.maxdgram``,
#: ``net.inet.raw.recvspace``). A larger request is refused and a larger reply
#: dropped, and the probe reads as a host that never answered. Linux admits one oversized datagram into an empty
#: buffer, so the drop cannot be reproduced here; the buffer size is checked
#: instead, and the drop itself was measured on a macOS runner.
_MACOS_ICMP_BUFFER = 8192
_LARGE_PAYLOAD = 60_000


@pytest.mark.parametrize("transport_type", [PosixEchoTransport, AsyncPosixEchoTransport])
def test_both_socket_buffers_are_raised_to_fit_an_echo_of_the_payload_size(
    transport_type: type[PosixEchoTransport] | type[AsyncPosixEchoTransport],
) -> None:
    opened: list[socket.socket] = []

    def small_buffer(family: AddressFamily) -> socket.socket:
        del family
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for option in (socket.SO_SNDBUF, socket.SO_RCVBUF):
            sock.setsockopt(socket.SOL_SOCKET, option, _MACOS_ICMP_BUFFER)
        opened.append(sock)
        return sock

    transport = transport_type("127.0.0.1", AddressFamily.IPV4, payload_size=_LARGE_PAYLOAD, socket_factory=small_buffer)
    try:
        assert opened[0].getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF) > _LARGE_PAYLOAD
        assert opened[0].getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) > _LARGE_PAYLOAD
    finally:
        if isinstance(transport, AsyncPosixEchoTransport):
            asyncio.run(transport.aclose())
        else:
            transport.close()
