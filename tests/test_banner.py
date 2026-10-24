"""Banner-grab stories against real loopback servers. No mocks anywhere."""

from __future__ import annotations

import asyncio
import socket
import sys
import threading
import time
from typing import TYPE_CHECKING, Any

import pytest

from ipscout import AddressFamily, Banner, BannerState, agrab_banners, grab_banners

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.os_agnostic

#: TEST-NET-3 (RFC 5737): reserved, unrouted, so a connect hangs or is unroutable.
NEVER_ANSWERS = "203.0.113.1"

#: How long a server keeps reading after its reply before giving up on the client.
_SERVER_READ_LIMIT = 5.0


class _Greeter:
    """A loopback TCP server on 127.0.0.1 and ::1 that greets, records and counts.

    Args:
        reply: Bytes sent on accept, or None to send nothing.
        close_after_reply: Close straight after ``reply`` instead of reading on.
        delay_v4: Seconds to wait before replying on the IPv4 listener only, so
            one host of a pair answers later than the other.
    """

    def __init__(self, reply: bytes | None, *, close_after_reply: bool = False, delay_v4: float = 0.0) -> None:
        self._reply = reply
        self._close_after_reply = close_after_reply
        self._delay_v4 = delay_v4
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.accepts = 0
        self.received: list[bytes] = []
        self._listeners = _bind_pair()
        self.port = int(self._listeners[0].getsockname()[1])
        self._threads = [threading.Thread(target=self._serve, args=(listener,), daemon=True) for listener in self._listeners]
        for thread in self._threads:
            thread.start()

    def _serve(self, listener: socket.socket) -> None:
        listener.settimeout(0.05)
        delay = self._delay_v4 if listener.family == socket.AF_INET else 0.0
        while not self._stop.is_set():
            try:
                conn, _ = listener.accept()
            except (TimeoutError, OSError):
                continue
            with self._lock:
                self.accepts += 1
            threading.Thread(target=self._handle, args=(conn, delay), daemon=True).start()

    def _handle(self, conn: socket.socket, delay: float) -> None:
        with conn:
            if delay:
                time.sleep(delay)
            if self._reply is not None:
                conn.sendall(self._reply)
                if self._close_after_reply:
                    return
            self._read_until_eof(conn)

    def _read_until_eof(self, conn: socket.socket) -> None:
        conn.settimeout(_SERVER_READ_LIMIT)
        chunks: list[bytes] = []
        try:
            while chunk := conn.recv(4096):
                chunks.append(chunk)
        except OSError:
            pass
        with self._lock:
            self.received.append(b"".join(chunks))

    def wait_for_sessions(self, count: int, *, limit: float = 5.0) -> None:
        """Block until ``count`` sessions have finished reading, or fail."""

        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            with self._lock:
                if len(self.received) >= count:
                    return
            time.sleep(0.01)
        pytest.fail(f"server saw {len(self.received)} finished sessions, wanted {count}")

    def close(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=2.0)
        for listener in self._listeners:
            listener.close()


def _bind_pair() -> list[socket.socket]:
    """Bind 127.0.0.1 and ::1 on the same free port, retrying on a collision."""

    for _ in range(20):
        v4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        v4.bind(("127.0.0.1", 0))
        port = int(v4.getsockname()[1])
        v6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        try:
            v6.bind(("::1", port))
        except OSError:
            v4.close()
            v6.close()
            continue
        v4.listen(16)
        v6.listen(16)
        return [v4, v6]
    pytest.fail("could not bind 127.0.0.1 and ::1 on one port")


@pytest.fixture
def greeter() -> Iterator[type[_Greeter]]:
    """Hand out greeters and close every one at teardown."""

    made: list[_Greeter] = []

    class _Tracked(_Greeter):
        def __init__(self, reply: bytes | None, *, close_after_reply: bool = False, delay_v4: float = 0.0) -> None:
            super().__init__(reply, close_after_reply=close_after_reply, delay_v4=delay_v4)
            made.append(self)

    yield _Tracked
    for server in made:
        server.close()


@pytest.fixture
def closed_port() -> int:
    """Return a loopback port that is bound then released, so it refuses."""

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


def _one(
    host: str,
    port: int,
    *,
    timeout: float = 3.0,
    max_line_bytes: int = 512,
    farewell: bytes | None = None,
    family: AddressFamily | None = None,
) -> Banner:
    """Grab one host's banner and return just that result."""

    results = grab_banners([host], port, timeout=timeout, max_line_bytes=max_line_bytes, farewell=farewell, family=family)
    return results[host]


# --- what a greeting looks like on the way back ---------------------------------


def test_a_greeting_is_returned_without_its_terminator(greeter: type[_Greeter]) -> None:
    server = greeter(b"220 Print Server Ready.\r\n", close_after_reply=True)

    banner = _one("127.0.0.1", server.port)

    assert banner == Banner(host="127.0.0.1", port=server.port, state=BannerState.GREETED, line="220 Print Server Ready.")


def test_a_bare_newline_ends_the_line_too(greeter: type[_Greeter]) -> None:
    server = greeter(b"SSH-2.0-OpenSSH_9.9\nsecond line\n", close_after_reply=True)

    assert _one("127.0.0.1", server.port).line == "SSH-2.0-OpenSSH_9.9"


def test_surrounding_whitespace_is_stripped(greeter: type[_Greeter]) -> None:
    server = greeter(b"  220 ready  \r\n", close_after_reply=True)

    assert _one("127.0.0.1", server.port).line == "220 ready"


def test_a_partial_line_before_the_close_is_still_the_line(greeter: type[_Greeter]) -> None:
    # A server that writes no terminator and hangs up has still said something.
    server = greeter(b"220 no newline", close_after_reply=True)

    banner = _one("127.0.0.1", server.port)

    assert banner.state is BannerState.GREETED
    assert banner.line == "220 no newline"


def test_a_line_longer_than_the_cap_is_cut_at_the_cap(greeter: type[_Greeter]) -> None:
    server = greeter(b"A" * 1000 + b"\n", close_after_reply=True)

    assert _one("127.0.0.1", server.port, max_line_bytes=16).line == "A" * 16


def test_bytes_that_are_not_utf8_are_replaced_rather_than_fatal(greeter: type[_Greeter]) -> None:
    server = greeter(b"220 \xff\xfe ok\r\n", close_after_reply=True)

    assert _one("127.0.0.1", server.port).line == "220 �� ok"


# --- the farewell, and the one-connection contract -------------------------------


def test_the_farewell_reaches_the_server_once_after_the_greeting(greeter: type[_Greeter]) -> None:
    server = greeter(b"220 ready\r\n")

    banner = _one("127.0.0.1", server.port, farewell=b"QUIT\r\n")
    server.wait_for_sessions(1)

    assert banner.state is BannerState.GREETED
    assert server.received == [b"QUIT\r\n"]


def test_everything_happens_on_one_connection(greeter: type[_Greeter]) -> None:
    # Some devices refuse a new connect for a moment after each session, so a
    # probe that connected once to test and again to read would miss them.
    server = greeter(b"220 ready\r\n")

    _one("127.0.0.1", server.port, farewell=b"QUIT\r\n")
    server.wait_for_sessions(1)

    assert server.accepts == 1


def test_no_farewell_is_sent_to_a_server_that_said_nothing(greeter: type[_Greeter]) -> None:
    server = greeter(None)

    banner = _one("127.0.0.1", server.port, timeout=0.3, farewell=b"QUIT\r\n")
    server.wait_for_sessions(1)

    assert banner.state is BannerState.SILENT
    assert server.received == [b""]


def test_without_a_farewell_nothing_is_sent(greeter: type[_Greeter]) -> None:
    server = greeter(b"220 ready\r\n")

    _one("127.0.0.1", server.port)
    server.wait_for_sessions(1)

    assert server.received == [b""]


# --- the states that are not a greeting ------------------------------------------


def test_a_server_that_accepts_and_says_nothing_is_silent(greeter: type[_Greeter]) -> None:
    server = greeter(None)

    started = time.monotonic()
    banner = _one("127.0.0.1", server.port, timeout=0.3)
    elapsed = time.monotonic() - started

    assert banner == Banner(host="127.0.0.1", port=server.port, state=BannerState.SILENT)
    assert elapsed < 2.0


def test_a_server_that_hangs_up_without_a_byte_is_silent(greeter: type[_Greeter]) -> None:
    server = greeter(b"", close_after_reply=True)

    assert _one("127.0.0.1", server.port).state is BannerState.SILENT


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows silently drops rather than sending RST for a bound-then-closed loopback port, so a refusal cannot be provoked",
)
def test_a_refused_connection_is_reported_as_refused(closed_port: int) -> None:
    assert _one("127.0.0.1", closed_port) == Banner(host="127.0.0.1", port=closed_port, state=BannerState.REFUSED)


def test_a_host_that_never_answers_is_unreachable_with_a_reason() -> None:
    started = time.monotonic()
    banner = _one(NEVER_ANSWERS, 21, timeout=0.3)
    elapsed = time.monotonic() - started

    assert banner.state is BannerState.UNREACHABLE
    assert banner.error
    assert elapsed < 2.0


def test_a_name_that_does_not_resolve_is_unreachable_not_raised() -> None:
    banner = _one("nothing.invalid", 21, timeout=2.0)

    assert banner.state is BannerState.UNREACHABLE
    assert banner.error
    assert "nothing.invalid" in banner.error


def test_the_family_restriction_is_applied_to_each_host(greeter: type[_Greeter]) -> None:
    server = greeter(b"220 ready\r\n", close_after_reply=True)

    banner = _one("127.0.0.1", server.port, family=AddressFamily.IPV6)

    assert banner.state is BannerState.UNREACHABLE
    assert banner.error


# --- many hosts --------------------------------------------------------------------


def test_results_come_back_in_input_order_whatever_finishes_first(greeter: type[_Greeter]) -> None:
    server = greeter(b"220 ready\r\n", close_after_reply=True, delay_v4=0.4)

    results = grab_banners(["127.0.0.1", "::1"], server.port)

    assert list(results) == ["127.0.0.1", "::1"]
    assert all(b.state is BannerState.GREETED for b in results.values())


def test_a_repeated_host_is_grabbed_once(greeter: type[_Greeter]) -> None:
    server = greeter(b"220 ready\r\n", close_after_reply=True)

    results = grab_banners(["127.0.0.1", "127.0.0.1"], server.port)

    assert list(results) == ["127.0.0.1"]
    assert server.accepts == 1


def test_hosts_are_grabbed_concurrently(greeter: type[_Greeter]) -> None:
    server = greeter(None)

    started = time.monotonic()
    results = grab_banners(["127.0.0.1", "::1"], server.port, timeout=1.0)
    elapsed = time.monotonic() - started

    assert [b.state for b in results.values()] == [BannerState.SILENT, BannerState.SILENT]
    assert elapsed < 1.8


def test_the_concurrency_limit_is_honoured(greeter: type[_Greeter]) -> None:
    server = greeter(None)

    started = time.monotonic()
    grab_banners(["127.0.0.1", "::1"], server.port, timeout=0.6, concurrency=1)
    elapsed = time.monotonic() - started

    assert elapsed >= 1.1


def test_the_awaitable_form_gives_the_same_answer(greeter: type[_Greeter]) -> None:
    server = greeter(b"220 ready\r\n", close_after_reply=True)

    results = asyncio.run(agrab_banners(["127.0.0.1"], server.port))

    assert results["127.0.0.1"].line == "220 ready"


def test_the_blocking_form_refuses_to_run_inside_an_event_loop() -> None:
    async def inside() -> None:
        grab_banners(["127.0.0.1"], 21)

    with pytest.raises(RuntimeError, match="agrab_banners"):
        asyncio.run(inside())


# --- arguments are checked before anything connects -------------------------------


@pytest.mark.parametrize("port", [0, 65536], ids=["zero", "too-high"])
def test_a_port_outside_the_tcp_range_is_refused(port: int) -> None:
    with pytest.raises(ValueError, match="port"):
        grab_banners(["127.0.0.1"], port)


@pytest.mark.parametrize(
    ("kwargs", "named"),
    [
        ({"timeout": 0}, "timeout"),
        ({"timeout": -1.0}, "timeout"),
        ({"max_line_bytes": 0}, "max_line_bytes"),
        ({"concurrency": 0}, "concurrency"),
    ],
    ids=["timeout-zero", "timeout-negative", "cap-zero", "concurrency-zero"],
)
def test_bad_arguments_are_refused_before_any_connect(greeter: type[_Greeter], kwargs: dict[str, Any], named: str) -> None:
    # Pointed at a live server, so a check made after connecting would show as an accept.
    server = greeter(b"220 ready\r\n", close_after_reply=True)

    with pytest.raises(ValueError, match=named):
        grab_banners(["127.0.0.1"], server.port, **kwargs)

    assert server.accepts == 0
