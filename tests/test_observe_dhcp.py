"""Session stories: ordering, the quiet window, teardown and the error split.

Everything here runs unprivileged on every platform, driven through the
``PacketCapture`` seam with an in-process double. Nothing in this package is
monkeypatched: the substitution point is a constructor argument.
"""

# The session's own internals are the subject here: the quiet-window rule and
# the platform dispatch are what these tests exist to pin down.
# pyright: reportPrivateUsage=false

from __future__ import annotations

import socket
import threading
import time
from typing import TYPE_CHECKING, TypedDict

import pytest
from capture_support import capture_interface
from dhcp_capture_fixture import REAL_REPLY_FRAMES

from ipscout.bootp import offers_from_frames
from ipscout.dhcp import (
    DhcpSession,
    _open_capture,
    _the_exchange_has_gone_quiet,
    dhcp_capture_available,
    observe_dhcp,
    observe_dhcp_first_reachable,
    observe_dhcp_session,
)
from ipscout.errors import IPScoutError, IPScoutPermissionError, IPScoutUnsupportedError
from ipscout.ports import PacketCapture

if TYPE_CHECKING:
    from collections.abc import Callable

pytestmark = pytest.mark.os_agnostic

GUEST_MAC = "02:00:5e:10:00:00"
EXPECTED_OFFERS = ["198.51.100.36", "198.51.100.51"]

FIRST = REAL_REPLY_FRAMES["offer_198.51.100.36"]
SECOND = REAL_REPLY_FRAMES["offer_198.51.100.51"]
FOREIGN = REAL_REPLY_FRAMES["foreign_mac"]


class _Window(TypedDict):
    """The two time knobs, named so they can be unpacked with their types."""

    timeout: float
    settle: float


#: Short enough that the whole file runs in well under a second, while still
#: leaving the quiet window comfortably longer than one poll tick.
FAST: _Window = {"timeout": 2.0, "settle": 0.05}


class ScriptedCapture:
    """Hands out prepared frames, then goes quiet, like a real capture."""

    def __init__(self, *frames: bytes, fail_with: OSError | None = None, delay: float = 0.0) -> None:
        self._frames = list(frames)
        self._fail_with = fail_with
        self._delay = delay
        self.closed = False
        self.opened = False

    def receive(self, *, timeout: float) -> bytes | None:
        del timeout
        if self._frames:
            if self._delay:
                time.sleep(self._delay)
            return self._frames.pop(0)
        if self._fail_with is not None:
            raise self._fail_with
        # Out of script: behave like a quiet wire rather than ending the read
        # loop, which is what a real capture does between exchanges.
        time.sleep(0.005)
        return None

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> ScriptedCapture:
        self.opened = True
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        del exc_type, exc, tb
        self.close()


def test_the_double_satisfies_the_declared_protocol() -> None:
    # If this fails, everything below proves nothing about the real backend.
    assert isinstance(ScriptedCapture(), PacketCapture)


# --------------------------------------------------------------------------
# The answer
# --------------------------------------------------------------------------


def test_both_offers_are_reported_in_the_order_they_arrived() -> None:
    with observe_dhcp_session(GUEST_MAC, capture=ScriptedCapture(FIRST, SECOND), **FAST) as session:
        assert session.result() == EXPECTED_OFFERS


def test_an_offer_for_another_machine_never_enters_the_answer() -> None:
    with observe_dhcp_session(GUEST_MAC, capture=ScriptedCapture(FOREIGN, FIRST), **FAST) as session:
        assert session.result() == ["198.51.100.36"]


def test_a_machine_that_never_appears_is_an_empty_list_not_an_error() -> None:
    # The acceptance criterion. "Did not appear" and "could not watch" are
    # different facts and only the second one raises.
    with observe_dhcp_session(GUEST_MAC, capture=ScriptedCapture(), timeout=0.2, settle=0.05) as session:
        assert session.result() == []


def test_the_one_shot_call_and_the_session_agree() -> None:
    # They must, because the one-shot form IS the session; this is what keeps
    # that true if somebody later gives it its own code path.
    with observe_dhcp_session(GUEST_MAC, capture=ScriptedCapture(FIRST, SECOND), **FAST) as session:
        through_session = session.result()
    one_shot = observe_dhcp(GUEST_MAC, capture=ScriptedCapture(FIRST, SECOND), **FAST)

    assert one_shot == through_session == EXPECTED_OFFERS


def test_a_retransmission_does_not_hold_the_quiet_window_open() -> None:
    # A server repeating an address already seen must not restart the settle
    # clock, or a chatty one would stretch every call to the full timeout.
    started = time.monotonic()
    with observe_dhcp_session(GUEST_MAC, capture=ScriptedCapture(FIRST, FIRST, FIRST), timeout=5.0, settle=0.1) as session:
        assert session.result() == ["198.51.100.36"]

    assert time.monotonic() - started < 2.0


# --------------------------------------------------------------------------
# The blocking contract
# --------------------------------------------------------------------------


def test_asking_twice_gives_the_same_answer_even_when_more_arrives_between() -> None:
    # A result records something that already happened, so observing it twice
    # cannot give two answers - not even when the wire kept talking after the
    # first look. Asserted by letting a second address genuinely arrive in
    # between, rather than by timing the second call: with a settle of 0.05 a
    # call that DID block again would return just as fast, so the clock could
    # never tell the two apart. It only ever measured runner load, and did
    # exactly that on a macOS lane at 0.0526s.
    with observe_dhcp_session(GUEST_MAC, capture=ScriptedCapture(FIRST, SECOND, delay=0.3), timeout=3.0, settle=0.05) as session:
        first = session.result()

        # The second frame is still in flight here: the quiet window closed
        # after the first, and the pump keeps running until the block exits.
        deadline = time.monotonic() + 2.0
        while session.running and len(session._found) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert len(session._found) == 2, "the later address never arrived, so this proves nothing"
        second = session.result()

    assert first == ["198.51.100.36"]
    assert second == first, "the recorded answer changed after a later address arrived"


def test_the_answer_survives_the_block_it_was_captured_in() -> None:
    session = observe_dhcp_session(GUEST_MAC, capture=ScriptedCapture(FIRST, SECOND), **FAST)
    with session:
        session.result()

    assert session.result() == EXPECTED_OFFERS
    assert session.running is False


def test_a_session_cannot_be_used_twice() -> None:
    session = observe_dhcp_session(GUEST_MAC, capture=ScriptedCapture(), timeout=0.2, settle=0.05)
    with session:
        pass

    with pytest.raises(RuntimeError, match="already been used"), session:
        pass


# --------------------------------------------------------------------------
# offers() and result() are two views of one record
# --------------------------------------------------------------------------


def test_partly_consuming_the_stream_does_not_subtract_from_the_answer() -> None:
    # result() is the record of what happened; reading the stream is a reading
    # action and cannot take anything out of it. observe_dhcp_first_reachable
    # depends on exactly this, since it stops as soon as one address answers.
    with observe_dhcp_session(GUEST_MAC, capture=ScriptedCapture(FIRST, SECOND), **FAST) as session:
        for _first_only in session.offers():
            break

        assert session.result() == EXPECTED_OFFERS


def test_the_incremental_ordering_matches_the_pure_rule() -> None:
    # The session appends against a set rather than calling merge_offers per
    # frame, because rebuilding the list and its set on every arrival was
    # quadratic. That makes two implementations of one rule, so this pins them
    # together: if they ever diverge, the answer's ORDER is what breaks.
    frames = [FIRST, SECOND, FIRST, SECOND, FIRST]

    with observe_dhcp_session(GUEST_MAC, capture=ScriptedCapture(*frames), **FAST) as session:
        incremental = session.result()

    assert incremental == offers_from_frames(frames, mac=GUEST_MAC)
    assert incremental == EXPECTED_OFFERS


def test_two_readers_each_see_the_whole_sequence() -> None:
    # Not a race for the same items: a second iterator replays what has
    # already been yielded and then continues.
    with observe_dhcp_session(GUEST_MAC, capture=ScriptedCapture(FIRST, SECOND), **FAST) as session:
        session.result()

        assert list(session.offers()) == EXPECTED_OFFERS
        assert list(session.offers()) == EXPECTED_OFFERS


def test_the_stream_yields_each_address_once_and_then_ends() -> None:
    with observe_dhcp_session(GUEST_MAC, capture=ScriptedCapture(FIRST, SECOND, FIRST), timeout=0.5, settle=0.05) as session:
        assert list(session.offers()) == EXPECTED_OFFERS


# --------------------------------------------------------------------------
# The quiet-window rule, as arithmetic
# --------------------------------------------------------------------------


def test_nothing_seen_yet_waits_for_the_whole_window() -> None:
    quiet = _the_exchange_has_gone_quiet

    assert quiet(last_seen_at=None, now=59.0, started_at=0.0, timeout=60.0, settle=12.0) is False
    assert quiet(last_seen_at=None, now=60.0, started_at=0.0, timeout=60.0, settle=12.0) is True


def test_a_new_address_slides_the_window() -> None:
    quiet = _the_exchange_has_gone_quiet

    # Seen at 2.0: quiet at 14.0. A second at 10.0 pushes that out to 22.0.
    assert quiet(last_seen_at=2.0, now=14.0, started_at=0.0, timeout=60.0, settle=12.0) is True
    assert quiet(last_seen_at=10.0, now=14.0, started_at=0.0, timeout=60.0, settle=12.0) is False


def test_the_deadline_always_wins() -> None:
    quiet = _the_exchange_has_gone_quiet

    assert quiet(last_seen_at=59.9, now=60.0, started_at=0.0, timeout=60.0, settle=12.0) is True


def test_a_settle_as_long_as_the_window_is_the_exhaustive_read() -> None:
    quiet = _the_exchange_has_gone_quiet

    assert quiet(last_seen_at=1.0, now=30.0, started_at=0.0, timeout=60.0, settle=60.0) is False
    assert quiet(last_seen_at=1.0, now=60.0, started_at=0.0, timeout=60.0, settle=60.0) is True


# --------------------------------------------------------------------------
# Teardown
# --------------------------------------------------------------------------


def test_leaving_the_block_releases_the_capture() -> None:
    capture = ScriptedCapture(FIRST)
    with observe_dhcp_session(GUEST_MAC, capture=capture, **FAST) as session:
        session.result()

    assert capture.closed is True


def test_a_failure_inside_the_block_still_releases_the_capture() -> None:
    # The interface is left promiscuous until the socket closes, so a leaked
    # capture is a host-wide side effect, not just an idle thread.
    capture = ScriptedCapture(FIRST)
    with pytest.raises(ZeroDivisionError), observe_dhcp_session(GUEST_MAC, capture=capture, **FAST):
        _ = 1 / 0

    assert capture.closed is True


def test_stopping_twice_is_harmless() -> None:
    session = observe_dhcp_session(GUEST_MAC, capture=ScriptedCapture(), timeout=0.2, settle=0.05)
    with session:
        session.stop()
        session.stop()


def test_the_reading_thread_does_not_outlive_the_block() -> None:
    before = threading.active_count()
    with observe_dhcp_session(GUEST_MAC, capture=ScriptedCapture(FIRST), **FAST) as session:
        session.result()

    assert threading.active_count() <= before


# --------------------------------------------------------------------------
# What raises, and where
# --------------------------------------------------------------------------


def test_a_hardware_address_that_is_not_one_is_refused_before_anything_opens() -> None:
    # Refused on every host, including those that could never capture, so the
    # error a user gets for a typo does not depend on their privileges.
    with pytest.raises(ValueError, match="not a hardware address"):
        observe_dhcp_session("nonsense")


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda: observe_dhcp_session(GUEST_MAC, timeout=0.0), id="timeout-zero"),
        pytest.param(lambda: observe_dhcp_session(GUEST_MAC, timeout=-1.0), id="timeout-negative"),
        pytest.param(lambda: observe_dhcp_session(GUEST_MAC, settle=-0.5), id="settle-negative"),
    ],
)
def test_a_window_that_could_never_work_is_refused(build: Callable[[], DhcpSession]) -> None:
    with pytest.raises(ValueError, match=r"timeout|settle"):
        build()


def test_a_capture_that_cannot_open_says_so_before_the_caller_starts_anything() -> None:
    # The whole reason the session form exists. Learning this after booting a
    # machine and waiting out the window is indistinguishable from the machine
    # never having appeared.
    if dhcp_capture_available():
        pytest.skip("this host may capture, so there is no refusal to observe")

    with pytest.raises((IPScoutPermissionError, IPScoutUnsupportedError)), DhcpSession(GUEST_MAC, interface=capture_interface() or "lo"):
        pytest.fail("the capture should not have opened")


def test_opening_a_real_capture_yields_something_satisfying_the_protocol() -> None:
    # The mirror of the test above, for a host that does have the privilege.
    # Between them one of the two always runs, so the un-injected path is
    # never left entirely unexercised.
    interface = capture_interface()
    if not dhcp_capture_available() or interface is None:
        pytest.skip("this host cannot capture, so there is nothing to open")

    with DhcpSession(GUEST_MAC, interface=interface, timeout=0.2, settle=0.05) as session:
        assert session.result() == []


def test_a_capture_that_dies_mid_window_raises_rather_than_answering_short() -> None:
    # A partial list cannot be told apart from a complete one, so it must not
    # be returned as though it were the answer.
    capture = ScriptedCapture(FIRST, fail_with=OSError("interface went away"))
    with pytest.raises(IPScoutError, match="stopped before the window ended"), observe_dhcp_session(GUEST_MAC, capture=capture, **FAST) as session:
        session.result()


@pytest.mark.parametrize(("platform", "expected"), [("darwin", "macOS"), ("sunos5", "no backend")])
def test_a_platform_without_a_backend_says_which_and_why(platform: str, expected: str) -> None:
    # Windows is deliberately absent: it HAS a backend now, and asserting a
    # refusal there passed for the wrong reason while it did not - the Windows
    # backend's own "iphlpapi is a Windows library" error merely contains the
    # word "Windows".
    with pytest.raises(IPScoutUnsupportedError, match=expected):
        _open_capture("br0", platform=platform)


def test_the_refusal_names_something_a_reader_can_actually_do() -> None:
    # A refusal that only reports refusal leaves the reader stuck.
    with pytest.raises(IPScoutUnsupportedError, match="subnet_info"):
        _open_capture("br0", platform="darwin")


def test_windows_dispatches_to_its_own_backend_rather_than_refusing() -> None:
    # Off Windows this cannot reach a socket, so what is asserted is the
    # DISPATCH: the failure must come from the Windows backend looking for an
    # adapter, not from the facade saying the platform is unsupported.
    with pytest.raises(IPScoutUnsupportedError, match=r"iphlpapi|no interface named"):
        _open_capture("Ethernet", platform="win32")


# --------------------------------------------------------------------------
# The first-reachable convenience
# --------------------------------------------------------------------------


def test_the_first_address_that_answers_is_the_one_returned() -> None:
    # The declined address is offered first and never comes up; the working
    # one arrives second. Taking [0] is the bug this whole feature exists to
    # avoid, so the wrapper has to walk past it.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        found = observe_dhcp_first_reachable(
            GUEST_MAC,
            capture=ScriptedCapture(_frame_offering("203.0.113.7"), _frame_offering("127.0.0.1")),
            timeout=3.0,
            tcp_port=port,
            probe_timeout=0.3,
        )

    assert found == "127.0.0.1"


def test_nothing_reachable_is_none_rather_than_an_error() -> None:
    found = observe_dhcp_first_reachable(
        GUEST_MAC,
        capture=ScriptedCapture(_frame_offering("203.0.113.7")),
        timeout=0.6,
        tcp_port=9,
        probe_timeout=0.2,
    )

    assert found is None


def _frame_offering(address: str) -> bytes:
    """Return the captured frame with its offered address swapped out."""

    # Rewriting in place keeps every other byte real wire data. The offered
    # address appears twice: as the IPv4 destination and as yiaddr.
    packed = socket.inet_aton(address)
    frame = bytearray(FIRST)
    frame[30:34] = packed
    frame[14 + 20 + 8 + 16 : 14 + 20 + 8 + 20] = packed
    return bytes(frame)
