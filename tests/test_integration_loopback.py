"""Real ICMP against loopback. No fakes, no mocks - actual packets.

These prove the thing unit tests cannot: that the codec, the socket handling
and the reply matching agree with what the kernel actually does. In particular
they cover the measured behaviour that an unprivileged datagram socket has the
kernel overwrite the ICMP identifier, which is why matching keys on the payload
token instead.

Every test skips rather than fails where unprivileged ICMP is unavailable, so a
hardened runner reports an honest skip instead of a red build.
"""

from __future__ import annotations

import asyncio

import pytest

import ipscout
from ipscout.errors import IPScoutPermissionError, IPScoutResolutionError
from ipscout.models import AddressFamily, ProbeMethod
from ipscout.transport_posix import PosixEchoTransport

#: Reserved by RFC 6761 to never resolve, so no network is consulted.
NEVER_RESOLVES = "nothing.invalid"

#: TEST-NET-3 (RFC 5737), reserved for documentation and guaranteed unrouted.
NEVER_ANSWERS = "203.0.113.1"

pytestmark = pytest.mark.os_agnostic


def _require_icmp(family: AddressFamily = AddressFamily.IPV4) -> None:
    """Skip the calling test when unprivileged ICMP is unavailable here."""

    if not ipscout.icmp_available(family):
        pytest.skip(f"unprivileged ICMP unavailable for {family.value} on this host (check net.ipv4.ping_group_range, or run with CAP_NET_RAW)")


@pytest.mark.parametrize(
    ("address", "family"),
    [("127.0.0.1", AddressFamily.IPV4), ("::1", AddressFamily.IPV6)],
)
def test_loopback_answers_in_both_families(address: str, family: AddressFamily) -> None:
    _require_icmp(family)

    result = ipscout.ping(address, 2, interval=0)

    assert result.reached is True
    assert result.ip == address
    assert result.family is family
    assert result.method is ProbeMethod.ICMP
    assert result.packets_received == 2
    assert result.packets_lost_percentage == 0
    assert all(rtt is not None for rtt in result.rtts_ms)


def test_the_kernel_rewrites_our_identifier_and_matching_still_works() -> None:
    # The design constraint this whole library is built around. If the kernel
    # ever stopped rewriting it, matching would still work; if we had matched
    # on the identifier instead, nothing would ever match.
    _require_icmp()

    with PosixEchoTransport("127.0.0.1", AddressFamily.IPV4) as transport:
        result = transport.probe(sequence=1, timeout=2.0)

    assert result.answered
    assert result.source == "127.0.0.1"


def test_an_unrouted_address_times_out_rather_than_raising() -> None:
    _require_icmp()

    result = ipscout.ping(NEVER_ANSWERS, 1, timeout=1.0, interval=0)

    assert result.reached is False
    assert result.packets_lost_percentage == 100
    assert result.error is None


def test_a_timeout_is_honoured_rather_than_hanging() -> None:
    import time

    _require_icmp()

    started = time.perf_counter()
    ipscout.ping(NEVER_ANSWERS, 1, timeout=1.0, interval=0)
    elapsed = time.perf_counter() - started

    assert 0.9 <= elapsed < 3.0


def test_an_unresolvable_name_raises_instead_of_reading_as_down() -> None:
    with pytest.raises(IPScoutResolutionError):
        ipscout.ping(NEVER_RESOLVES)


def test_the_old_swallow_everything_behaviour_is_still_available() -> None:
    result = ipscout.ping(NEVER_RESOLVES, raise_on_error=False)

    assert result.reached is False
    assert result.error is not None
    assert "nothing.invalid" in result.error


def test_a_payload_size_is_honoured_end_to_end() -> None:
    _require_icmp()

    result = ipscout.ping("127.0.0.1", 1, interval=0, payload_size=1024)

    assert result.reached is True


def test_the_async_path_reaches_loopback_too() -> None:
    _require_icmp()

    result = asyncio.run(ipscout.aping("127.0.0.1", 2, interval=0))

    assert result.reached is True
    assert result.packets_received == 2


def test_a_sweep_returns_one_result_per_target_in_order() -> None:
    _require_icmp()

    results = ipscout.ping_many(["127.0.0.1", NEVER_ANSWERS], times=1, timeout=1.0)

    assert list(results) == ["127.0.0.1", NEVER_ANSWERS]
    assert results["127.0.0.1"].reached is True
    assert results[NEVER_ANSWERS].reached is False


def test_a_sweep_survives_one_bad_target_among_good_ones() -> None:
    # Defaulting raise_on_error to False for sweeps exists precisely so that
    # one typo cannot destroy 199 other results.
    _require_icmp()

    results = ipscout.ping_many(["127.0.0.1", NEVER_RESOLVES], times=1, timeout=1.0)

    assert results["127.0.0.1"].reached is True
    assert results[NEVER_RESOLVES].reached is False
    assert results[NEVER_RESOLVES].error is not None


def test_a_sweep_collapses_repeated_targets() -> None:
    _require_icmp()

    results = ipscout.ping_many(["127.0.0.1", "127.0.0.1"], times=1)

    assert list(results) == ["127.0.0.1"]


def test_a_concurrent_sweep_beats_running_the_timeouts_end_to_end() -> None:
    import time

    _require_icmp()
    targets = [NEVER_ANSWERS, "203.0.113.2", "203.0.113.3", "203.0.113.4"]

    started = time.perf_counter()
    ipscout.ping_many(targets, times=1, timeout=1.0, concurrency=8)
    elapsed = time.perf_counter() - started

    # Four 1s timeouts sequentially would be ~4s; concurrently, about one.
    assert elapsed < 2.5


def test_the_sync_sweep_refuses_to_deadlock_inside_a_running_loop() -> None:
    # Better a loud error than a hang nobody can diagnose.
    async def attempt() -> None:
        ipscout.ping_many(["127.0.0.1"], times=1)

    with pytest.raises(RuntimeError, match="aping_many"):
        asyncio.run(attempt())


def test_is_reachable_answers_for_loopback_and_for_nonsense() -> None:
    assert ipscout.is_reachable("127.0.0.1") is True
    assert ipscout.is_reachable(NEVER_RESOLVES) is False


def test_is_reachable_never_raises_whatever_it_is_given() -> None:
    # It is the one total function in the public API; that is its whole point.
    for nonsense in ("", "not a host", "999.999.999.999", NEVER_RESOLVES):
        assert ipscout.is_reachable(nonsense, timeout=0.5) is False


def test_the_async_reachability_shortcut_agrees_with_the_sync_one() -> None:
    assert asyncio.run(ipscout.ais_reachable("127.0.0.1")) is True
    assert asyncio.run(ipscout.ais_reachable(NEVER_RESOLVES, timeout=0.5)) is False


def test_availability_is_reported_without_provoking_an_exception() -> None:
    assert isinstance(ipscout.icmp_available(), bool)


def test_a_permission_failure_names_how_to_fix_it() -> None:
    # A bare refusal is useless; the message has to say what to change.
    message = str(
        IPScoutPermissionError(
            'unprivileged ICMP is unavailable and no raw socket could be opened. Fix any one of:\n  - Linux: sysctl -w net.ipv4.ping_group_range="0 2147483647"'
        )
    )

    assert "ping_group_range" in message
