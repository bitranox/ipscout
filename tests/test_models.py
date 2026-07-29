"""Result-type stories, with the pre-1.0 compatibility promise pinned down."""

from __future__ import annotations

import dataclasses

import pytest

from ipscout.models import AddressFamily, MacLookup, MacScope, ProbeMethod, ResponseObject


def _reply(*rtts: float | None, target: str = "example.test", ip: str = "10.0.0.1") -> ResponseObject:
    """Build a result from a per-packet round-trip pattern."""

    received = [rtt for rtt in rtts if rtt is not None]
    return ResponseObject(
        target=target,
        reached=bool(received),
        ip=ip,
        number_of_pings=len(rtts),
        rtts_ms=tuple(rtts),
        packets_sent=len(rtts),
        packets_received=len(received),
    )


@pytest.mark.os_agnostic
def test_the_summary_line_matches_the_pre_1_0_format_exactly() -> None:
    # Callers log this string and some of them parse it, so it is a contract.
    result = _reply(2.5, ip="1.1.1.1")

    assert result.str_result == "[1.1.1.1] pinged 1 times, min: 2.50ms, avg: 2.50ms, max: 2.50ms, 0% Packet loss"


@pytest.mark.os_agnostic
def test_a_result_with_nothing_received_keeps_the_old_sentinels() -> None:
    result = ResponseObject(target="10.0.0.9", number_of_pings=1, rtts_ms=(None,), packets_sent=1)

    assert result.reached is False
    assert result.ip == "0.0.0.0"  # noqa: S104 - asserting the compatibility sentinel, not binding
    assert result.time_min_ms == -1.0
    assert result.time_avg_ms == -1.0
    assert result.time_max_ms == -1.0
    assert result.packets_lost_percentage == 100


@pytest.mark.os_agnostic
def test_a_default_result_is_the_unreached_shape() -> None:
    result = ResponseObject(target="nowhere")

    assert result.reached is False
    assert result.number_of_pings == 0
    assert result.packets_lost_percentage == 100
    assert result.n_packets_lost == 0
    assert result.error is None


@pytest.mark.os_agnostic
def test_the_timing_summary_spans_what_actually_came_back() -> None:
    result = _reply(1.0, 3.0, 5.0)

    assert (result.time_min_ms, result.time_avg_ms, result.time_max_ms) == (1.0, 3.0, 5.0)


@pytest.mark.os_agnostic
def test_lost_packets_are_skipped_by_the_timing_summary_not_counted_as_zero() -> None:
    result = _reply(2.0, None, 4.0)

    assert result.time_min_ms == 2.0
    assert result.time_avg_ms == 3.0
    assert result.time_max_ms == 4.0


@pytest.mark.os_agnostic
def test_loss_counts_packets_rather_than_pattern_matches() -> None:
    # The pre-1.0 implementation set this to the number of regex matches found
    # in the system ping output, which was never a packet count.
    result = _reply(1.0, None, None, 4.0)

    assert result.packets_sent == 4
    assert result.packets_received == 2
    assert result.n_packets_lost == 2
    assert result.packets_lost_percentage == 50


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ((1.0, 1.0, 1.0), 0),
        ((1.0, None, 1.0, None), 50),
        ((None, None), 100),
        ((1.0, None, None), 67),
    ],
)
def test_loss_percentage_rounds_the_way_the_old_output_did(pattern: tuple[float | None, ...], expected: int) -> None:
    assert _reply(*pattern).packets_lost_percentage == expected


@pytest.mark.os_agnostic
def test_sending_nothing_reads_as_total_loss_not_a_division_by_zero() -> None:
    result = ResponseObject(target="t", packets_sent=0)

    assert result.packets_lost_percentage == 100


@pytest.mark.os_agnostic
def test_jitter_needs_two_samples_before_it_means_anything() -> None:
    # One reply has no spread; reporting 0.0 would imply a measured stability
    # that was never observed.
    assert _reply(5.0).jitter_ms == -1.0
    assert _reply(None).jitter_ms == -1.0
    assert _reply(1.0, 3.0).jitter_ms == 1.0


@pytest.mark.os_agnostic
def test_a_result_cannot_be_edited_after_the_fact() -> None:
    result = _reply(1.0)

    with pytest.raises(dataclasses.FrozenInstanceError):
        result.reached = False  # type: ignore[misc]


@pytest.mark.os_agnostic
def test_a_result_records_which_protocol_answered() -> None:
    # A TCP handshake time is not comparable to an ICMP round trip, so the
    # result has to say which one produced it.
    icmp = _reply(1.0)
    tcp = dataclasses.replace(_reply(1.0), method=ProbeMethod.TCP)

    assert icmp.method is ProbeMethod.ICMP
    assert tcp.method is ProbeMethod.TCP


@pytest.mark.os_agnostic
def test_a_suppressed_error_is_reported_on_the_result() -> None:
    result = ResponseObject(target="t", error="unprivileged ICMP unavailable")

    assert result.reached is False
    assert result.error == "unprivileged ICMP unavailable"


@pytest.mark.os_agnostic
def test_a_mac_answer_states_whose_mac_it_is() -> None:
    # The whole reason MacLookup exists: a routed address can only ever yield
    # the next-hop router's MAC, and a bare string could not say so.
    far = MacLookup(ip="8.8.8.8", mac="aa:bb:cc:dd:ee:ff", scope=MacScope.NEXT_HOP, via_ip="192.168.1.1")
    near = MacLookup(ip="192.168.1.5", mac="11:22:33:44:55:66", scope=MacScope.DIRECT)

    assert far.scope is MacScope.NEXT_HOP
    assert far.via_ip == "192.168.1.1"
    assert near.scope is MacScope.DIRECT
    assert near.via_ip is None


@pytest.mark.os_agnostic
def test_an_unanswerable_mac_question_is_its_own_state() -> None:
    unknown = MacLookup(ip="203.0.113.9")

    assert unknown.scope is MacScope.UNKNOWN
    assert unknown.mac is None


@pytest.mark.os_agnostic
def test_results_serialise_for_the_cli_json_output() -> None:
    payload = dataclasses.asdict(_reply(1.0, 2.0))

    assert payload["target"] == "example.test"
    assert payload["rtts_ms"] == (1.0, 2.0)
    assert payload["family"] is AddressFamily.IPV4
