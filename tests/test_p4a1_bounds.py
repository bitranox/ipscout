"""Bounds on the ping request, the result records and the caller arguments.

Every record here refuses a value no producer in this library could make, and
every public entry point refuses a caller mistake before anything is sent and
in the caller's terms, never in pydantic's. Addresses are RFC 5737 / 3849
documentation addresses wherever nothing is sent, and loopback where it is.
"""

from __future__ import annotations

import asyncio
import math

import pytest
from pydantic import ValidationError

import ipscout
from ipscout.models import (
    MAX_HOP_LIMIT,
    MAX_PORT,
    MAX_TIMEOUT,
    MAX_TIMES,
    MIN_PORT,
    AddressFamily,
    Interface,
    InterfaceAddress,
    JsonEnvelope,
    JsonError,
    MtuReport,
    ObserveDhcpReport,
    ResponseObject,
    SubnetInfo,
    SweepScope,
    TraceHop,
)
from ipscout.pool import gather_bounded
from ipscout.ports import EchoResult
from ipscout.service import PingRequest
from ipscout.traceroute import trace_path

#: Text only pydantic's own rendering carries; none of it may reach a caller.
_PYDANTIC_TELLS = ("errors.pydantic.dev", "input_value", "validation error for", "type=")


def _request(**overrides: object) -> PingRequest:
    fields: dict[str, object] = {"target": "t", "address": "192.0.2.1", "family": AddressFamily.IPV4}
    fields.update(overrides)
    return PingRequest.model_validate(fields)


# --------------------------------------------------------------------------
# ping / aping: a refusal reads in the caller's terms, and keeps what is known
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_suppressed_argument_refusal_names_the_field_without_pydantic_s_text() -> None:
    result = ipscout.ping("127.0.0.1", 0, raise_on_error=False)

    assert result.error == "ping refused its arguments: times: Input should be greater than or equal to 1"
    assert not any(tell in result.error for tell in _PYDANTIC_TELLS)


@pytest.mark.os_agnostic
def test_a_raised_argument_refusal_names_the_field_and_keeps_pydantic_s_error_as_the_cause() -> None:
    with pytest.raises(ValueError, match="ping refused its arguments: times") as caught:
        ipscout.ping("127.0.0.1", 0)

    assert not any(tell in str(caught.value) for tell in _PYDANTIC_TELLS)
    assert isinstance(caught.value.__cause__, ValidationError)


@pytest.mark.os_agnostic
def test_the_awaitable_ping_suppresses_the_same_refusal_the_same_way() -> None:
    result = asyncio.run(ipscout.aping("127.0.0.1", 0, raise_on_error=False))

    assert result.error == "ping refused its arguments: times: Input should be greater than or equal to 1"


@pytest.mark.os_agnostic
def test_a_sweep_reports_a_refused_argument_on_each_target_in_the_caller_s_terms() -> None:
    results = ipscout.ping_many(["127.0.0.1"], times=0)

    error = results["127.0.0.1"].error
    assert error is not None
    assert not any(tell in error for tell in _PYDANTIC_TELLS)


@pytest.mark.os_agnostic
def test_a_suppressed_refusal_keeps_the_address_the_target_resolved_to() -> None:
    result = ipscout.ping("::1", 0, raise_on_error=False)

    assert (result.ip, result.family) == ("::1", AddressFamily.IPV6)
    assert (result.number_of_pings, result.packets_sent) == (0, 0)


@pytest.mark.os_agnostic
def test_an_unresolved_target_reports_the_requested_family_and_its_unspecified_address() -> None:
    result = ipscout.ping("nothing.invalid", family=AddressFamily.IPV6, raise_on_error=False)

    assert (result.ip, result.family) == ("::", AddressFamily.IPV6)
    assert result.reached is False


@pytest.mark.os_agnostic
def test_a_suppressed_failure_reports_that_nothing_was_sent() -> None:
    # "pinged 4 times" for a name that never resolved described echoes that
    # never left this host.
    result = ipscout.ping("nothing.invalid", 4, raise_on_error=False)

    assert result.number_of_pings == 0
    assert result.str_result.startswith("[0.0.0.0] pinged 0 times")


@pytest.mark.os_agnostic
def test_a_timeout_past_what_a_socket_can_carry_is_refused_before_anything_is_sent() -> None:
    # Measured before the bound: OverflowError from settimeout, mid-probe, and
    # past raise_on_error=False, which handles only refusals.
    with pytest.raises(ValueError, match="timeout"):
        ipscout.ping("127.0.0.1", 1, timeout=1e12)

    assert ipscout.ping("127.0.0.1", 1, timeout=1e12, raise_on_error=False).error is not None


# --------------------------------------------------------------------------
# concurrency
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize("concurrency", [0, -1])
def test_a_sweep_refuses_a_concurrency_below_one(concurrency: int) -> None:
    with pytest.raises(ValueError, match=f"concurrency must be at least 1, got {concurrency}"):
        ipscout.ping_many(["127.0.0.1"], times=1, concurrency=concurrency)


@pytest.mark.os_agnostic
def test_the_awaitable_sweep_refuses_it_too_whatever_raise_on_error_says() -> None:
    with pytest.raises(ValueError, match="concurrency must be at least 1, got 0"):
        asyncio.run(ipscout.aping_many(["127.0.0.1"], times=1, concurrency=0, raise_on_error=False))


@pytest.mark.os_agnostic
def test_the_pool_refuses_rather_than_silently_running_one_worker() -> None:
    async def echo(value: int) -> int:
        return value

    with pytest.raises(ValueError, match="concurrency must be at least 1"):
        asyncio.run(gather_bounded([1, 2], echo, 0))


# --------------------------------------------------------------------------
# PingRequest
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_negative_payload_size_is_refused_and_a_small_one_still_accepted() -> None:
    with pytest.raises(ValidationError, match="payload_size"):
        _request(payload_size=-1)

    assert _request(payload_size=0).payload_size == 0


@pytest.mark.os_agnostic
@pytest.mark.parametrize("target", ["", "   "])
def test_a_blank_target_is_refused(target: str) -> None:
    with pytest.raises(ValidationError, match="target must not be empty"):
        _request(target=target)


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("address", "family", "reason"),
    [
        ("2001:db8::1", AddressFamily.IPV4, "is not an ipv4 address"),
        ("192.0.2.1", AddressFamily.IPV6, "is not an ipv6 address"),
        ("example.test", AddressFamily.IPV4, "is not an IP address literal"),
        ("", AddressFamily.IPV4, "is not an IP address literal"),
    ],
)
def test_an_address_must_be_a_literal_of_the_request_s_family(address: str, family: AddressFamily, reason: str) -> None:
    with pytest.raises(ValidationError, match=reason):
        _request(address=address, family=family)


@pytest.mark.os_agnostic
def test_a_zoned_link_local_address_is_still_a_valid_request() -> None:
    assert _request(address="fe80::1%eth0", family=AddressFamily.IPV6).address == "fe80::1%eth0"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("timeout", [0.0, -1.0, math.inf, math.nan, MAX_TIMEOUT * 2])
def test_a_timeout_that_is_no_usable_wait_is_refused(timeout: float) -> None:
    with pytest.raises(ValidationError, match="timeout must be above 0"):
        _request(timeout=timeout)


@pytest.mark.os_agnostic
@pytest.mark.parametrize("interval", [-0.1, math.inf, math.nan, MAX_TIMEOUT * 2])
def test_an_interval_that_is_no_usable_pause_is_refused(interval: float) -> None:
    with pytest.raises(ValidationError, match="interval"):
        _request(interval=interval)


@pytest.mark.os_agnostic
def test_times_is_bounded_by_the_sequence_numbers_one_run_can_use() -> None:
    assert _request(times=MAX_TIMES).times == MAX_TIMES
    with pytest.raises(ValidationError, match="times"):
        _request(times=MAX_TIMES + 1)


@pytest.mark.os_agnostic
def test_the_port_description_states_the_range_the_check_enforces() -> None:
    description = PingRequest.model_fields["tcp_port"].description or ""

    assert f"{MIN_PORT}-{MAX_PORT}" in description


# --------------------------------------------------------------------------
# ResponseObject: the counts agree with each other, as every producer's do
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "fields",
    [
        {"number_of_pings": -1},
        {"number_of_pings": MAX_TIMES + 1, "packets_sent": MAX_TIMES + 1},
        {"number_of_pings": 2, "packets_sent": 1, "rtts_ms": (None,)},
        {"number_of_pings": 1, "packets_sent": 1, "rtts_ms": ()},
        {"number_of_pings": 1, "packets_sent": 1, "rtts_ms": (1.0,)},
        {"number_of_pings": 1, "packets_sent": 1, "rtts_ms": (None,), "packets_received": 1, "reached": True},
        {"number_of_pings": 1, "packets_sent": 1, "rtts_ms": (-1.0,), "packets_received": 1, "reached": True},
        {"number_of_pings": 1, "packets_sent": 1, "rtts_ms": (math.inf,), "packets_received": 1, "reached": True},
        {"reached": True},
        {"error": ""},
        {"error": "x", "number_of_pings": 1, "packets_sent": 1, "rtts_ms": (None,)},
        {"ip": "2001:db8::1"},
        {"ip": "example.test"},
        {"family": AddressFamily.IPV6},
    ],
)
def test_a_result_no_producer_could_make_is_refused(fields: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ResponseObject.model_validate({"target": "t", **fields})


@pytest.mark.os_agnostic
def test_a_result_keyed_by_a_blank_target_is_still_a_result() -> None:
    # The sweep echoes the caller's key back, a blank one included.
    results = ipscout.ping_many([""], times=1)

    assert results[""].target == ""
    assert results[""].error == "target must not be empty"


# --------------------------------------------------------------------------
# The other records
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize("ttl", [0, MAX_HOP_LIMIT + 1])
def test_a_hop_outside_the_one_byte_hop_limit_is_refused(ttl: int) -> None:
    with pytest.raises(ValidationError, match="ttl"):
        TraceHop(ttl=ttl)


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("address", "good", "bad"), [("192.0.2.1", 32, 33), ("2001:db8::1", 128, 129), ("fe80::1%eth0", 64, 129)])
def test_a_prefix_length_is_bounded_by_the_address_family(address: str, good: int, bad: int) -> None:
    assert InterfaceAddress(address=address, prefix_len=good).prefix_len == good
    with pytest.raises(ValidationError, match="prefix_len"):
        InterfaceAddress(address=address, prefix_len=bad)
    with pytest.raises(ValidationError, match="prefix_len"):
        InterfaceAddress(address=address, prefix_len=-1)


@pytest.mark.os_agnostic
def test_a_subnet_prefix_and_address_are_bounded_by_its_family() -> None:
    def subnet(address: str, prefix_len: int, family: AddressFamily) -> SubnetInfo:
        return SubnetInfo(interface="eth0", address=address, prefix_len=prefix_len, network="192.0.2.0/24", family=family)

    assert subnet("2001:db8::1", 64, AddressFamily.IPV6).prefix_len == 64
    with pytest.raises(ValidationError, match="prefix_len"):
        subnet("192.0.2.1", 64, AddressFamily.IPV4)
    with pytest.raises(ValidationError, match="is not an ipv4 address"):
        subnet("2001:db8::1", 24, AddressFamily.IPV4)


@pytest.mark.os_agnostic
def test_an_mtu_where_present_is_positive() -> None:
    with pytest.raises(ValidationError, match="mtu"):
        Interface(name="eth0", mtu=0)
    with pytest.raises(ValidationError, match="mtu"):
        MtuReport(target="t", mtu=0)
    with pytest.raises(ValidationError, match="mtu"):
        SubnetInfo(interface="eth0", address="192.0.2.1", prefix_len=24, network="192.0.2.0/24", mtu=-1)
    assert Interface(name="eth0").mtu is None


@pytest.mark.os_agnostic
def test_an_interface_index_starts_at_one() -> None:
    with pytest.raises(ValidationError, match="index"):
        Interface(name="eth0", index=0)


@pytest.mark.os_agnostic
def test_a_sweep_scope_needs_room_for_at_least_one_address() -> None:
    with pytest.raises(ValidationError, match="limit"):
        SweepScope(limit=0)


@pytest.mark.os_agnostic
def test_a_dhcp_report_window_is_positive_and_its_settle_not_negative() -> None:
    assert ObserveDhcpReport(mac="00:00:5e:00:53:01", timeout=1.0, settle=0.0).settle == 0.0
    with pytest.raises(ValidationError, match="timeout"):
        ObserveDhcpReport(mac="00:00:5e:00:53:01", timeout=0.0, settle=0.0)
    with pytest.raises(ValidationError, match="settle"):
        ObserveDhcpReport(mac="00:00:5e:00:53:01", timeout=1.0, settle=-1.0)


@pytest.mark.os_agnostic
def test_an_envelope_is_ok_exactly_when_it_carries_no_error() -> None:
    error = JsonError(type="ValueError", message="bad")

    with pytest.raises(ValidationError, match="ok is True exactly when error is None"):
        JsonEnvelope(ok=True, error=error)
    with pytest.raises(ValidationError, match="ok is True exactly when error is None"):
        JsonEnvelope(ok=False)
    assert JsonEnvelope(ok=False, error=error).error == error


@pytest.mark.os_agnostic
def test_an_envelope_is_still_frozen_and_strict_about_extra_keys() -> None:
    envelope = JsonEnvelope(ok=True)

    with pytest.raises(ValidationError):
        envelope.ok = False
    with pytest.raises(ValidationError):
        JsonEnvelope.model_validate({"ok": True, "unexpected": 1})


@pytest.mark.os_agnostic
@pytest.mark.parametrize("fields", [{"type": "", "message": "m"}, {"type": "T", "message": ""}])
def test_an_error_record_says_something(fields: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        JsonError.model_validate(fields)


# --------------------------------------------------------------------------
# traceroute
# --------------------------------------------------------------------------


class _CountingTransport:
    """Answers every hop as the target, and counts the probes it was asked for."""

    supports_ttl = True
    supports_ttl_discovery = True

    def __init__(self) -> None:
        self.probes = 0

    def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:
        del sequence, timeout, ttl
        self.probes += 1
        return EchoResult(rtt_ms=1.0, source="192.0.2.9")

    def close(self) -> None:
        """Nothing to release."""

    def __enter__(self) -> _CountingTransport:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


@pytest.mark.os_agnostic
def test_a_walk_past_the_largest_hop_limit_is_refused_before_any_probe() -> None:
    transport = _CountingTransport()

    with pytest.raises(ValueError, match=f"max_hops must be 1-{MAX_HOP_LIMIT}, got {MAX_HOP_LIMIT + 1}"):
        trace_path(transport, max_hops=MAX_HOP_LIMIT + 1)
    assert transport.probes == 0
    assert len(trace_path(transport, max_hops=MAX_HOP_LIMIT)) == 1


@pytest.mark.os_agnostic
@pytest.mark.parametrize("timeout", [0.0, -1.0, math.inf])
def test_a_walk_with_no_usable_wait_is_refused_rather_than_reported_as_silent_hops(timeout: float) -> None:
    transport = _CountingTransport()

    with pytest.raises(ValueError, match="timeout must be above 0"):
        trace_path(transport, timeout=timeout)
    assert transport.probes == 0


# --------------------------------------------------------------------------
# query_route
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("destination", "family", "reason"),
    [
        ("example.test", AddressFamily.IPV4, "is not an IP address literal"),
        ("999.1.1.1", AddressFamily.IPV4, "is not an IP address literal"),
        ("192.0.2.1%eth0", AddressFamily.IPV4, "is not an IP address literal"),
        ("::1", AddressFamily.IPV4, "is not an ipv4 address"),
        ("127.0.0.1", AddressFamily.IPV6, "is not an ipv6 address"),
    ],
)
def test_a_route_lookup_refuses_what_is_not_a_literal_of_its_family(destination: str, family: AddressFamily, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        ipscout.query_route(destination, family)


@pytest.mark.os_agnostic
def test_a_zoned_link_local_destination_is_still_looked_up() -> None:
    # Answered or not, a scoped literal is a valid question: reaching the end
    # without a refusal is the assertion.
    ipscout.query_route("fe80::1%1", AddressFamily.IPV6)
