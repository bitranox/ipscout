"""Service-layer stories, driven by a real in-process transport double.

The fakes here are ordinary objects handed to ``run_ping``/``arun_ping`` through
their transport argument. Nothing is monkeypatched, because the seam is a
parameter rather than a module attribute - that is the whole reason
:mod:`ipscout.ports` exists.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from ipscout.errors import IPScoutPermissionError
from ipscout.models import AddressFamily, ProbeMethod
from ipscout.ports import EchoResult, EchoTransport
from ipscout.service import PingRequest, arun_ping, run_ping

if TYPE_CHECKING:
    from types import TracebackType


class ScriptedTransport:
    """Answers each probe from a fixed script of round-trip times."""

    def __init__(self, *rtts: float | None, supports_ttl: bool = True) -> None:
        self._rtts = list(rtts)
        self._supports_ttl = supports_ttl
        self.sequences: list[int] = []
        self.ttls: list[int | None] = []
        self.closed = False

    @property
    def supports_ttl(self) -> bool:
        return self._supports_ttl

    def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:
        del timeout
        self.sequences.append(sequence)
        self.ttls.append(ttl)
        rtt = self._rtts[sequence - 1] if sequence - 1 < len(self._rtts) else None
        return EchoResult(rtt_ms=rtt, source="10.0.0.1" if rtt is not None else None)

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> ScriptedTransport:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class AsyncScriptedTransport(ScriptedTransport):
    """The same script, awaited."""

    async def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:  # type: ignore[override]
        return ScriptedTransport.probe(self, sequence=sequence, timeout=timeout, ttl=ttl)

    async def aclose(self) -> None:
        self.close()

    async def __aenter__(self) -> AsyncScriptedTransport:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


class RefusingTransport:
    """Stands in for a machine where ICMP cannot be opened at all."""

    supports_ttl = True

    def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:
        del sequence, timeout, ttl
        msg = "unprivileged ICMP unavailable"
        raise IPScoutPermissionError(msg)

    def close(self) -> None:
        return None

    def __enter__(self) -> RefusingTransport:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None


def _request(**overrides: object) -> PingRequest:
    defaults: dict[str, object] = {
        "target": "example.test",
        "address": "10.0.0.1",
        "family": AddressFamily.IPV4,
        "times": 3,
        "interval": 0.0,
    }
    defaults.update(overrides)
    return PingRequest(**defaults)  # type: ignore[arg-type]


@pytest.mark.os_agnostic
def test_the_doubles_satisfy_the_declared_protocol() -> None:
    # If this fails, the tests below prove nothing about the real transports.
    assert isinstance(ScriptedTransport(), EchoTransport)
    assert isinstance(RefusingTransport(), EchoTransport)


@pytest.mark.os_agnostic
def test_every_reply_is_folded_into_the_summary() -> None:
    result = run_ping(_request(), ScriptedTransport(1.0, 2.0, 3.0))

    assert result.reached is True
    assert result.packets_sent == 3
    assert result.packets_received == 3
    assert result.time_avg_ms == 2.0
    assert result.method is ProbeMethod.ICMP


@pytest.mark.os_agnostic
def test_a_partial_loss_pattern_is_reported_exactly() -> None:
    result = run_ping(_request(), ScriptedTransport(1.0, None, 3.0))

    assert result.rtts_ms == (1.0, None, 3.0)
    assert result.n_packets_lost == 1
    assert result.packets_lost_percentage == 33
    assert result.reached is True


@pytest.mark.os_agnostic
def test_total_loss_is_an_answer_not_an_exception() -> None:
    # The core of the error contract: a silent host is a result.
    result = run_ping(_request(), ScriptedTransport(None, None, None))

    assert result.reached is False
    assert result.packets_lost_percentage == 100
    assert result.error is None


@pytest.mark.os_agnostic
def test_a_transport_that_cannot_probe_at_all_propagates() -> None:
    # Distinct from total loss: this machine cannot ask the question.
    with pytest.raises(IPScoutPermissionError):
        run_ping(_request(), RefusingTransport())


@pytest.mark.os_agnostic
def test_sequence_numbers_run_from_one_and_do_not_repeat() -> None:
    transport = ScriptedTransport(1.0, 1.0, 1.0)

    run_ping(_request(times=3), transport)

    assert transport.sequences == [1, 2, 3]


@pytest.mark.os_agnostic
def test_the_result_reports_what_the_caller_asked_for_not_what_arrived() -> None:
    result = run_ping(_request(times=3), ScriptedTransport(1.0, None, None))

    assert result.number_of_pings == 3
    assert result.target == "example.test"
    assert result.ip == "10.0.0.1"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("bad", [{"times": 0}, {"times": -1}, {"timeout": 0}, {"timeout": -1.0}, {"interval": -0.1}])
def test_nonsense_parameters_are_rejected_before_any_packet_moves(bad: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="must"):
        _request(**bad)


@pytest.mark.os_agnostic
def test_a_single_echo_is_a_legitimate_request() -> None:
    result = run_ping(_request(times=1), ScriptedTransport(5.0))

    assert result.packets_sent == 1
    assert result.time_avg_ms == 5.0
    assert result.jitter_ms == -1.0


@pytest.mark.os_agnostic
def test_pacing_does_not_accumulate_delay_across_echoes() -> None:
    # Paced against the run's start, so a slow reply cannot push every later
    # echo progressively later.
    import time

    started = time.perf_counter()
    run_ping(_request(times=4, interval=0.05), ScriptedTransport(1.0, 1.0, 1.0, 1.0))
    elapsed = time.perf_counter() - started

    # Three gaps of 50ms between four echoes, with generous slack for CI.
    assert 0.10 <= elapsed < 0.60


@pytest.mark.os_agnostic
def test_the_async_path_produces_the_same_summary_as_the_sync_one() -> None:
    sync_result = run_ping(_request(), ScriptedTransport(1.0, None, 3.0))
    async_result = asyncio.run(arun_ping(_request(), AsyncScriptedTransport(1.0, None, 3.0)))

    assert sync_result.rtts_ms == async_result.rtts_ms
    assert sync_result.packets_lost_percentage == async_result.packets_lost_percentage
    assert sync_result.reached == async_result.reached


@pytest.mark.os_agnostic
def test_a_tcp_flavoured_request_is_labelled_as_such() -> None:
    result = run_ping(_request(method=ProbeMethod.TCP), ScriptedTransport(1.0, 1.0, 1.0))

    assert result.method is ProbeMethod.TCP
