"""Sequences probes over a transport and aggregates them into a result.

This is where the probing policy lives - how many echoes, how far apart, what
counts as reached - kept separate from how any individual echo travels. It
depends only on the protocols in :mod:`ipscout.ports`, never on a concrete
backend, which is what lets a test drive it with an in-process fake on any
machine without patching a single module attribute.

Contents:
    PingRequest: The validated parameters of one ping.
    run_ping: Drive a synchronous transport and build the result.
    arun_ping: The same over asyncio.

"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .models import AddressFamily, ProbeMethod, ResponseObject

if TYPE_CHECKING:
    from .ports import AsyncEchoTransport, EchoResult, EchoTransport

__all__ = ["PingRequest", "arun_ping", "run_ping"]


@dataclass(frozen=True)
class PingRequest:
    """Validated parameters for one ping.

    Validation happens once, here, at construction. Every caller path -
    sync, async, single, sweep, CLI - goes through this, so an invalid
    argument is rejected identically everywhere and before any packet moves.

    Attributes:
        target: The target as the caller wrote it, carried through to the result.
        address: The resolved address actually probed.
        family: Address family of ``address``.
        times: How many echoes to send.
        timeout: Seconds to wait for each individual reply.
        interval: Seconds between the start of consecutive echoes.
        method: Which protocol the chosen transport represents.

    Raises:
        ValueError: ``times`` below 1, ``timeout`` not positive, or ``interval``
            negative. These are caller mistakes, not network conditions, so
            they raise regardless of the ``raise_on_error`` setting.

    Examples:
        >>> PingRequest(target="t", address="127.0.0.1", family=AddressFamily.IPV4).times
        4
        >>> PingRequest(target="t", address="127.0.0.1", family=AddressFamily.IPV4, times=0)
        Traceback (most recent call last):
        ...
        ValueError: times must be at least 1, got 0

    """

    target: str
    address: str
    family: AddressFamily
    times: int = 4
    timeout: float = 2.0
    interval: float = 0.2
    method: ProbeMethod = ProbeMethod.ICMP

    def __post_init__(self) -> None:
        """Reject parameters that cannot describe a meaningful probe."""

        if self.times < 1:
            msg = f"times must be at least 1, got {self.times}"
            raise ValueError(msg)
        if self.timeout <= 0:
            msg = f"timeout must be positive, got {self.timeout}"
            raise ValueError(msg)
        if self.interval < 0:
            msg = f"interval must not be negative, got {self.interval}"
            raise ValueError(msg)


def _build_response(request: PingRequest, results: list[EchoResult]) -> ResponseObject:
    """Fold a list of probe outcomes into the public result type."""

    rtts = tuple(result.rtt_ms for result in results)
    received = sum(1 for rtt in rtts if rtt is not None)
    return ResponseObject(
        target=request.target,
        reached=received > 0,
        ip=request.address,
        number_of_pings=request.times,
        rtts_ms=rtts,
        packets_sent=len(results),
        packets_received=received,
        family=request.family,
        method=request.method,
    )


def _pace(started: float, index: int, interval: float) -> float:
    """Return how long to sleep so echo ``index + 1`` starts on schedule.

    Paces against the run's start rather than sleeping a flat interval after
    each reply, so a slow reply does not push every later echo later. Never
    negative: a probe that already overran its slot simply sends immediately.
    """

    return max(0.0, started + (index + 1) * interval - time.perf_counter())


def run_ping(request: PingRequest, transport: EchoTransport) -> ResponseObject:
    """Send the requested echoes over ``transport`` and aggregate them.

    Args:
        request: Validated parameters.
        transport: The transport to probe with. Ownership stays with the
            caller, who is responsible for closing it.

    Returns:
        The aggregated result. Timeouts and total loss are reported here, not
        raised: a silent host is an answer.

    Examples:
        >>> from ipscout.ports import EchoResult
        >>> class AlwaysAnswers:
        ...     supports_ttl = True
        ...     def probe(self, *, sequence, timeout, ttl=None):
        ...         return EchoResult(rtt_ms=1.5, source="127.0.0.1")
        ...     def close(self): pass
        >>> request = PingRequest(target="t", address="127.0.0.1",
        ...                       family=AddressFamily.IPV4, times=3, interval=0)
        >>> result = run_ping(request, AlwaysAnswers())
        >>> result.reached, result.packets_received, result.time_avg_ms
        (True, 3, 1.5)

    """

    results: list[EchoResult] = []
    started = time.perf_counter()
    for index in range(request.times):
        results.append(transport.probe(sequence=index + 1, timeout=request.timeout))
        if index + 1 < request.times and request.interval > 0:
            time.sleep(_pace(started, index, request.interval))
    return _build_response(request, results)


async def arun_ping(request: PingRequest, transport: AsyncEchoTransport) -> ResponseObject:
    """Send the requested echoes over an async transport and aggregate them.

    Args:
        request: Validated parameters.
        transport: The transport to probe with. Ownership stays with the caller.

    Returns:
        The aggregated result.

    Note:
        Echoes within one target stay sequential and paced, exactly as in the
        synchronous path, so the two produce comparable timings. Concurrency
        belongs between targets, not between one target's own packets, where
        it would distort the round trips being measured.

    """

    results: list[EchoResult] = []
    started = time.perf_counter()
    for index in range(request.times):
        results.append(await transport.probe(sequence=index + 1, timeout=request.timeout))
        if index + 1 < request.times and request.interval > 0:
            await asyncio.sleep(_pace(started, index, request.interval))
    return _build_response(request, results)
