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
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from .models import MAX_PORT, MIN_PORT, AddressFamily, ProbeMethod, ResponseObject
from .packet import DEFAULT_PAYLOAD_SIZE
from .transport_tcp import DEFAULT_TCP_PORT

if TYPE_CHECKING:
    from .ports import AsyncEchoTransport, EchoResult, EchoTransport

__all__ = ["DEFAULT_INTERVAL", "DEFAULT_TIMEOUT", "DEFAULT_TIMES", "PingRequest", "arun_ping", "run_ping"]

#: Default echoes per ping, the count Windows ping sends unasked.
DEFAULT_TIMES = 4

#: Default seconds to wait for each reply.
DEFAULT_TIMEOUT = 2.0

#: Default seconds between the start of consecutive echoes.
DEFAULT_INTERVAL = 0.2


class PingRequest(BaseModel):
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
        payload_size: Bytes of ICMP payload per echo. Ignored by the TCP transport.
        tcp_port: Port the TCP transport connects to. Ignored by ICMP.
        method: Which protocol the chosen transport represents.

    Raises:
        pydantic.ValidationError: ``times`` below 1, ``timeout`` not positive,
            ``interval`` negative, or ``tcp_port`` outside 1-65535. These
            are caller mistakes, not network conditions, so they raise
            regardless of ``raise_on_error``. The bounds live on the fields
            rather than in a hand-written check, so the constraint and the
            documentation cannot drift apart.

    Examples:
        >>> PingRequest(target="t", address="127.0.0.1", family=AddressFamily.IPV4).times
        4
        >>> PingRequest(target="t", address="127.0.0.1", family=AddressFamily.IPV4, times=0)
        Traceback (most recent call last):
        ...
        pydantic_core._pydantic_core.ValidationError: ...

    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    target: str
    address: str
    family: AddressFamily
    times: int = Field(default=DEFAULT_TIMES, ge=1, description="Echoes to send; fewer than one describes no probe at all.")
    timeout: float = Field(default=DEFAULT_TIMEOUT, gt=0, description="Seconds to wait per reply; zero would never wait.")
    interval: float = Field(default=DEFAULT_INTERVAL, ge=0, description="Seconds between echoes; negative is meaningless.")
    payload_size: int = Field(default=DEFAULT_PAYLOAD_SIZE, description="Bytes of ICMP payload per echo; the packet builder raises it to its minimum.")
    tcp_port: int = Field(default=DEFAULT_TCP_PORT, ge=MIN_PORT, le=MAX_PORT, description="Port for the TCP transport; outside 1-65535 no connect can be made.")
    method: ProbeMethod = ProbeMethod.ICMP


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
