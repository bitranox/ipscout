"""Traceroute stories: hop assembly, termination, and an honest refusal.

The hop-walking logic is driven through the transport seam, so it is exercised
identically on every platform. The one live test walks loopback, where the
target answers at hop 1.
"""

from __future__ import annotations

import asyncio
import sys
from typing import TYPE_CHECKING

import pytest

import ipscout
from ipscout.errors import IPScoutUnsupportedError
from ipscout.models import AddressFamily
from ipscout.ports import EchoResult
from ipscout.traceroute import atrace_path, trace_path
from ipscout.transport_posix import PosixEchoTransport
from ipscout.transport_tcp import TcpEchoTransport

if TYPE_CHECKING:
    from types import TracebackType

pytestmark = pytest.mark.os_agnostic


class ScriptedPath:
    """Answers each hop from a fixed map of ttl to outcome."""

    def __init__(self, hops: dict[int, EchoResult], *, discovery: bool = True) -> None:
        self._hops = hops
        self._discovery = discovery
        self.probed: list[int | None] = []

    supports_ttl = True

    @property
    def supports_ttl_discovery(self) -> bool:
        return self._discovery

    def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:
        del sequence, timeout
        self.probed.append(ttl)
        return self._hops.get(ttl or 0, EchoResult())

    def close(self) -> None:
        return None

    def __enter__(self) -> ScriptedPath:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None


class AsyncScriptedPath(ScriptedPath):
    """The same script, awaited."""

    async def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:  # type: ignore[override]
        return ScriptedPath.probe(self, sequence=sequence, timeout=timeout, ttl=ttl)

    async def aclose(self) -> None:
        return None

    async def __aenter__(self) -> AsyncScriptedPath:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None


def _router(address: str, rtt: float) -> EchoResult:
    return EchoResult(rtt_ms=rtt, source=address, ttl_expired=True)


def _target(address: str, rtt: float) -> EchoResult:
    return EchoResult(rtt_ms=rtt, source=address)


def test_a_path_is_reported_hop_by_hop_and_stops_at_the_target() -> None:
    path = ScriptedPath(
        {
            1: _router("10.0.0.1", 1.0),
            2: _router("10.0.1.1", 5.0),
            3: _target("93.184.216.34", 9.0),
            4: _target("should.never.be.probed", 1.0),
        }
    )

    hops = trace_path(path, max_hops=10)

    assert [hop.ttl for hop in hops] == [1, 2, 3]
    assert [hop.address for hop in hops] == ["10.0.0.1", "10.0.1.1", "93.184.216.34"]
    assert [hop.reached for hop in hops] == [False, False, True]
    # The walk must stop rather than probe past the target.
    assert path.probed == [1, 2, 3]


def test_a_silent_hop_is_recorded_rather_than_dropped() -> None:
    # A firewall ignoring one hop in the middle of a complete path is
    # information; collapsing it would misnumber every hop after it.
    path = ScriptedPath({1: _router("10.0.0.1", 1.0), 3: _target("10.0.9.9", 3.0)})

    hops = trace_path(path, max_hops=10)

    assert [hop.ttl for hop in hops] == [1, 2, 3]
    assert hops[1].address is None
    assert hops[1].rtt_ms is None
    assert hops[1].reached is False


def test_a_path_that_never_terminates_stops_at_the_hop_limit() -> None:
    hops = trace_path(ScriptedPath({}), max_hops=5)

    assert len(hops) == 5
    assert all(hop.address is None for hop in hops)


def test_the_hop_limit_is_the_ttl_that_was_actually_sent() -> None:
    path = ScriptedPath({4: _target("10.0.0.4", 1.0)})

    trace_path(path, max_hops=6)

    assert path.probed == [1, 2, 3, 4]


@pytest.mark.parametrize("bad", [0, -1, -30])
def test_a_nonsense_hop_limit_is_refused(bad: int) -> None:
    with pytest.raises(ValueError, match="max_hops"):
        trace_path(ScriptedPath({}), max_hops=bad)


def test_a_transport_that_cannot_observe_expiry_is_refused_with_a_reason() -> None:
    # This is the macOS path, reached through the capability rather than
    # through a platform string, so it is testable on every OS.
    with pytest.raises(IPScoutUnsupportedError, match="Time Exceeded"):
        trace_path(ScriptedPath({}, discovery=False))


def test_the_refusal_names_the_platforms_that_do_work() -> None:
    with pytest.raises(IPScoutUnsupportedError) as caught:
        trace_path(ScriptedPath({}, discovery=False))

    message = str(caught.value)
    assert "macOS" in message
    assert "Linux" in message
    assert "Windows" in message


def test_the_tcp_probe_declines_to_pretend_it_can_trace() -> None:
    # It has no hop limit to set, so every hop would report the same endpoint.
    with pytest.raises(IPScoutUnsupportedError):
        trace_path(TcpEchoTransport("127.0.0.1", AddressFamily.IPV4))


def test_reverse_names_are_looked_up_only_when_asked() -> None:
    path = ScriptedPath({1: _target("127.0.0.1", 1.0)})

    without = trace_path(path, max_hops=2)
    with_names = trace_path(ScriptedPath({1: _target("127.0.0.1", 1.0)}), max_hops=2, resolve_names=True)

    assert without[0].hostname is None
    assert with_names[0].hostname is not None


def test_the_async_walk_agrees_with_the_sync_one() -> None:
    script = {1: _router("10.0.0.1", 1.0), 2: _target("10.0.0.9", 2.0)}

    sync_hops = trace_path(ScriptedPath(dict(script)), max_hops=5)
    async_hops = asyncio.run(atrace_path(AsyncScriptedPath(dict(script)), max_hops=5))

    assert [(h.ttl, h.address, h.reached) for h in sync_hops] == [(h.ttl, h.address, h.reached) for h in async_hops]


def test_the_async_walk_refuses_a_transport_that_cannot_observe_expiry() -> None:
    with pytest.raises(IPScoutUnsupportedError):
        asyncio.run(atrace_path(AsyncScriptedPath({}, discovery=False)))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX socket path; Windows uses iphlpapi")
def test_the_posix_transport_reports_whether_it_can_observe_expiry() -> None:
    # True on Linux via IP_RECVERR, False on macOS, which has no error queue.
    if not ipscout.icmp_available():
        pytest.skip("unprivileged ICMP unavailable on this host")

    with PosixEchoTransport("127.0.0.1", AddressFamily.IPV4) as transport:
        expected = sys.platform.startswith("linux")
        assert transport.supports_ttl_discovery is expected


def test_tracing_loopback_reaches_the_target_at_the_first_hop() -> None:
    if not ipscout.icmp_available():
        pytest.skip("unprivileged ICMP unavailable on this host")
    if not sys.platform.startswith(("linux", "win32")):
        pytest.skip("this platform cannot observe TTL expiry, so traceroute is unsupported by design")

    hops = ipscout.traceroute("127.0.0.1", max_hops=4, timeout=1.0)

    assert len(hops) == 1
    assert hops[0].reached is True
    assert hops[0].address == "127.0.0.1"


def test_traceroute_refuses_an_unresolvable_target() -> None:
    with pytest.raises(ipscout.IPScoutResolutionError):
        ipscout.traceroute("nothing.invalid", max_hops=2)
