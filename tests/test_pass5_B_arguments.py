"""Caller mistakes the many-host, traceroute and port-scan entry points refuse up front.

Each test passes a value no caller means - one bare string where a collection
of hosts belongs, a float or a bool where an ``int`` belongs, a string where a
member belongs - and asserts it is refused as a ``ValueError`` in the
``<operation> refused its arguments: <argument>: <reason>`` shape, before any
host is taken from an iterable and before anything is sent. Before these
checks existed, every one of these calls ran and returned a plausible result.

Where the old behaviour would have probed something, the value is chosen so
that it could only ever have reached this machine: ``"0"`` is ``0.0.0.0``,
which Linux and macOS route to loopback, and the ports are on 127.0.0.1.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

import ipscout
from ipscout.models import DISCARD_PORT
from ipscout.ports import EchoResult
from ipscout.portscan import ascan_ports, scan_ports, syn_scan
from ipscout.traceroute import atrace_path, atraceroute, trace_path, traceroute

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import TracebackType


def _untyped(value: object) -> Any:
    """Return ``value`` typed as ``Any``, as a caller without a type checker would pass it."""

    return value


class _Recorder:
    """An iterator of hosts that records whether anything was ever taken from it."""

    def __init__(self) -> None:
        self.taken = False

    def __iter__(self) -> Iterator[str]:
        return self

    def __next__(self) -> str:
        self.taken = True
        raise StopIteration


# --------------------------------------------------------------------------
# one bare string where a collection of hosts belongs
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_banner_grab_refuses_one_bare_string_as_its_hosts() -> None:
    with pytest.raises(ValueError, match=r"^banner grab refused its arguments: hosts: one string is a single host"):
        ipscout.grab_banners("0", DISCARD_PORT, timeout=0.5)


@pytest.mark.os_agnostic
def test_the_awaitable_banner_grab_refuses_it_too() -> None:
    with pytest.raises(ValueError, match=r"^banner grab refused its arguments: hosts: one string is a single host"):
        asyncio.run(ipscout.agrab_banners("0", DISCARD_PORT, timeout=0.5))


@pytest.mark.os_agnostic
def test_a_banner_grab_refuses_a_host_that_is_not_a_string() -> None:
    with pytest.raises(ValueError, match=r"^banner grab refused its arguments: hosts: 1: Input should be a valid string"):
        ipscout.grab_banners(["0", _untyped(0)], DISCARD_PORT, timeout=0.5)


@pytest.mark.os_agnostic
def test_a_ping_sweep_refuses_one_bare_string_as_its_targets() -> None:
    with pytest.raises(ValueError, match=r"^ping sweep refused its arguments: targets: one string is a single host"):
        ipscout.ping_many("0", times=1, timeout=0.5)


@pytest.mark.os_agnostic
def test_the_awaitable_ping_sweep_refuses_it_too() -> None:
    with pytest.raises(ValueError, match=r"^ping sweep refused its arguments: targets: one string is a single host"):
        asyncio.run(ipscout.aping_many("0", times=1, timeout=0.5))


@pytest.mark.os_agnostic
def test_a_ping_sweep_still_takes_any_collection_or_iterator_of_names() -> None:
    results = ipscout.ping_many(name for name in ("127.0.0.1", "127.0.0.1"))

    assert list(results) == ["127.0.0.1"]


# --------------------------------------------------------------------------
# sweep-wide arguments are checked before any target is taken
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("concurrency", "reason"),
    [(0, "concurrency must be at least 1, got 0"), (_untyped(True), "Input should be a valid integer")],
)
def test_a_ping_sweep_refuses_a_bad_concurrency_before_taking_any_target(concurrency: int, reason: str) -> None:
    targets = _Recorder()

    with pytest.raises(ValueError, match=rf"^ping sweep refused its arguments: concurrency: {reason}$"):
        ipscout.ping_many(targets, concurrency=concurrency)
    assert targets.taken is False


@pytest.mark.os_agnostic
def test_the_awaitable_ping_sweep_checks_concurrency_before_taking_any_target_too() -> None:
    targets = _Recorder()

    with pytest.raises(ValueError, match=r"^ping sweep refused its arguments: concurrency: concurrency must be at least 1, got 0$"):
        asyncio.run(ipscout.aping_many(targets, concurrency=0, raise_on_error=False))
    assert targets.taken is False


# --------------------------------------------------------------------------
# traceroute
# --------------------------------------------------------------------------


class _Target:
    """Answers every hop as the target itself, and counts the probes it was asked for."""

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

    def __enter__(self) -> _Target:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()


class _AsyncTarget:
    """The same target behind the awaitable transport protocol."""

    supports_ttl = True
    supports_ttl_discovery = True

    def __init__(self) -> None:
        self.probes = 0

    async def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:
        del sequence, timeout, ttl
        self.probes += 1
        return EchoResult(rtt_ms=1.0, source="192.0.2.9")

    async def aclose(self) -> None:
        """Nothing to release."""

    async def __aenter__(self) -> _AsyncTarget:
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        await self.aclose()


_NOT_A_HOP_LIMIT = [
    pytest.param(_untyped(3.0), "max_hops: Input should be a valid integer", id="float"),
    pytest.param(_untyped("5"), "max_hops: Input should be a valid integer", id="string"),
    pytest.param(_untyped(True), "max_hops: Input should be a valid integer", id="bool"),
]


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("max_hops", "reason"), _NOT_A_HOP_LIMIT)
def test_a_walk_refuses_a_hop_limit_that_is_not_an_int_before_any_probe(max_hops: int, reason: str) -> None:
    transport = _Target()

    with pytest.raises(ValueError, match=rf"^traceroute refused its arguments: {reason}$"):
        trace_path(transport, max_hops=max_hops)
    assert transport.probes == 0


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("max_hops", "reason"), _NOT_A_HOP_LIMIT)
def test_the_awaitable_walk_refuses_it_too(max_hops: int, reason: str) -> None:
    transport = _AsyncTarget()

    with pytest.raises(ValueError, match=rf"^traceroute refused its arguments: {reason}$"):
        asyncio.run(atrace_path(transport, max_hops=max_hops))
    assert transport.probes == 0


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        pytest.param({"timeout": _untyped(True)}, "timeout: Input should be a valid number", id="bool-timeout"),
        pytest.param({"timeout": _untyped("1")}, "timeout: Input should be a valid number", id="string-timeout"),
        pytest.param({"resolve_names": _untyped("no")}, "resolve_names: Input should be a valid boolean", id="string-resolve-names"),
    ],
)
def test_a_walk_refuses_a_timeout_or_switch_of_the_wrong_type(arguments: dict[str, Any], reason: str) -> None:
    transport = _Target()

    with pytest.raises(ValueError, match=rf"^traceroute refused its arguments: {reason}$"):
        trace_path(transport, **arguments)
    assert transport.probes == 0


@pytest.mark.os_agnostic
def test_a_traceroute_refuses_a_bad_argument_before_resolving_the_name() -> None:
    with pytest.raises(ValueError, match=r"^traceroute refused its arguments: max_hops: Input should be greater than or equal to 1$"):
        traceroute("nothing.invalid", max_hops=0)


@pytest.mark.os_agnostic
def test_the_awaitable_traceroute_refuses_it_before_resolving_too() -> None:
    with pytest.raises(ValueError, match=r"^traceroute refused its arguments: max_hops: Input should be greater than or equal to 1$"):
        asyncio.run(atraceroute("nothing.invalid", max_hops=0))


@pytest.mark.os_agnostic
def test_a_valid_walk_still_runs_to_the_target() -> None:
    hops = trace_path(_Target(), max_hops=3, timeout=1)

    assert [(hop.ttl, hop.reached) for hop in hops] == [(1, True)]


# --------------------------------------------------------------------------
# port lists and the scan method
# --------------------------------------------------------------------------

_NOT_A_PORT = [pytest.param(_untyped(True), id="bool"), pytest.param(_untyped(80.5), id="float"), pytest.param(_untyped("80"), id="string")]


@pytest.mark.os_agnostic
@pytest.mark.parametrize("port", _NOT_A_PORT)
def test_a_port_scan_refuses_a_listed_port_that_is_not_an_int(port: int) -> None:
    with pytest.raises(ValueError, match=r"^port scan refused its arguments: ports\.0: Input should be a valid integer$"):
        scan_ports("127.0.0.1", [port], timeout=0.2)


@pytest.mark.os_agnostic
@pytest.mark.parametrize("port", _NOT_A_PORT)
def test_the_awaitable_port_scan_refuses_it_too(port: int) -> None:
    with pytest.raises(ValueError, match=r"^port scan refused its arguments: ports\.0: Input should be a valid integer$"):
        asyncio.run(ascan_ports("127.0.0.1", [port], timeout=0.2))


@pytest.mark.os_agnostic
@pytest.mark.parametrize("port", _NOT_A_PORT)
def test_a_syn_scan_refuses_it_whatever_the_privileges(port: int) -> None:
    with pytest.raises(ValueError, match=r"^port scan refused its arguments: ports\.0: Input should be a valid integer$"):
        syn_scan("127.0.0.1", [port], timeout=0.2)


@pytest.mark.os_agnostic
def test_a_listed_port_out_of_range_is_named_by_its_position() -> None:
    with pytest.raises(ValueError, match=r"^port scan refused its arguments: ports\.1: port out of range 1-65535: 0$"):
        scan_ports("127.0.0.1", [1, 0], timeout=0.2)


@pytest.mark.os_agnostic
def test_a_tuple_of_ports_is_still_read_as_meant() -> None:
    assert list(scan_ports("127.0.0.1", _untyped((DISCARD_PORT, DISCARD_PORT)), timeout=0.2)) == [DISCARD_PORT]


@pytest.mark.os_agnostic
def test_a_port_scan_refuses_a_method_that_only_equals_a_member() -> None:
    with pytest.raises(ValueError, match=r"^port scan refused its arguments: method: Input should be an instance of ScanMethod$"):
        scan_ports("127.0.0.1", [DISCARD_PORT], method=_untyped("syn"), timeout=0.2)
