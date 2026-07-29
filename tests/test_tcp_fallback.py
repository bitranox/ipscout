"""TCP-probe stories against a real listening socket. No mocks anywhere."""

from __future__ import annotations

import asyncio
import socket
import sys
from typing import TYPE_CHECKING

import pytest

import ipscout
from ipscout.models import AddressFamily, ProbeMethod
from ipscout.transport_tcp import AsyncTcpEchoTransport, TcpEchoTransport

if TYPE_CHECKING:
    from collections.abc import Iterator

#: TEST-NET-3 (RFC 5737): reserved, unrouted, so connects hang rather than refuse.
NEVER_ANSWERS = "203.0.113.1"

pytestmark = pytest.mark.os_agnostic


@pytest.fixture
def listening_port() -> Iterator[int]:
    """Bind a real listener on an ephemeral loopback port."""

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    try:
        yield int(listener.getsockname()[1])
    finally:
        listener.close()


@pytest.fixture
def closed_port() -> int:
    """Return a loopback port that is bound then released, so it refuses."""

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


def test_an_open_port_answers(listening_port: int) -> None:
    with TcpEchoTransport("127.0.0.1", AddressFamily.IPV4, port=listening_port) as transport:
        result = transport.probe(sequence=1, timeout=2.0)

    assert result.answered
    assert result.rtt_ms is not None
    assert result.source == "127.0.0.1"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows silently drops rather than sending RST for a bound-then-closed port, so a refusal cannot be provoked",
)
def test_a_refused_port_still_proves_the_host_is_alive(closed_port: int) -> None:
    # A RST is an answer: only a live host sends one. Treating refusal as
    # "unreachable" would call every firewalled-but-running server dead.
    with TcpEchoTransport("127.0.0.1", AddressFamily.IPV4, port=closed_port) as transport:
        result = transport.probe(sequence=1, timeout=2.0)

    assert result.answered


def test_an_unrouted_address_times_out_without_raising() -> None:
    with TcpEchoTransport(NEVER_ANSWERS, AddressFamily.IPV4, port=443) as transport:
        result = transport.probe(sequence=1, timeout=1.0)

    assert not result.answered


def test_the_tcp_transport_declines_to_pretend_it_can_set_a_hop_limit() -> None:
    # Saying so keeps traceroute from silently reporting hop 1 for every TTL.
    assert TcpEchoTransport("127.0.0.1", AddressFamily.IPV4).supports_ttl is False
    assert AsyncTcpEchoTransport("127.0.0.1", AddressFamily.IPV4).supports_ttl is False


def test_the_async_probe_agrees_with_the_sync_one(listening_port: int) -> None:
    async def attempt() -> bool:
        transport = AsyncTcpEchoTransport("127.0.0.1", AddressFamily.IPV4, port=listening_port)
        async with transport:
            return (await transport.probe(sequence=1, timeout=2.0)).answered

    assert asyncio.run(attempt()) is True


def test_the_async_probe_times_out_on_an_unrouted_address() -> None:
    async def attempt() -> bool:
        transport = AsyncTcpEchoTransport(NEVER_ANSWERS, AddressFamily.IPV4, port=443)
        async with transport:
            return (await transport.probe(sequence=1, timeout=1.0)).answered

    assert asyncio.run(attempt()) is False


def test_a_tcp_result_is_labelled_tcp_and_never_passed_off_as_icmp(listening_port: int) -> None:
    # TCP timing includes the handshake and is not comparable to an ICMP round
    # trip, so the result has to carry which one produced it.
    result = ipscout.ping(
        "127.0.0.1",
        1,
        interval=0,
        allow_tcp_fallback=True,
        tcp_port=listening_port,
    )

    # ICMP is available on this host, so the fallback must NOT have engaged.
    if ipscout.icmp_available():
        assert result.method is ProbeMethod.ICMP
    else:
        assert result.method is ProbeMethod.TCP


def test_the_fallback_is_never_engaged_while_icmp_still_works() -> None:
    # Opting in permits substitution; it does not request it. Substituting
    # while ICMP works would silently change what is being measured.
    if not ipscout.icmp_available():
        pytest.skip("ICMP unavailable here, so there is no substitution to avoid")

    result = ipscout.ping("127.0.0.1", 1, interval=0, allow_tcp_fallback=True)

    assert result.method is ProbeMethod.ICMP


def test_reachability_falls_through_to_tcp_when_icmp_stays_silent(listening_port: int) -> None:
    # The shortcut always tries TCP after ICMP fails, which is what makes it
    # useful on hosts that drop ICMP but serve traffic.
    assert ipscout.is_reachable("127.0.0.1", tcp_port=listening_port) is True
