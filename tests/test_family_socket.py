"""A TCP probe connects over the family it was given, sync and async alike.

Real loopback sockets, no mocks: a listener on 127.0.0.1 answers any probe
that is allowed to reach it, so a probe told it is IPv6 can only miss it by
actually opening an IPv6 connection.
"""

from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING

import pytest

from ipscout.models import AddressFamily
from ipscout.transport_tcp import AsyncTcpEchoTransport, TcpEchoTransport

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.os_agnostic


@pytest.fixture
def ipv4_listener_port() -> Iterator[int]:
    """Bind a real IPv4 listener on an ephemeral loopback port."""

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    try:
        yield int(listener.getsockname()[1])
    finally:
        listener.close()


def test_the_sync_probe_reaches_an_ipv4_listener_over_ipv4(ipv4_listener_port: int) -> None:
    with TcpEchoTransport("127.0.0.1", AddressFamily.IPV4, port=ipv4_listener_port) as transport:
        assert transport.probe(sequence=1, timeout=2.0).answered is True


def test_the_sync_probe_does_not_reach_an_ipv4_listener_over_ipv6(ipv4_listener_port: int) -> None:
    with TcpEchoTransport("127.0.0.1", AddressFamily.IPV6, port=ipv4_listener_port) as transport:
        assert transport.probe(sequence=1, timeout=2.0).answered is False


def test_the_async_probe_reaches_an_ipv4_listener_over_ipv4(ipv4_listener_port: int) -> None:
    transport = AsyncTcpEchoTransport("127.0.0.1", AddressFamily.IPV4, port=ipv4_listener_port)

    assert asyncio.run(transport.probe(sequence=1, timeout=2.0)).answered is True


def test_the_async_probe_does_not_reach_an_ipv4_listener_over_ipv6(ipv4_listener_port: int) -> None:
    # Without the family the resolver picks IPv4 for this literal and the
    # connect succeeds, silently answering a question nobody asked.
    transport = AsyncTcpEchoTransport("127.0.0.1", AddressFamily.IPV6, port=ipv4_listener_port)

    assert asyncio.run(transport.probe(sequence=1, timeout=2.0)).answered is False


# An IPv6 socket that accepts IPv4-mapped destinations carries IPv4 traffic:
# Linux and macOS allow it by default, and Python 3.15 on macOS maps a plain
# IPv4 literal there too. Either way an "IPv6" answer would come from IPv4.
IPV4_MAPPED_LOOPBACK = "::ffff:127.0.0.1"


def test_the_sync_probe_does_not_reach_an_ipv4_listener_through_an_ipv4_mapped_address(ipv4_listener_port: int) -> None:
    with TcpEchoTransport(IPV4_MAPPED_LOOPBACK, AddressFamily.IPV6, port=ipv4_listener_port) as transport:
        assert transport.probe(sequence=1, timeout=2.0).answered is False


def test_the_async_probe_does_not_reach_an_ipv4_listener_through_an_ipv4_mapped_address(ipv4_listener_port: int) -> None:
    transport = AsyncTcpEchoTransport(IPV4_MAPPED_LOOPBACK, AddressFamily.IPV6, port=ipv4_listener_port)

    assert asyncio.run(transport.probe(sequence=1, timeout=2.0)).answered is False


@pytest.fixture
def ipv6_listener_port() -> Iterator[int]:
    """Bind a real IPv6 listener on an ephemeral loopback port."""

    listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.bind(("::1", 0))
    listener.listen(8)
    try:
        yield int(listener.getsockname()[1])
    finally:
        listener.close()


def test_the_sync_probe_still_reaches_an_ipv6_listener_over_ipv6(ipv6_listener_port: int) -> None:
    with TcpEchoTransport("::1", AddressFamily.IPV6, port=ipv6_listener_port) as transport:
        assert transport.probe(sequence=1, timeout=2.0).answered is True


def test_the_async_probe_still_reaches_an_ipv6_listener_over_ipv6(ipv6_listener_port: int) -> None:
    transport = AsyncTcpEchoTransport("::1", AddressFamily.IPV6, port=ipv6_listener_port)

    assert asyncio.run(transport.probe(sequence=1, timeout=2.0)).answered is True
