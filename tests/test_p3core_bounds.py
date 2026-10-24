"""One refusal per bound, worded the same wherever the bound is checked.

Three bounds, each a caller mistake rather than a network condition:

* A port outside 1-65535 names nothing on a remote host. Every record carrying
  a port, and the ping request's TCP port, refuse it with the words the
  port-list parser uses, so a reader meets one message for one mistake.
* An ICMP payload above the protocol maximum for its family cannot be sent at
  all: the IP length field has no room for it. Sending it anyway made the send
  fail and a live host read as unreachable, so the request refuses it up front.
  A small or negative payload stays accepted: the packet builder raises it to
  its minimum.
* A CLI default for a knob the library already names is that constant, never a
  second literal.
"""

from __future__ import annotations

import asyncio
import sys
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

import ipscout
from ipscout import cli
from ipscout.api import DEFAULT_CONCURRENCY as PING_DEFAULT_CONCURRENCY
from ipscout.models import MAX_PORT, MIN_PORT, AddressFamily, Banner, BannerState, PortResult, PortState, WakeReport
from ipscout.packet import MAX_PAYLOAD_SIZE_IPV4, MAX_PAYLOAD_SIZE_IPV6
from ipscout.portscan import DEFAULT_CONCURRENCY as PORTSCAN_DEFAULT_CONCURRENCY
from ipscout.scan import DEFAULT_CONCURRENCY as SWEEP_DEFAULT_CONCURRENCY
from ipscout.service import DEFAULT_TIMEOUT, PingRequest
from ipscout.traceroute import DEFAULT_MAX_HOPS
from ipscout.wol import DEFAULT_PORT as WAKE_DEFAULT_PORT

if TYPE_CHECKING:
    from collections.abc import Callable

    import rich_click as click

pytestmark = pytest.mark.os_agnostic

_OUT_OF_RANGE = [MIN_PORT - 1, MAX_PORT + 1]


def _port_result(port: int) -> object:
    return PortResult(port=port, state=PortState.OPEN)


def _banner(port: int) -> object:
    return Banner(host="h.test", port=port, state=BannerState.REFUSED)


def _wake_report(port: int) -> object:
    return WakeReport(mac="aa:bb:cc:dd:ee:ff", broadcast="192.0.2.255", port=port)


def _ping_request(port: int) -> object:
    return PingRequest(target="t", address="127.0.0.1", family=AddressFamily.IPV4, tcp_port=port)


_PORT_CARRIERS: list[Callable[[int], object]] = [_port_result, _banner, _wake_report, _ping_request]


@pytest.mark.parametrize("build", _PORT_CARRIERS, ids=lambda f: f.__name__.lstrip("_"))
@pytest.mark.parametrize("port", _OUT_OF_RANGE)
def test_every_port_carrier_refuses_with_the_port_parser_s_words(build: Callable[[int], object], port: int) -> None:
    with pytest.raises(ValidationError, match=rf"port out of range 1-65535: {port}"):
        build(port)


@pytest.mark.parametrize("build", _PORT_CARRIERS, ids=lambda f: f.__name__.lstrip("_"))
@pytest.mark.parametrize("port", [MIN_PORT, MAX_PORT])
def test_every_port_carrier_accepts_the_edges_of_the_range(build: Callable[[int], object], port: int) -> None:
    assert build(port) is not None


def test_ping_names_the_field_and_the_range_when_it_refuses_a_port() -> None:
    with pytest.raises(ValueError, match=r"tcp_port\n.*port out of range 1-65535: 0"):
        ipscout.ping("127.0.0.1", 1, interval=0, tcp_port=0)


_OVERSIZED = [("127.0.0.1", MAX_PAYLOAD_SIZE_IPV4 + 1), ("::1", MAX_PAYLOAD_SIZE_IPV6 + 1)]


def test_the_payload_maxima_are_the_protocol_maxima() -> None:
    # 65535 less the 20-byte IPv4 header and the 8-byte ICMP header; IPv6's
    # payload length excludes its own fixed header, so only ICMP's 8 come off.
    assert (MAX_PAYLOAD_SIZE_IPV4, MAX_PAYLOAD_SIZE_IPV6) == (65507, 65527)


@pytest.mark.parametrize(("target", "size"), _OVERSIZED)
def test_an_unsendable_payload_raises_instead_of_reading_as_a_dead_host(target: str, size: int) -> None:
    with pytest.raises(ValueError, match=rf"payload_size .*{size}"):
        ipscout.ping(target, 1, interval=0, timeout=0.5, payload_size=size)


@pytest.mark.parametrize(("target", "size"), _OVERSIZED)
def test_the_awaitable_ping_refuses_the_same_payload(target: str, size: int) -> None:
    with pytest.raises(ValueError, match=rf"payload_size .*{size}"):
        asyncio.run(ipscout.aping(target, 1, interval=0, timeout=0.5, payload_size=size))


@pytest.mark.parametrize(
    ("family", "size"),
    [
        (AddressFamily.IPV4, MAX_PAYLOAD_SIZE_IPV4),
        (AddressFamily.IPV6, MAX_PAYLOAD_SIZE_IPV6),
        # The bound is per family: a size only IPv4 cannot carry is fine for IPv6.
        (AddressFamily.IPV6, MAX_PAYLOAD_SIZE_IPV4 + 1),
        # Small and negative sizes are raised to the minimum by the packet builder.
        (AddressFamily.IPV4, 0),
        (AddressFamily.IPV4, -5),
    ],
)
def test_a_sendable_payload_still_passes_validation(family: AddressFamily, size: int) -> None:
    address = "::1" if family is AddressFamily.IPV6 else "127.0.0.1"
    assert PingRequest(target="t", address=address, family=family, payload_size=size).payload_size == size


@pytest.mark.skipif(sys.platform != "linux", reason="the maxima were measured on Linux; other kernels may cap ICMP datagrams lower")
@pytest.mark.parametrize(
    ("target", "family", "size"), [("127.0.0.1", AddressFamily.IPV4, MAX_PAYLOAD_SIZE_IPV4), ("::1", AddressFamily.IPV6, MAX_PAYLOAD_SIZE_IPV6)]
)
def test_the_largest_accepted_payload_really_reaches_loopback(target: str, family: AddressFamily, size: int) -> None:
    # Liveness for the bound: the maximum the request accepts is one the
    # kernel actually sends, so the refusal above takes away nothing usable.
    if not ipscout.icmp_available(family):
        pytest.skip(f"no {family.value} ICMP socket on this host")
    assert ipscout.ping(target, 1, interval=0, timeout=1.0, payload_size=size).reached is True


def _option_default(command: click.Command, name: str) -> object:
    return next(param.default for param in command.params if param.name == name)


@pytest.mark.parametrize(
    ("command", "name", "expected"),
    [
        (cli.cli_ping_many, "concurrency", PING_DEFAULT_CONCURRENCY),
        (cli.cli_arp_scan, "concurrency", SWEEP_DEFAULT_CONCURRENCY),
        (cli.cli_scan_ports, "concurrency", PORTSCAN_DEFAULT_CONCURRENCY),
        (cli.cli_wake, "port", WAKE_DEFAULT_PORT),
        (cli.cli_traceroute, "max_hops", DEFAULT_MAX_HOPS),
        (cli.cli_traceroute, "timeout", DEFAULT_TIMEOUT),
    ],
    ids=["ping-many", "arp-scan", "scan-ports", "wake", "traceroute-max-hops", "traceroute-timeout"],
)
def test_a_cli_default_is_the_library_constant(command: click.Command, name: str, expected: object) -> None:
    assert _option_default(command, name) == expected
