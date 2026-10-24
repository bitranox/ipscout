"""Port-number bounds, wherever a port enters or leaves the library.

A port outside 1-65535 names nothing on a remote host: 0 asks the OS to pick
one, and anything above 16 bits does not fit the header. Every record that
carries a port refuses one, and every entry point that takes a list of ports
refuses one before anything is sent, with the same words the specification
parser uses.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from ipscout import ascan_ports, scan_ports
from ipscout.models import MAX_PORT, MIN_PORT, Banner, BannerState, PortResult, PortState, ScanMethod, WakeReport
from ipscout.portscan import parse_ports, syn_scan
from ipscout.wol import wake_on_lan

pytestmark = pytest.mark.os_agnostic

OUT_OF_RANGE = [MIN_PORT - 1, MAX_PORT + 1, -5, 70000]


def _port_result(port: int) -> PortResult:
    return PortResult(port=port, state=PortState.OPEN)


def _banner(port: int) -> Banner:
    return Banner(host="h.test", port=port, state=BannerState.REFUSED)


def _wake_report(port: int) -> WakeReport:
    return WakeReport(mac="aa:bb:cc:dd:ee:ff", broadcast="192.0.2.255", port=port)


BUILDERS: list[Any] = [_port_result, _banner, _wake_report]


@pytest.mark.parametrize("build", BUILDERS)
@pytest.mark.parametrize("port", [MIN_PORT, MAX_PORT])
def test_every_port_carrying_record_accepts_the_edges_of_the_range(build: Any, port: int) -> None:
    assert build(port).port == port


@pytest.mark.parametrize("build", BUILDERS)
@pytest.mark.parametrize("port", [MIN_PORT - 1, MAX_PORT + 1])
def test_every_port_carrying_record_refuses_a_port_outside_the_range(build: Any, port: int) -> None:
    with pytest.raises(ValidationError):
        build(port)


@pytest.mark.parametrize("port", OUT_OF_RANGE)
def test_a_port_list_is_refused_like_a_specification_before_anything_is_sent(port: int) -> None:
    with pytest.raises(ValueError, match=rf"^port out of range 1-65535: {port}$"):
        scan_ports("127.0.0.1", [port], timeout=0.2)


@pytest.mark.parametrize("port", OUT_OF_RANGE)
def test_the_awaitable_scan_refuses_the_same_list(port: int) -> None:
    import asyncio

    with pytest.raises(ValueError, match=rf"^port out of range 1-65535: {port}$"):
        asyncio.run(ascan_ports("127.0.0.1", [port], timeout=0.2))


@pytest.mark.parametrize("port", OUT_OF_RANGE)
def test_a_syn_scan_refuses_a_bad_port_before_asking_for_privileges(port: int) -> None:
    # Argument errors come first: an unprivileged caller with a bad list
    # must be told about the list, not about the raw socket.
    with pytest.raises(ValueError, match=rf"^port out of range 1-65535: {port}$"):
        syn_scan("127.0.0.1", [80, port], timeout=0.2)


@pytest.mark.parametrize("port", OUT_OF_RANGE)
def test_the_syn_method_of_scan_ports_refuses_the_same_list(port: int) -> None:
    with pytest.raises(ValueError, match=rf"^port out of range 1-65535: {port}$"):
        scan_ports("127.0.0.1", [port], method=ScanMethod.SYN, timeout=0.2)


def test_the_specification_message_is_unchanged() -> None:
    with pytest.raises(ValueError, match=r"^port out of range 1-65535: 0$"):
        parse_ports("0")


@pytest.mark.parametrize("port", OUT_OF_RANGE)
def test_a_magic_packet_to_a_port_outside_the_range_is_refused_as_an_argument(port: int) -> None:
    # A bad argument is a ValueError, not a send failure: before this check
    # the socket layer answered 0 with an OSError on Linux and 70000 with an
    # OverflowError, which the CLI does not catch.
    with pytest.raises(ValueError, match=rf"^port out of range 1-65535: {port}$"):
        wake_on_lan("aa:bb:cc:dd:ee:ff", broadcast="127.0.0.1", port=port)
