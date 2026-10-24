"""Every public record refuses a value no producer can report.

Each record here is built by a probe in another module; the bounds pinned below
are the ones every such producer already guarantees, so a record holding
anything else was built by mistake, and is refused where it is built rather
than passed on to fail somewhere further away.
"""

from __future__ import annotations

import ipaddress
import json
import math
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from ipscout.cli import cli
from ipscout.models import (
    MAX_TIMEOUT,
    AddressFamily,
    FindIpReport,
    Interface,
    InterfaceAddress,
    MacLookup,
    MacScope,
    MtuReport,
    Neighbour,
    ObserveDhcpReport,
    SubnetInfo,
    SweepScope,
    TraceHop,
    WakeReport,
)
from ipscout.ports import EchoResult
from ipscout.subnet import subnet_info

if TYPE_CHECKING:
    from collections.abc import Mapping

#: A documentation hardware address (RFC 7042), in the canonical form.
_MAC = "02:00:5e:10:00:00"


# --- EchoResult -------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize("rtt", [math.nan, math.inf, -1.0])
def test_an_echo_round_trip_is_a_clock_difference(rtt: float) -> None:
    # nan used to count as answered and fail only later, inside the hop record.
    with pytest.raises(ValidationError, match="rtt_ms"):
        EchoResult(rtt_ms=rtt, source="192.0.2.1")


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        ({"ttl_expired": True}, "rtt_ms and source"),
        ({"rtt_ms": 1.0}, "set together"),
        ({"source": "192.0.2.1"}, "set together"),
    ],
)
def test_an_echo_answer_carries_both_its_time_and_its_source(fields: dict[str, object], reason: str) -> None:
    with pytest.raises(ValidationError, match=reason):
        EchoResult.model_validate(fields)


@pytest.mark.os_agnostic
def test_a_router_answer_and_a_timeout_are_still_records() -> None:
    assert EchoResult(rtt_ms=1.0, source="192.0.2.1", ttl_expired=True).answered
    assert not EchoResult().answered


# --- TraceHop ---------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        ({"reached": True}, "reached needs the address"),
        ({"rtt_ms": 1.0}, "set together"),
        ({"address": "192.0.2.1"}, "set together"),
        ({"hostname": "router.test"}, "hostname needs the address"),
        ({"address": "192.0.2.1", "rtt_ms": 1.0, "hostname": ""}, "hostname"),
        ({"address": "router.test", "rtt_ms": 1.0}, "is not an IP address literal"),
    ],
)
def test_a_hop_either_answered_or_was_silent(fields: dict[str, object], reason: str) -> None:
    with pytest.raises(ValidationError, match=reason):
        TraceHop.model_validate({"ttl": 1, **fields})


@pytest.mark.os_agnostic
def test_answered_and_silent_hops_are_both_records() -> None:
    assert TraceHop(ttl=1).address is None
    assert TraceHop(ttl=2, address="fe80::1%eth0", rtt_ms=0.5, reached=True, hostname="gw.test").reached


# --- Interface --------------------------------------------------------------


@pytest.mark.os_agnostic
def test_an_interface_files_each_address_under_its_own_family() -> None:
    v6 = InterfaceAddress(address="2001:db8::1", prefix_len=64)
    v4 = InterfaceAddress(address="192.0.2.1", prefix_len=24)

    with pytest.raises(ValidationError, match="is not an ipv4 address"):
        Interface(name="eth0", ipv4=(v6,))
    with pytest.raises(ValidationError, match="is not an ipv6 address"):
        Interface(name="eth0", ipv6=(v4,))
    assert Interface(name="eth0", ipv4=(v4,), ipv6=(v6,)).ipv6 == (v6,)


@pytest.mark.os_agnostic
def test_an_interface_has_a_name() -> None:
    with pytest.raises(ValidationError, match="name"):
        Interface(name="")


@pytest.mark.os_agnostic
@pytest.mark.parametrize("mac", ["AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "00:00:00:00:00:00", "", "a:bb", ":".join(["aa"] * 33)])
def test_an_interface_hardware_address_is_written_as_the_formatter_writes_it(mac: str) -> None:
    with pytest.raises(ValidationError, match="is not a hardware address"):
        Interface(name="eth0", mac=mac)


@pytest.mark.os_agnostic
@pytest.mark.parametrize("mac", [_MAC, "00:11:22:33:44:55:66:77", "01"])
def test_an_interface_hardware_address_need_not_be_six_bytes(mac: str) -> None:
    # A tunnel or an InfiniBand port reports a link address of another length.
    assert Interface(name="eth0", mac=mac).mac == mac


# --- MTU --------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize("mtu", [65536, 0xFFFFFFFF])
def test_an_mtu_may_exceed_the_ip_length_field(mtu: int) -> None:
    # Measured: Linux loopback's MTU and its path MTU over ::1 are 65536, and
    # Windows reports its loopback adapter as 0xFFFFFFFF.
    assert Interface(name="lo", mtu=mtu).mtu == mtu
    assert MtuReport(target="::1", mtu=mtu).mtu == mtu


@pytest.mark.os_agnostic
def test_an_mtu_past_a_32_bit_count_is_refused() -> None:
    with pytest.raises(ValidationError, match="mtu"):
        Interface(name="eth0", mtu=1 << 32)
    with pytest.raises(ValidationError, match="mtu"):
        MtuReport(target="t", mtu=1 << 32)
    with pytest.raises(ValidationError, match="mtu"):
        SubnetInfo(interface="eth0", address="192.0.2.1", prefix_len=24, network=ipaddress.IPv4Network("192.0.2.0/24"), mtu=1 << 32)


# --- Neighbour --------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        ({"ip": "2001:db8::1"}, "is not an ipv4 address"),
        ({"ip": "192.0.2.1", "family": AddressFamily.IPV6}, "is not an ipv6 address"),
        ({"ip": "fe80::1%eth0", "family": AddressFamily.IPV6}, "carries a zone"),
        ({"ip": "192.0.2.1", "mac": "AA-BB-CC-DD-EE-FF"}, "is not a hardware address"),
        ({"ip": "192.0.2.1", "mac": "00:11:22:33:44:55:66:77"}, "is not a hardware address"),
    ],
)
def test_a_cache_entry_holds_a_bare_address_of_its_family_and_a_canonical_mac(fields: dict[str, object], reason: str) -> None:
    with pytest.raises(ValidationError, match=reason):
        Neighbour.model_validate(fields)


# --- MacLookup --------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        ({"scope": MacScope.NEXT_HOP, "mac": _MAC}, "via_ip is set exactly when scope is NEXT_HOP"),
        ({"scope": MacScope.DIRECT, "mac": _MAC, "via_ip": "192.0.2.1"}, "via_ip is set exactly when scope is NEXT_HOP"),
        ({"scope": MacScope.DIRECT}, "DIRECT answer carries"),
        ({"scope": MacScope.UNKNOWN, "mac": _MAC}, "UNKNOWN answer carries no"),
        ({"ip": "host.test"}, "is not an IP address literal"),
        ({"scope": MacScope.NEXT_HOP, "via_ip": "router.test"}, "is not an IP address literal"),
        ({"scope": MacScope.DIRECT, "mac": "AABB.CCDD.EEFF"}, "is not a hardware address"),
    ],
)
def test_a_mac_answer_agrees_with_its_scope(fields: dict[str, object], reason: str) -> None:
    with pytest.raises(ValidationError, match=reason):
        MacLookup.model_validate({"ip": "192.0.2.5", **fields})


@pytest.mark.os_agnostic
def test_a_routed_answer_without_a_cached_router_mac_is_still_a_record() -> None:
    # lookup_mac reports the router it would use even when its MAC is not cached.
    answer = MacLookup(ip="198.51.100.7", scope=MacScope.NEXT_HOP, via_ip="192.0.2.1")
    assert answer.mac is None


# --- SubnetInfo -------------------------------------------------------------


def _subnet(**fields: object) -> SubnetInfo:
    base: dict[str, object] = {"interface": "eth0", "address": "192.0.2.1", "prefix_len": 24, "network": "192.0.2.0/24"}
    return SubnetInfo.model_validate({**base, **fields})


@pytest.mark.os_agnostic
def test_a_subnet_network_is_the_one_its_address_sits_on() -> None:
    assert _subnet().network == ipaddress.IPv4Network("192.0.2.0/24")
    with pytest.raises(ValidationError, match=r"network must be 192\.0\.2\.0/24"):
        _subnet(network="198.51.100.0/24")
    with pytest.raises(ValidationError, match="network"):
        _subnet(network="not a network")


@pytest.mark.os_agnostic
def test_a_subnet_broadcast_is_its_network_s_own() -> None:
    assert _subnet(broadcast="192.0.2.255").broadcast == "192.0.2.255"
    with pytest.raises(ValidationError, match="broadcast must be"):
        _subnet(broadcast="192.0.2.254")
    with pytest.raises(ValidationError, match="broadcast must be"):
        _subnet(address="2001:db8::1", prefix_len=64, network="2001:db8::/64", family=AddressFamily.IPV6, broadcast="2001:db8::ffff")


@pytest.mark.os_agnostic
def test_a_subnet_gateway_is_a_router_of_its_family() -> None:
    assert _subnet(gateway="192.0.2.254").gateway == "192.0.2.254"
    with pytest.raises(ValidationError, match="is not an ipv4 address"):
        _subnet(gateway="2001:db8::1")
    with pytest.raises(ValidationError, match="is not an IP address literal"):
        _subnet(gateway="router.test")


@pytest.mark.os_agnostic
def test_a_link_local_subnet_is_built_from_its_scoped_address() -> None:
    entry = _subnet(address="fe80::1%eth0", prefix_len=64, network="fe80::/64", family=AddressFamily.IPV6)
    assert entry.model_dump(mode="json")["network"] == "fe80::/64"


@pytest.mark.os_agnostic
def test_every_subnet_this_host_reports_still_validates() -> None:
    # The real producer, on this host: a bound it violates would crash here.
    for item in subnet_info():
        assert item.network == ipaddress.ip_network(f"{item.address}/{item.prefix_len}", strict=False)


@pytest.mark.os_agnostic
def test_the_subnet_table_renders_the_parsed_network() -> None:
    # The table cell is text; a network object handed to it raises instead.
    result = CliRunner().invoke(cli, ["subnet"])

    assert result.exception is None or isinstance(result.exception, SystemExit), repr(result.exception)
    assert "network" in result.output


# --- SweepScope -------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_sweep_scope_covers_no_more_than_its_limit() -> None:
    with pytest.raises(ValidationError, match="more than the limit of 4096"):
        SweepScope(networks=(ipaddress.IPv4Network("10.0.0.0/16"),), limit=4096)
    assert SweepScope(networks=(ipaddress.IPv4Network("10.0.0.0/20"),), limit=4096).complete


# --- FindIpReport -----------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_find_ip_report_states_its_scope_exactly_when_it_swept() -> None:
    scope = SweepScope.from_networks(["192.0.2.0/24"], limit=4096)

    with pytest.raises(ValidationError, match="scope is set exactly when scanned"):
        FindIpReport(mac=_MAC, scanned=True)
    with pytest.raises(ValidationError, match="scope is set exactly when scanned"):
        FindIpReport(mac=_MAC, scanned=False, scope=scope)
    assert FindIpReport(mac=_MAC, scanned=True, scope=scope).scope == scope


@pytest.mark.os_agnostic
@pytest.mark.parametrize("record", [FindIpReport, WakeReport, ObserveDhcpReport])
def test_a_report_names_its_hardware_address_in_the_canonical_form(record: type[FindIpReport | WakeReport | ObserveDhcpReport]) -> None:
    extra: Mapping[str, object] = {
        FindIpReport: {},
        WakeReport: {"broadcast": "192.0.2.255", "port": 9},
        ObserveDhcpReport: {"timeout": 1.0, "settle": 0.0},
    }[record]
    with pytest.raises(ValidationError, match="is not a hardware address"):
        record.model_validate({"mac": "AABB.CCDD.EEFF", **extra})


# --- ObserveDhcpReport -------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("timeout", "settle"), [(math.inf, 0.0), (1e12, 0.0), (1.0, math.inf), (1.0, MAX_TIMEOUT + 1), (1.0, math.nan)])
def test_a_dhcp_window_is_bounded_like_every_other_wait(timeout: float, settle: float) -> None:
    with pytest.raises(ValidationError):
        ObserveDhcpReport(mac=_MAC, timeout=timeout, settle=settle)


# --- WakeReport -------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("broadcast", "reason"),
    [
        (AddressFamily.IPV4.unspecified_address, r"other than 0\.0\.0\.0"),
        ("ff02::1", "is not an ipv4 address"),
        ("lan.test", "is not an IP address literal"),
    ],
)
def test_a_wake_report_names_the_ipv4_address_the_packet_went_to(broadcast: str, reason: str) -> None:
    with pytest.raises(ValidationError, match=reason):
        WakeReport(mac=_MAC, broadcast=broadcast, port=9)


# --- the CLI echoes the canonical hardware address --------------------------


@pytest.mark.os_agnostic
def test_wake_reports_the_hardware_address_in_the_form_every_other_command_uses() -> None:
    result = CliRunner().invoke(cli, ["--json-bare", "wake", "02005E100000", "--broadcast", "127.0.0.1"])
    dotted = CliRunner().invoke(cli, ["--json-bare", "wake", "0200.5E10.0000", "--broadcast", "127.0.0.1"])

    assert json.loads(result.output)["mac"] == _MAC
    assert json.loads(dotted.output)["mac"] == _MAC


@pytest.mark.os_agnostic
def test_find_ip_reports_the_hardware_address_in_the_form_every_other_command_uses() -> None:
    result = CliRunner().invoke(cli, ["--json-bare", "find-ip", "02-00-5E-10-00-00"])

    assert json.loads(result.output)["mac"] == _MAC
