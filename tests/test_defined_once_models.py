"""The shared, defined-once homes in ``ipscout.models`` and ``ipscout.packet``.

Each public name added as the single home of a fact gets its edges pinned here,
so a later caller rewired onto it inherits behaviour that is already tested.
"""

from __future__ import annotations

import math
import re
import socket
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address

import pytest
from pydantic import ValidationError

from ipscout.models import (
    BLANK_TARGET_MESSAGE,
    MAX_ICMP_FIELD16,
    MAX_TIMEOUT,
    MAX_TIMES,
    AddressFamily,
    FamilyAddress,
    Interface,
    InterfaceAddress,
    Neighbour,
    ObserveDhcpReport,
    SubnetInfo,
    interface_network,
    is_blank_target,
    names_a_neighbour,
    require_settle,
)
from ipscout.packet import IPV4_MIN_HEADER_SIZE, build_echo_request, ipv4_header_length, strip_ip_header

_MAC = "00:00:5e:00:53:01"


# --- InterfaceAddress.cidr / .network and interface_network -----------------


def test_cidr_keeps_the_host_bits_of_an_ipv4_address() -> None:
    assert InterfaceAddress(address="192.0.2.77", prefix_len=24).cidr == "192.0.2.77/24"


def test_cidr_keeps_the_host_bits_and_zone_of_an_ipv6_address() -> None:
    assert InterfaceAddress(address="fe80::1%eth0", prefix_len=64).cidr == "fe80::1%eth0/64"


def test_network_clears_the_host_bits_of_an_ipv4_address() -> None:
    assert InterfaceAddress(address="192.0.2.77", prefix_len=24).network == IPv4Network("192.0.2.0/24")


def test_network_clears_the_host_bits_of_an_ipv6_address() -> None:
    assert InterfaceAddress(address="2001:db8::5", prefix_len=64).network == IPv6Network("2001:db8::/64")


@pytest.mark.parametrize("prefix_len", [64, 128])
def test_network_drops_a_zone_at_every_prefix_length(prefix_len: int) -> None:
    zoned = InterfaceAddress(address="fe80::1%eth0", prefix_len=prefix_len).network
    bare = InterfaceAddress(address="fe80::1", prefix_len=prefix_len).network
    assert zoned == bare
    assert "%" not in str(zoned)


def test_network_and_cidr_stay_off_the_wire() -> None:
    assert InterfaceAddress(address="192.0.2.77", prefix_len=24).model_dump() == {"address": "192.0.2.77", "prefix_len": 24}


def test_interface_network_refuses_a_name_in_parse_address_s_words() -> None:
    with pytest.raises(ValueError, match=re.escape("'example.test' is not an IP address literal")):
        interface_network("example.test", 24)


def test_interface_network_refuses_a_prefix_its_family_cannot_hold() -> None:
    with pytest.raises(ValueError, match="33"):
        interface_network("192.0.2.1", 33)


def test_subnet_info_requires_the_network_interface_network_derives() -> None:
    record = SubnetInfo(interface="eth0", address="192.0.2.77", prefix_len=24, network=IPv4Network("192.0.2.0/24"))
    assert record.network == interface_network("192.0.2.77", 24)
    with pytest.raises(ValidationError, match=r"network must be 192\.0\.2\.0/24 for 192\.0\.2\.77/24, got 192\.0\.3\.0/24"):
        SubnetInfo(interface="eth0", address="192.0.2.77", prefix_len=24, network=IPv4Network("192.0.3.0/24"))


# --- InterfaceAddress / Interface validators keep their messages ------------


def test_interface_address_refuses_a_non_literal_in_the_same_words() -> None:
    with pytest.raises(ValidationError, match=re.escape("'example.test' is not an IP address literal")):
        InterfaceAddress(address="example.test", prefix_len=24)


def test_interface_refuses_an_address_of_the_other_family_in_the_same_words() -> None:
    with pytest.raises(ValidationError, match="'2001:db8::1' is not an ipv4 address"):
        Interface(name="eth0", ipv4=(InterfaceAddress(address="2001:db8::1", prefix_len=64),))


# --- AddressFamily.of_socket_family -----------------------------------------


def test_of_socket_family_maps_both_ip_families() -> None:
    assert AddressFamily.of_socket_family(int(socket.AF_INET)) is AddressFamily.IPV4
    assert AddressFamily.of_socket_family(int(socket.AF_INET6)) is AddressFamily.IPV6


@pytest.mark.parametrize("value", [int(socket.AF_UNSPEC), -1, 0xFFFF])
def test_of_socket_family_has_no_answer_for_a_family_that_is_not_ip(value: int) -> None:
    assert AddressFamily.of_socket_family(value) is None


# --- MAX_ICMP_FIELD16 / MAX_TIMES -------------------------------------------


def test_max_icmp_field16_is_the_largest_16_bit_value_and_bounds_times() -> None:
    assert MAX_ICMP_FIELD16 == 2**16 - 1
    assert MAX_TIMES == MAX_ICMP_FIELD16


def test_an_echo_header_field_accepts_max_icmp_field16_and_refuses_one_more() -> None:
    assert build_echo_request(sequence=MAX_ICMP_FIELD16, token=b"ABCDEFGH").datagram
    with pytest.raises(ValueError, match=f"sequence out of range 0-{MAX_ICMP_FIELD16}: {MAX_ICMP_FIELD16 + 1}"):
        build_echo_request(sequence=MAX_ICMP_FIELD16 + 1, token=b"ABCDEFGH")


# --- BLANK_TARGET_MESSAGE / is_blank_target ---------------------------------


def test_blank_target_message_is_the_text_the_entry_points_refuse_with() -> None:
    assert BLANK_TARGET_MESSAGE == "target must not be empty"


@pytest.mark.parametrize("text", ["", " ", "\t\n", chr(0x3000)])
def test_is_blank_target_is_true_for_empty_and_whitespace_only(text: str) -> None:
    assert is_blank_target(text)


@pytest.mark.parametrize("text", ["a", " 192.0.2.1 ", "example.test", chr(0x4F8B)])
def test_is_blank_target_is_false_for_anything_with_a_visible_character(text: str) -> None:
    assert not is_blank_target(text)


# --- require_settle / Settle ------------------------------------------------


@pytest.mark.parametrize("settle", [0.0, -0.0, 0.5, MAX_TIMEOUT])
def test_require_settle_accepts_every_finite_value_from_0_to_max_timeout(settle: float) -> None:
    assert require_settle(settle) == settle


@pytest.mark.parametrize("settle", [-1.0, -1e-9, math.nextafter(MAX_TIMEOUT, math.inf), math.inf, -math.inf, math.nan])
def test_require_settle_refuses_with_the_exact_session_message(settle: float) -> None:
    expected = f"settle must be a finite number of seconds from 0 to {MAX_TIMEOUT:g}, got {settle!r}"
    with pytest.raises(ValueError, match=r"^settle must") as caught:
        require_settle(settle)
    assert str(caught.value) == expected


@pytest.mark.parametrize("settle", [-1.0, math.inf, math.nan, MAX_TIMEOUT + 1])
def test_a_dhcp_report_refuses_the_settles_require_settle_refuses(settle: float) -> None:
    with pytest.raises(ValidationError, match="settle must be a finite number of seconds"):
        ObserveDhcpReport(mac=_MAC, timeout=1.0, settle=settle)


def test_a_dhcp_report_settle_keeps_its_wire_shape() -> None:
    report = ObserveDhcpReport(mac=_MAC, timeout=1.0, settle=0.0)
    assert report.model_dump()["settle"] == 0.0
    assert ObserveDhcpReport.model_validate_json(report.model_dump_json()) == report


# --- Neighbour.address ------------------------------------------------------


def test_neighbour_address_is_ip_parsed() -> None:
    assert Neighbour(ip="192.0.2.1").address == IPv4Address("192.0.2.1")
    assert Neighbour(ip="fe80::1", interface="eth0", family=AddressFamily.IPV6).address == IPv6Address("fe80::1")


def test_neighbour_address_stays_off_the_wire() -> None:
    assert "address" not in Neighbour(ip="192.0.2.1").model_dump()


# --- names_a_neighbour ------------------------------------------------------


@pytest.mark.parametrize("text", ["192.0.2.1", "2001:db8::1", "fe80::1", "169.254.1.1"])
def test_names_a_neighbour_for_a_unicast_address(text: str) -> None:
    assert names_a_neighbour(ip_address(text))


@pytest.mark.parametrize(
    "text", ["224.0.0.1", "239.255.255.250", "ff02::1", "ff02::1:ff00:1", AddressFamily.IPV4.unspecified_address, AddressFamily.IPV6.unspecified_address]
)
def test_names_no_neighbour_for_a_multicast_or_unspecified_address(text: str) -> None:
    assert not names_a_neighbour(ip_address(text))


# --- FamilyAddress ----------------------------------------------------------


def test_family_address_is_a_named_pair() -> None:
    record = FamilyAddress(AddressFamily.IPV6, "2001:db8::1")
    assert (record.family, record.address) == (AddressFamily.IPV6, "2001:db8::1")
    assert record == (AddressFamily.IPV6, "2001:db8::1")


# --- ipv4_header_length -----------------------------------------------------


@pytest.mark.parametrize(("ihl", "expected"), [(5, 20), (6, 24), (15, 60)])
def test_ipv4_header_length_reads_the_ihl_nibble(ihl: int, expected: int) -> None:
    assert ipv4_header_length(bytes([0x40 | ihl]) + b"\x00" * 63) == expected


@pytest.mark.parametrize("ihl", [0, 1, 4])
def test_ipv4_header_length_refuses_an_ihl_below_the_fixed_header(ihl: int) -> None:
    assert ipv4_header_length(bytes([0x40 | ihl]) + b"\x00" * 63) is None


@pytest.mark.parametrize("version", [0, 6, 15])
def test_ipv4_header_length_refuses_any_other_version(version: int) -> None:
    assert ipv4_header_length(bytes([version << 4 | 5]) + b"\x00" * 63) is None


@pytest.mark.parametrize("size", [0, 1, IPV4_MIN_HEADER_SIZE - 1])
def test_ipv4_header_length_refuses_a_buffer_too_short_for_any_header(size: int) -> None:
    assert ipv4_header_length((b"\x45" + b"\x00" * 63)[:size]) is None


def test_ipv4_header_length_leaves_the_claimed_length_check_to_the_caller() -> None:
    # IHL 15 claims 60 bytes; only 20 are present, and the decoded length is still reported.
    assert ipv4_header_length(b"\x4f" + b"\x00" * 19) == 60


def test_strip_ip_header_keeps_a_header_that_is_the_whole_datagram() -> None:
    header_only = b"\x45" + b"\x00" * 19
    assert strip_ip_header(header_only) == header_only
    assert strip_ip_header(header_only + b"\x00") == b"\x00"
