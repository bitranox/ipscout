"""Callers of the defined-once homes in sweeping, subnets, static entries and wake-on-LAN.

Each test drives a public entry point that now reads a shared home (the
interface network, the hardware-address refusal, the one network parser, the
wake-on-LAN arguments model) and pins what a caller sees through it.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Network
from typing import Any

import pytest
from pydantic import ValidationError

from ipscout.models import AddressFamily, Interface, InterfaceAddress, SubnetInfo
from ipscout.scan import find_ip_by_mac, local_networks, sweep_scope
from ipscout.static_neighbours import station_mac, subnet_interface_index
from ipscout.subnet import subnet_info
from ipscout.wol import WakeSettings, wake_on_lan

pytestmark = pytest.mark.os_agnostic

_MAC = "00:00:5e:00:53:01"


# --- subnet_info and the zone-free interface network ---------------------------------


def test_a_zoned_ipv6_host_address_gets_a_zone_free_network() -> None:
    # ip_network keeps the zone of "fe80::1%lab0/128" but drops it at a shorter
    # prefix, so the network is derived zone-free: one address, one network.
    # Compared as text, so the assertion reads exactly what a caller is shown.
    lab = Interface(name="lab0", ipv6=(InterfaceAddress(address="fe80::1%lab0", prefix_len=128),))

    (record,) = subnet_info(interfaces=[lab])

    assert (record.address, record.family, str(record.network)) == ("fe80::1%lab0", AddressFamily.IPV6, "fe80::1/128")
    assert record.broadcast is None


def test_a_subnet_record_carries_the_network_and_broadcast_of_its_address() -> None:
    lab = Interface(name="lab0", ipv4=(InterfaceAddress(address="192.0.2.77", prefix_len=24), InterfaceAddress(address="198.51.100.9", prefix_len=32)))

    records = subnet_info(interfaces=[lab])

    assert [(str(item.network), item.broadcast) for item in records] == [("192.0.2.0/24", "192.0.2.255"), ("198.51.100.9/32", None)]


def test_subnet_info_still_filters_the_given_interfaces_by_name() -> None:
    first = Interface(name="lab0", ipv4=(InterfaceAddress(address="192.0.2.77", prefix_len=24),))
    second = Interface(name="lab1", ipv4=(InterfaceAddress(address="198.51.100.9", prefix_len=24),))

    assert [item.interface for item in subnet_info("lab1", interfaces=[first, second])] == ["lab1"]


# --- sweeping ---------------------------------------------------------------------------


def test_the_local_networks_are_the_interface_networks_host_bits_cleared() -> None:
    lab = Interface(name="lab0", ipv4=(InterfaceAddress(address="192.0.2.77", prefix_len=24),))

    assert local_networks([lab]) == (IPv4Network("192.0.2.0/24"),)


def test_a_written_network_is_parsed_once_with_its_host_bits_cleared() -> None:
    assert sweep_scope("192.0.2.77/24").networks == (IPv4Network("192.0.2.0/24"),)


def test_a_written_network_that_is_not_one_is_refused_as_a_value_error() -> None:
    with pytest.raises(ValueError, match="does not appear to be an IPv4 or IPv6 network"):
        sweep_scope("not-a-network")


def test_a_bad_limit_is_reported_before_a_bad_network() -> None:
    # The network is parsed by SweepScope.from_networks, which runs after the
    # limit is checked, so the limit is what a call with both wrong names.
    with pytest.raises(ValueError, match=r"^sweep refused its arguments: limit: "):
        sweep_scope("not-a-network", limit=0)


def test_a_search_for_something_that_is_not_a_hardware_address_names_it() -> None:
    with pytest.raises(ValueError, match=r"^'nonsense' is not a hardware address$"):
        find_ip_by_mac("nonsense")


# --- static neighbour entries -----------------------------------------------------------


def test_a_static_entry_refuses_something_that_is_not_a_hardware_address_in_the_shared_words() -> None:
    with pytest.raises(ValueError, match=r"^'nonsense' is not a hardware address$"):
        station_mac("nonsense")


@pytest.mark.parametrize(("mac", "why"), [("00:00:00:00:00:00", "all-zero"), ("01:00:5e:00:00:01", "multicast")])
def test_a_static_entry_still_refuses_an_address_no_station_owns(mac: str, why: str) -> None:
    with pytest.raises(ValueError, match=why):
        station_mac(mac)


def test_the_interface_whose_subnet_holds_an_address_is_found_through_its_network() -> None:
    lan = Interface(name="lab0", index=2, mac=_MAC, ipv4=(InterfaceAddress(address="192.0.2.1", prefix_len=24),))
    other = Interface(name="lab1", index=3, mac=_MAC, ipv4=(InterfaceAddress(address="198.51.100.1", prefix_len=24),))

    assert subnet_interface_index("192.0.2.200", [other, lan]) == 2


# --- wake-on-LAN ------------------------------------------------------------------------


def test_every_bad_wake_argument_is_reported_together() -> None:
    expected = (
        "wake-on-LAN refused its arguments: "
        "mac: 'nonsense' is not a hardware address; "
        "broadcast: broadcast must be an IPv4 address other than 0.0.0.0: '0.0.0.0' is this host; "
        "port: port out of range 1-65535: 0"
    )

    with pytest.raises(ValueError, match=rf"^{re.escape(expected)}$"):
        wake_on_lan("nonsense", broadcast="0.0.0.0", port=0)  # noqa: S104 - the refused INADDR_ANY under test


@pytest.mark.parametrize("port", [True, 9.0], ids=["bool", "float"])
def test_a_port_that_is_not_an_integer_is_refused_before_anything_is_sent(port: Any) -> None:
    # Before, True passed the range check as port 1 and the packet went there.
    # The refusal coming from the arguments model, not from the socket layer,
    # is what shows the send never started.
    with pytest.raises(ValueError, match=r"^wake-on-LAN refused its arguments: port: Input should be a valid integer"):
        wake_on_lan(_MAC, broadcast="127.0.0.1", port=port)


def test_the_wake_settings_store_the_canonical_hardware_address() -> None:
    assert WakeSettings(mac="00-00-5E-00-53-01", broadcast="192.0.2.255").mac == _MAC


def test_a_record_naming_another_zone_on_its_network_is_refused() -> None:
    with pytest.raises(ValidationError, match="network must be fe80::1/128"):
        SubnetInfo.model_validate({"interface": "lab0", "address": "fe80::1%lab0", "prefix_len": 128, "network": "fe80::1%eth9/128", "family": "ipv6"})


@pytest.mark.parametrize(
    ("prefix_len", "network"),
    [(64, "fe80::/64"), (64, "fe80::%lab0/64"), (128, "fe80::1%lab0/128")],
    ids=["unzoned", "own-zone", "own-zone-host"],
)
def test_a_network_written_with_the_address_s_own_zone_is_the_same_network(prefix_len: int, network: str) -> None:
    # ip_network keeps a zone written into its text, so a caller building the
    # network from the zoned address spells the same link this way.
    record = SubnetInfo.model_validate({"interface": "lab0", "address": "fe80::1%lab0", "prefix_len": prefix_len, "network": network, "family": "ipv6"})
    assert str(record.network) == network
