"""Interface-enumeration stories, asserted on shape rather than on this host."""

from __future__ import annotations

import ipaddress

import pytest

import ipscout
from ipscout.interfaces import local_interfaces
from ipscout.interfaces_posix import network_of

pytestmark = pytest.mark.os_agnostic


def test_every_host_reports_at_least_a_loopback() -> None:
    interfaces = local_interfaces()

    assert interfaces
    assert any(item.is_loopback for item in interfaces)


def test_interface_names_are_unique() -> None:
    names = [item.name for item in local_interfaces()]

    assert len(names) == len(set(names))
    assert all(names)


def test_every_reported_address_actually_parses() -> None:
    # The addresses come out of a hand-walked C structure, so an off-by-one in
    # the offsets would surface here as unparseable text rather than silently.
    for item in local_interfaces():
        for address, prefix in item.ipv4:
            assert ipaddress.ip_address(address).version == 4
            assert 0 <= prefix <= 32
        for address, prefix in item.ipv6:
            assert ipaddress.ip_address(address).version == 6
            assert 0 <= prefix <= 128


def test_a_reported_mac_has_the_canonical_shape() -> None:
    for item in local_interfaces():
        if item.mac is None:
            continue
        octets = item.mac.split(":")
        assert 1 <= len(octets) <= 8
        assert all(len(part) == 2 for part in octets)
        assert all(0 <= int(part, 16) <= 255 for part in octets)


def test_loopback_carries_the_loopback_address() -> None:
    loopbacks = [item for item in local_interfaces() if item.is_loopback]

    assert loopbacks
    addresses = {address for item in loopbacks for address, _ in item.ipv4}
    assert "127.0.0.1" in addresses or not addresses


def test_an_all_zero_hardware_address_is_reported_as_absent() -> None:
    # Loopback has an all-zero MAC, which is the absence of one rather than a
    # real address; reporting 00:00:00:00:00:00 would be misleading.
    for item in local_interfaces():
        if item.is_loopback:
            assert item.mac is None or any(int(part, 16) for part in item.mac.split(":"))


def test_the_records_are_immutable() -> None:
    import dataclasses

    item = local_interfaces()[0]

    with pytest.raises(dataclasses.FrozenInstanceError):
        item.name = "renamed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("address", "prefix", "expected"),
    [
        ("192.168.1.55", 24, "192.168.1.0/24"),
        ("10.1.2.3", 8, "10.0.0.0/8"),
        ("172.16.5.9", 12, "172.16.0.0/12"),
        ("192.168.1.1", 32, "192.168.1.1/32"),
        ("2001:db8::1", 64, "2001:db8::/64"),
    ],
)
def test_a_network_is_derived_from_an_address_and_prefix(address: str, prefix: int, expected: str) -> None:
    assert network_of(address, prefix) == expected


def test_the_public_surface_exposes_the_enumeration() -> None:
    assert ipscout.local_interfaces() == local_interfaces()
