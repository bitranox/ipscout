"""The Windows backends' decoded values: one status type, one address decode, bounded rows.

Everything here runs on any OS: the iphlpapi structures are plain ctypes
layouts, and the decode steps under test are pure functions of their bytes.
"""

from __future__ import annotations

import importlib
import inspect
import ipaddress
import socket

import pytest

from ipscout import interfaces_windows, neighbours_windows, routes_windows, winapi
from ipscout.models import DEFAULT_TIMEOUT, AddressFamily
from ipscout.transport_windows import echo_outcome

#: The IP_STATUS numbers as ipexport.h defines them, written out independently
#: of the enum so a renumbered member is caught.
_IPEXPORT_H = {
    "SUCCESS": 0,
    "BUF_TOO_SMALL": 11001,
    "DEST_NET_UNREACHABLE": 11002,
    "DEST_HOST_UNREACHABLE": 11003,
    "DEST_PROT_UNREACHABLE": 11004,
    "DEST_PORT_UNREACHABLE": 11005,
    "NO_RESOURCES": 11006,
    "PACKET_TOO_BIG": 11009,
    "REQ_TIMED_OUT": 11010,
    "TTL_EXPIRED_TRANSIT": 11013,
}

DOC_MAC = bytes.fromhex("00005e005307")


# --------------------------------------------------------------------------
# IP_STATUS
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_every_status_member_carries_the_ipexport_number_once() -> None:
    assert {member.name: int(member) for member in winapi.IpStatus} == _IPEXPORT_H


@pytest.mark.os_agnostic
@pytest.mark.parametrize("member", list(winapi.IpStatus))
def test_every_status_member_has_text_and_parses_back(member: winapi.IpStatus) -> None:
    assert member.text
    assert winapi.IpStatus.parse(int(member)) is member


@pytest.mark.os_agnostic
@pytest.mark.parametrize("code", [11050, 99999, 12345, 1, 2**32 - 1])
def test_an_unlisted_status_code_decodes_to_none_rather_than_raising(code: int) -> None:
    assert winapi.IpStatus.parse(code) is None
    assert winapi.status_message(code) == f"IP_STATUS {code}"


@pytest.mark.os_agnostic
def test_an_unlisted_status_reads_as_unanswered_not_as_a_crash() -> None:
    outcome = echo_outcome(winapi.IpStatus.parse(11050), elapsed_ms=3.0, api_rtt_ms=3, source="192.0.2.1")

    assert outcome.answered is False
    assert outcome.ttl_expired is False


@pytest.mark.os_agnostic
def test_a_success_status_is_an_answer_timed_by_the_measured_clock() -> None:
    outcome = echo_outcome(winapi.IpStatus.SUCCESS, elapsed_ms=0.4, api_rtt_ms=0, source="192.0.2.1")

    assert (outcome.rtt_ms, outcome.source, outcome.ttl_expired) == (0.4, "192.0.2.1", False)


@pytest.mark.os_agnostic
def test_an_expired_hop_is_reported_with_the_router() -> None:
    outcome = echo_outcome(winapi.IpStatus.TTL_EXPIRED_TRANSIT, elapsed_ms=0.0, api_rtt_ms=7, source="192.0.2.254")

    assert (outcome.rtt_ms, outcome.source, outcome.ttl_expired) == (7.0, "192.0.2.254", True)


@pytest.mark.os_agnostic
def test_an_unreachable_status_is_no_answer() -> None:
    assert echo_outcome(winapi.IpStatus.DEST_HOST_UNREACHABLE, elapsed_ms=1.0, api_rtt_ms=1, source="192.0.2.1").answered is False


# --------------------------------------------------------------------------
# SOCKADDR_INET, decoded once
# --------------------------------------------------------------------------


def _sockaddr(address: str) -> winapi.SOCKADDR_INET:
    parsed = ipaddress.ip_address(address)
    sockaddr = winapi.SOCKADDR_INET()
    if parsed.version == 6:
        sockaddr.si_family = winapi.WIN_AF_INET6
        sockaddr.Ipv6.sin6_addr[:] = parsed.packed
    else:
        sockaddr.si_family = winapi.WIN_AF_INET
        sockaddr.Ipv4.sin_addr[:] = parsed.packed
    return sockaddr


@pytest.mark.os_agnostic
@pytest.mark.parametrize("address", ["192.0.2.1", "2001:db8::1", "fe80::1", "::"])
def test_a_sockaddr_decodes_to_its_address(address: str) -> None:
    assert winapi.sockaddr_inet_address(_sockaddr(address)) == ipaddress.ip_address(address)
    assert winapi.sockaddr_inet_to_string(_sockaddr(address)) == address


@pytest.mark.os_agnostic
def test_an_ipv4_mapped_address_reads_as_inet_ntop_writes_it() -> None:
    # str() of this address is '::ffff:c000:201' before Python 3.13; every
    # other backend reports what inet_ntop writes.
    expected = socket.inet_ntop(socket.AF_INET6, ipaddress.IPv6Address("::ffff:192.0.2.1").packed)

    assert winapi.sockaddr_inet_to_string(_sockaddr("::ffff:192.0.2.1")) == expected


@pytest.mark.os_agnostic
def test_a_sockaddr_of_no_family_holds_no_address() -> None:
    assert winapi.sockaddr_inet_address(winapi.SOCKADDR_INET()) is None


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("address", "expected"),
    [
        (AddressFamily.IPV4.unspecified_address, None),
        (AddressFamily.IPV6.unspecified_address, None),
        ("192.0.2.1", "192.0.2.1"),
        ("2001:db8::1", "2001:db8::1"),
    ],
)
def test_an_unspecified_next_hop_is_on_link_in_either_family(address: str, expected: str | None) -> None:
    assert routes_windows._next_hop(_sockaddr(address)) == expected  # pyright: ignore[reportPrivateUsage] - the next-hop decode has no public entry off Windows


# --------------------------------------------------------------------------
# Hardware addresses
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("raw", "length", "expected"),
    [
        (DOC_MAC + bytes(26), 6, "00:00:5e:00:53:07"),
        (DOC_MAC + bytes(2), 6, "00:00:5e:00:53:07"),
        (DOC_MAC + bytes(26), 8, None),
        (DOC_MAC + bytes(26), 0, None),
        (DOC_MAC, 40, "00:00:5e:00:53:07"),
        (bytes(32), 6, None),
    ],
)
def test_a_row_mac_is_read_to_its_declared_length(raw: bytes, length: int, expected: str | None) -> None:
    assert neighbours_windows.declared_mac(raw, length) == expected


def _adapter(octets: bytes, length: int) -> interfaces_windows._IpAdapterAddresses:  # pyright: ignore[reportPrivateUsage] - the adapter record is the module's own ctypes struct
    adapter = interfaces_windows._IpAdapterAddresses()  # pyright: ignore[reportPrivateUsage] - same struct as above
    adapter.PhysicalAddress[: len(octets)] = octets
    adapter.PhysicalAddressLength = length
    return adapter


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("octets", "length", "expected"),
    [
        (DOC_MAC, 6, "00:00:5e:00:53:07"),
        (bytes.fromhex("0011223344556677"), 8, "00:11:22:33:44:55:66:77"),
        (DOC_MAC, 0, None),
        (bytes(8), 8, None),
        (bytes.fromhex("0011223344556677"), winapi.MAX_ADAPTER_ADDRESS_LENGTH + 1, None),
    ],
)
def test_an_adapter_hardware_address_is_bounded_by_its_buffer(octets: bytes, length: int, expected: str | None) -> None:
    assert interfaces_windows._mac_text(_adapter(octets, length)) == expected  # pyright: ignore[reportPrivateUsage] - the adapter decode has no public entry off Windows


@pytest.mark.os_agnostic
def test_the_adapter_and_sendarp_buffers_are_the_shared_length() -> None:
    field = interfaces_windows._IpAdapterAddresses.PhysicalAddress  # pyright: ignore[reportPrivateUsage] - layout of the module's own ctypes struct

    assert field.size == winapi.MAX_ADAPTER_ADDRESS_LENGTH == 8


# --------------------------------------------------------------------------
# The static-entry row refuses what the stack would be handed wrongly
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize("length", [1, 5, 7, 8, 32, 33])
def test_a_neighbour_row_refuses_a_hardware_address_that_is_not_six_bytes(length: int) -> None:
    with pytest.raises(ValueError, match=f"6 bytes .*not {length}"):
        neighbours_windows.ipv4_neighbour_row("192.0.2.7", bytes(range(length)), 4)


@pytest.mark.os_agnostic
def test_a_delete_row_carries_no_hardware_address() -> None:
    row = neighbours_windows.ipv4_neighbour_row("192.0.2.7", b"", 4)

    assert int(row.PhysicalAddressLength) == 0
    assert bytes(row.PhysicalAddress) == bytes(32)


@pytest.mark.os_agnostic
@pytest.mark.parametrize("ip", ["192.0.2", "1", "192.0.2.256", "2001:db8::7", "not an address"])
def test_a_neighbour_row_refuses_anything_but_a_dotted_quad(ip: str) -> None:
    with pytest.raises(ValueError, match="dotted-quad"):
        neighbours_windows.ipv4_neighbour_row(ip, DOC_MAC, 4)


@pytest.mark.os_agnostic
@pytest.mark.parametrize("index", [0, -1, 2**32])
def test_a_neighbour_row_refuses_an_index_its_field_cannot_hold(index: int) -> None:
    with pytest.raises(ValueError, match="interface index out of range"):
        neighbours_windows.ipv4_neighbour_row("192.0.2.7", DOC_MAC, index)


@pytest.mark.os_agnostic
def test_the_largest_interface_index_is_kept_whole() -> None:
    assert int(neighbours_windows.ipv4_neighbour_row("192.0.2.7", DOC_MAC, 2**32 - 1).InterfaceIndex) == 2**32 - 1


# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_active_resolution_waits_the_shared_default() -> None:
    # By import_module: the package re-exports a function named ``neighbours``,
    # which shadows the submodule for a plain attribute import.
    module = importlib.import_module("ipscout.neighbours")

    assert inspect.signature(module.resolve_active).parameters["timeout"].default == DEFAULT_TIMEOUT


@pytest.mark.os_agnostic
def test_the_windows_resolver_takes_the_family_its_caller_decided() -> None:
    # The zone's interface travels as a keyword of its own; the family is still the caller's.
    parameters = inspect.signature(neighbours_windows.resolve_active).parameters
    assert list(parameters) == ["ip", "family", "interface_index"]
    assert parameters["interface_index"].kind is inspect.Parameter.KEYWORD_ONLY
