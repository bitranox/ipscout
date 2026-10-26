"""The Windows backends read their shared facts from one home each.

Most of these backends only run on Windows, but the pieces pinned here - the
argument checks, the sockaddr builders, the decoded records - are pure and
import everywhere, so each test runs on every OS. Where a refusal moved to the
shared check, the test pins that it now happens before anything is loaded or
sent, which is what makes the same malformed argument fail the same way on
every platform.
"""

from __future__ import annotations

import ctypes
import socket
import struct

import pytest

from ipscout import interfaces_windows, neighbours_windows, routes_windows, winapi
from ipscout.models import AddressFamily, FamilyAddress
from ipscout.resolve import MAX_INTERFACE_INDEX
from ipscout.transport_windows import WindowsEchoTransport, api_destination, ipv6_destination

pytestmark = pytest.mark.os_agnostic


# --------------------------------------------------------------------------
# transport_windows: the echo destination, parsed once
# --------------------------------------------------------------------------


@pytest.mark.parametrize("address", ["not an address", "2001:db8::zz", "fe80::1%", "192.0.2.1"])
def test_an_ipv6_echo_destination_refuses_what_is_not_an_ipv6_literal_as_a_value_error(address: str) -> None:
    with pytest.raises(ValueError, match="is not an"):
        ipv6_destination(address)


def test_an_ipv4_echo_destination_is_the_ipaddr_the_api_takes() -> None:
    assert api_destination("192.0.2.1", AddressFamily.IPV4) == winapi.string_to_ipv4("192.0.2.1")


def test_an_ipv6_echo_destination_keeps_its_zone_as_the_scope_id() -> None:
    destination = api_destination("fe80::1%7", AddressFamily.IPV6)

    assert isinstance(destination, winapi.SOCKADDR_IN6)
    assert destination.sin6_scope_id == 7
    assert bytes(destination.sin6_addr) == socket.inet_pton(socket.AF_INET6, "fe80::1")


@pytest.mark.parametrize(
    ("address", "family"),
    [("::1", AddressFamily.IPV4), ("192.0.2.1", AddressFamily.IPV6), ("127.1", AddressFamily.IPV4), ("192.0.2.1%eth0", AddressFamily.IPV4)],
)
def test_an_echo_destination_of_the_wrong_shape_is_refused(address: str, family: AddressFamily) -> None:
    with pytest.raises(ValueError, match="is not an"):
        api_destination(address, family)


def test_a_windows_transport_refuses_a_malformed_address_before_loading_anything() -> None:
    # Checked before iphlpapi.dll is loaded, so this is a ValueError on every
    # OS rather than "unsupported" here and a failure on the first probe there.
    with pytest.raises(ValueError, match="'nonsense' is not an IP address literal"):
        WindowsEchoTransport("nonsense", AddressFamily.IPV4)


# --------------------------------------------------------------------------
# neighbours_windows: the active-resolution argument and the static row
# --------------------------------------------------------------------------


def test_an_active_resolution_packs_the_bare_address() -> None:
    assert neighbours_windows.request_address("fe80::1", AddressFamily.IPV6) == socket.inet_pton(socket.AF_INET6, "fe80::1")


@pytest.mark.parametrize(
    ("ip", "family", "words"),
    [
        ("fe80::1%7", AddressFamily.IPV6, "carries a zone"),
        ("192.0.2.1%eth0", AddressFamily.IPV4, "carries a zone"),
        ("not an address", AddressFamily.IPV4, "is not an IP address literal"),
        ("2001:db8::1", AddressFamily.IPV4, "is not an ipv4 address"),
    ],
)
def test_an_active_resolution_refuses_what_it_cannot_ask_about(ip: str, family: AddressFamily, words: str) -> None:
    with pytest.raises(ValueError, match=words):
        neighbours_windows.request_address(ip, family)


@pytest.mark.parametrize(("ip", "family"), [("not an address", AddressFamily.IPV4), ("fe80::1%7", AddressFamily.IPV6)])
def test_an_active_resolution_refuses_before_loading_anything(ip: str, family: AddressFamily) -> None:
    # A request that could not be made must never read as "nobody answered"
    # (None), and is refused before the library loads, so on every OS.
    with pytest.raises(ValueError):
        neighbours_windows.resolve_active(ip, family)


def test_the_static_row_carries_the_address_as_the_shared_sockaddr_builder_packs_it() -> None:
    row = neighbours_windows.ipv4_neighbour_row("192.0.2.7", bytes(6), 4)
    expected = winapi.sockaddr_inet(socket.inet_pton(socket.AF_INET, "192.0.2.7"), AddressFamily.IPV4)

    assert bytes(row.Address) == bytes(expected)


def test_the_static_row_index_bound_is_the_shared_interface_index_bound() -> None:
    assert int(neighbours_windows.ipv4_neighbour_row("192.0.2.7", bytes(6), MAX_INTERFACE_INDEX).InterfaceIndex) == MAX_INTERFACE_INDEX
    with pytest.raises(ValueError, match=f"interface index out of range 1-{MAX_INTERFACE_INDEX}: {MAX_INTERFACE_INDEX + 1}"):
        neighbours_windows.ipv4_neighbour_row("192.0.2.7", bytes(6), MAX_INTERFACE_INDEX + 1)


# --------------------------------------------------------------------------
# routes_windows: the GetBestRoute2 destination
# --------------------------------------------------------------------------


def test_a_route_destination_is_looked_up_for_the_bare_address_of_a_zoned_literal() -> None:
    # The public query_route strips the zone on every platform; the backend now
    # does the same rather than reading the zoned text as "no route".
    sockaddr = routes_windows._destination("fe80::1%7", AddressFamily.IPV6)  # pyright: ignore[reportPrivateUsage] - the packing step has no public entry off Windows

    assert sockaddr is not None
    assert bytes(sockaddr) == bytes(winapi.sockaddr_inet(socket.inet_pton(socket.AF_INET6, "fe80::1"), AddressFamily.IPV6))


@pytest.mark.parametrize("address", ["not an address", "127.1", "192.0.2.1%eth0"])
def test_a_route_destination_that_is_not_a_literal_is_no_destination(address: str) -> None:
    assert routes_windows._destination(address, AddressFamily.IPV4) is None  # pyright: ignore[reportPrivateUsage] - as above


# --------------------------------------------------------------------------
# interfaces_windows: the decoded sockaddr record
# --------------------------------------------------------------------------


def test_an_adapter_address_decodes_into_the_shared_family_address_record() -> None:
    raw = struct.pack("<HH4s8x", winapi.WIN_AF_INET, 0, socket.inet_pton(socket.AF_INET, "192.0.2.7"))
    buffer = ctypes.create_string_buffer(raw, len(raw))
    address = interfaces_windows._SocketAddress(ctypes.cast(buffer, ctypes.c_void_p), len(raw))  # pyright: ignore[reportPrivateUsage] - the decoder takes the module's own ctypes struct

    decoded = interfaces_windows._sockaddr_text(address)  # pyright: ignore[reportPrivateUsage] - the decode step has no public entry off Windows

    assert type(decoded) is FamilyAddress
    assert decoded == FamilyAddress(AddressFamily.IPV4, "192.0.2.7")
