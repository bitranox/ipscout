"""Windows' own address-family numbering, and the structures that carry it.

Windows numbers ``AF_INET6`` 23, Linux 10 and macOS 30. Every iphlpapi
structure carries the Windows number whichever platform builds it, so a
backend that wrote the host's ``socket.AF_INET6`` would hand Windows a family
it does not know, and a reader that compared against it would drop every IPv6
row. These run on every platform, which is the point: on Windows the two
numbers coincide and the mistake is invisible.
"""

from __future__ import annotations

import ctypes
import socket

import pytest

from ipscout import winapi
from ipscout.models import AddressFamily
from ipscout.transport_windows import ipv6_destination

pytestmark = pytest.mark.os_agnostic


@pytest.mark.parametrize(
    ("family", "number"),
    [(AddressFamily.IPV4, winapi.WIN_AF_INET), (AddressFamily.IPV6, winapi.WIN_AF_INET6)],
)
def test_a_family_round_trips_through_its_windows_number(family: AddressFamily, number: int) -> None:
    assert winapi.win_family(family) == number
    assert winapi.family_from_win(number) is family


def test_windows_numbers_ipv6_differently_from_this_host_where_it_matters() -> None:
    # Pins the constants themselves: a helper returning socket.AF_INET6 would
    # still pass the round trip above on Windows, where both are 23.
    assert (winapi.WIN_AF_INET, winapi.WIN_AF_INET6) == (2, 23)


@pytest.mark.parametrize("number", [winapi.WIN_AF_UNSPEC, 10, 30, 65535])
def test_a_number_naming_no_known_family_decodes_to_none(number: int) -> None:
    # 10 and 30 are AF_INET6 on Linux and macOS: read back from a Windows
    # structure they are not IPv6, and must not be taken for it.
    assert winapi.family_from_win(number) is None


def test_a_sockaddr_in6_carries_the_windows_family_number() -> None:
    sockaddr = winapi.sockaddr_in6()

    assert sockaddr.sin6_family == winapi.WIN_AF_INET6
    assert bytes(sockaddr.sin6_addr) == bytes(16)
    assert sockaddr.sin6_scope_id == 0


def test_an_ipv6_echo_destination_carries_the_windows_family_and_the_address() -> None:
    sockaddr = ipv6_destination("2001:db8::7")

    assert sockaddr.sin6_family == winapi.WIN_AF_INET6
    assert socket.inet_ntop(socket.AF_INET6, bytes(sockaddr.sin6_addr)) == "2001:db8::7"
    assert sockaddr.sin6_scope_id == 0


def test_an_ipv6_echo_destination_carries_a_numeric_zone_as_its_scope_id() -> None:
    sockaddr = ipv6_destination("fe80::1%7")

    assert sockaddr.sin6_scope_id == 7
    assert socket.inet_ntop(socket.AF_INET6, bytes(sockaddr.sin6_addr)) == "fe80::1"


@pytest.mark.parametrize("reply", [winapi.ICMP_ECHO_REPLY, winapi.ICMPV6_ECHO_REPLY])
def test_a_reply_buffer_holds_the_reply_the_payload_and_the_error_headroom(reply: type[ctypes.Structure]) -> None:
    assert winapi.reply_buffer_size(reply, 56) == ctypes.sizeof(reply) + 56 + winapi.ICMP_REPLY_HEADROOM
