"""Each route backend packs and parses the family it is handed.

The backends take an :class:`~ipscout.models.AddressFamily` and turn it into
their own wire number only where bytes are built or read. A backend that
compared the category against a raw socket number would treat every IPv6
request as IPv4 and still return a plausible answer, so each encoder and
decoder is driven here with both families and the family it wrote is read back
out of the bytes.
"""

# The encoders and decoders are private: the public lookups that wrap them talk
# to a live kernel (and two of the three only run on their own platform), so the
# bytes they build can only be checked by asking the builders directly.
# pyright: reportPrivateUsage=false

from __future__ import annotations

import socket
import struct

import pytest

from ipscout import bsdroute, netlink, winapi
from ipscout import routes_linux as linux
from ipscout import routes_macos as macos
from ipscout import routes_windows as windows
from ipscout.models import AddressFamily

pytestmark = pytest.mark.os_agnostic

#: One documentation address per family (RFC 5737, RFC 3849).
_SAMPLE = {
    AddressFamily.IPV4: "192.0.2.1",
    AddressFamily.IPV6: "2001:db8::1",
}

_FAMILIES = pytest.mark.parametrize("family", list(AddressFamily))


def _rtmsg_of(message: bytes) -> tuple[int, ...]:
    """Return the struct rtmsg fields that follow the netlink header."""

    start = netlink.NLMSGHDR.size
    return linux._RTMSG.unpack(message[start : start + linux._RTMSG.size])


# --------------------------------------------------------------------------
# Linux netlink
# --------------------------------------------------------------------------


@_FAMILIES
def test_a_linux_route_query_names_the_family_it_was_given(family: AddressFamily) -> None:
    packed = socket.inet_pton(family.socket_family, _SAMPLE[family])

    fields = _rtmsg_of(linux._build_query(packed, family))

    assert fields[0] == family.socket_family
    assert fields[1] == len(packed) * 8


@_FAMILIES
def test_a_linux_route_dump_names_the_family_it_was_given(family: AddressFamily) -> None:
    fields = _rtmsg_of(linux._build_dump(family))

    assert fields[0] == family.socket_family


@_FAMILIES
def test_a_linux_route_gateway_is_decoded_in_the_family_it_was_given(family: AddressFamily) -> None:
    packed = socket.inet_pton(family.socket_family, _SAMPLE[family])
    header = linux._RTMSG.pack(family.socket_family, 0, 0, 0, 0, 0, 0, 0, 0)
    attribute = struct.pack("=HH", 4 + len(packed), linux._RTA_GATEWAY) + packed

    route = linux._parse_route(header + attribute, family)

    assert route.gateway == _SAMPLE[family]


# --------------------------------------------------------------------------
# macOS route socket
# --------------------------------------------------------------------------


@_FAMILIES
def test_a_macos_route_request_carries_a_sockaddr_of_the_family_it_was_given(family: AddressFamily) -> None:
    packed = socket.inet_pton(family.socket_family, _SAMPLE[family])

    message = macos._build_request(packed, family, 1)
    sockaddr = message[bsdroute.RT_MSGHDR.size :]

    assert sockaddr[1] == family.socket_family
    assert sockaddr[0] == len(sockaddr)
    assert bsdroute.address_of(sockaddr) == _SAMPLE[family]


# --------------------------------------------------------------------------
# Windows GetBestRoute2 / GetIpForwardTable2
# --------------------------------------------------------------------------


_WIN_FAMILY = {
    AddressFamily.IPV4: winapi.WIN_AF_INET,
    AddressFamily.IPV6: winapi.WIN_AF_INET6,
}


@_FAMILIES
def test_a_windows_route_destination_is_packed_in_the_family_it_was_given(family: AddressFamily) -> None:
    sockaddr = windows._destination(_SAMPLE[family], family)

    assert sockaddr is not None
    assert sockaddr.si_family == _WIN_FAMILY[family]
    assert winapi.sockaddr_inet_to_string(sockaddr) == _SAMPLE[family]


@_FAMILIES
def test_an_address_of_the_other_family_is_not_a_windows_route_destination(family: AddressFamily) -> None:
    other = AddressFamily.IPV4 if family is AddressFamily.IPV6 else AddressFamily.IPV6

    assert windows._destination(_SAMPLE[other], family) is None
