"""The shared routing-socket encoders and the defaults the backends take.

The macOS backends cannot run on the development host, so what they send is
pinned here as bytes: each shared encoder must produce exactly the packing the
backends wrote by hand before, and a static-entry write must still carry an
all-zero ``rt_metrics`` of the size ``rt_msghdr`` reserves for it.
"""

from __future__ import annotations

import inspect
import socket
import struct

import pytest

from ipscout import bsdroute, neighbours_linux, neighbours_macos
from ipscout.models import DEFAULT_TIMEOUT

pytestmark = pytest.mark.os_agnostic

#: RFC 5737 / RFC 3849 documentation addresses and a locally administered MAC.
_DOC_IPV4 = "192.0.2.7"
_DOC_IPV6 = "2001:db8::7"
_DOC_MAC = bytes.fromhex("020000000007")


def test_pack_sockaddr_in_matches_the_hand_packed_sockaddr_in() -> None:
    address = socket.inet_aton(_DOC_IPV4)

    assert bsdroute.pack_sockaddr_in(address) == struct.pack("=BBH4s8s", 16, socket.AF_INET, 0, address, b"\x00" * 8)


def test_pack_sockaddr_in6_matches_the_hand_packed_sockaddr_in6() -> None:
    address = socket.inet_pton(socket.AF_INET6, _DOC_IPV6)

    encoded = bsdroute.pack_sockaddr_in6(address)

    assert encoded == struct.pack("=BBHI16sI", 28, socket.AF_INET6, 0, 0, address, 0)
    assert bsdroute.address_of(encoded) == _DOC_IPV6


def test_no_metrics_fills_exactly_the_metrics_field_of_rt_msghdr() -> None:
    metrics = bsdroute.NO_METRICS

    assert metrics == bytes(56)
    assert bsdroute.RT_MSGHDR.size == struct.calcsize("=HBBH2xiiiiiiI") + len(bsdroute.NO_METRICS)


def _hand_packed_header(message_type: int, addrs: int, payload_length: int, *, pid: int, seq: int) -> bytes:
    flags = bsdroute.RTF_HOST | bsdroute.RTF_STATIC | bsdroute.RTF_LLINFO
    return bsdroute.RT_MSGHDR.pack(bsdroute.RT_MSGHDR.size + payload_length, 5, message_type, 0, flags, addrs, pid, seq, 0, 0, bsdroute.RTV_EXPIRE, bytes(56))


def test_a_static_add_is_byte_identical_to_the_hand_packed_form() -> None:
    addresses = bsdroute.pack_sockaddr_in(socket.inet_aton(_DOC_IPV4)) + bsdroute.pack_sockaddr_dl(4, _DOC_MAC)
    expected = _hand_packed_header(0x01, bsdroute.RTA_DST | bsdroute.RTA_GATEWAY, len(addresses), pid=1, seq=2) + addresses

    assert neighbours_macos.build_add_message(_DOC_IPV4, _DOC_MAC, 4, pid=1, seq=2) == expected


def test_a_static_delete_is_byte_identical_to_the_hand_packed_form() -> None:
    address = bsdroute.pack_sockaddr_in(socket.inet_aton(_DOC_IPV4))
    expected = _hand_packed_header(0x02, bsdroute.RTA_DST, len(address), pid=1, seq=1) + address

    assert neighbours_macos.build_delete_message(_DOC_IPV4, pid=1, seq=1) == expected


@pytest.mark.parametrize(
    ("mac", "expected"),
    [
        (_DOC_MAC, "02:00:00:00:00:07"),
        (bytes.fromhex("AABBCCDDEEFF"), "aa:bb:cc:dd:ee:ff"),
        (bytes(6), None),
    ],
)
def test_a_sockaddr_dl_hardware_address_renders_as_before(mac: bytes, expected: str | None) -> None:
    name = b"en0"
    data = name + mac
    chunk = bsdroute.SOCKADDR_DL.pack(bsdroute.SOCKADDR_DL.size + len(data), bsdroute.AF_LINK, 1, 6, len(name), len(mac), 0) + data

    assert bsdroute.link_address_of(chunk) == expected


@pytest.mark.parametrize(
    "resolver",
    [
        neighbours_linux.resolve_active_ipv4,
        neighbours_linux.resolve_active_ipv6,
        neighbours_macos.resolve_active_ipv4,
        neighbours_macos.resolve_active_ipv6,
    ],
)
def test_every_active_resolver_waits_the_package_default_for_a_reply(resolver: object) -> None:
    assert callable(resolver)
    assert inspect.signature(resolver).parameters["timeout"].default == DEFAULT_TIMEOUT
