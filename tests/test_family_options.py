"""The per-family ICMP and IP option facts hold the right numbers.

Every fact that differs between IPv4 and IPv6 in the POSIX transport and the
Linux path MTU query is read from one row per family. A wrong value in a row is
silent: the socket opens, the option is set, and the kernel either ignores it
or answers a different question. So the rows are pinned against the kernel and
RFC numbers here, and the transports that consume them are driven over real
sockets, with the expected option read back from the kernel using the stdlib's
own constants as the oracle.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import sys
from typing import TYPE_CHECKING

import pytest

from ipscout import packet
from ipscout.errors import IPScoutPermissionError
from ipscout.models import AddressFamily
from ipscout.mtu import _IP_PMTUDISC_DO, _LINUX_MTU_OPTIONS  # pyright: ignore[reportPrivateUsage] - the module-private table is what is pinned
from ipscout.transport_posix import (
    _ICMP_FAMILY,  # pyright: ignore[reportPrivateUsage] - the module-private table is what is pinned
    AsyncPosixEchoTransport,
    PosixEchoTransport,
    _offender_address,  # pyright: ignore[reportPrivateUsage] - error-queue records reach it only from a live router
    open_socket,
)

if TYPE_CHECKING:
    from collections.abc import Callable

pytestmark = pytest.mark.os_agnostic

#: ``struct sock_extended_err`` as the kernel writes it, header only.
_EXTENDED_ERR = struct.Struct("=IBBBBII")

#: Where each family's loopback answers; nothing is expected to reply.
_LOOPBACK = {AddressFamily.IPV4: "127.0.0.1", AddressFamily.IPV6: "::1"}

#: The stdlib's own level and hop-limit option per family, independent of ipscout.
_STDLIB_HOP_OPTION = {
    AddressFamily.IPV4: (socket.IPPROTO_IP, socket.IP_TTL),
    AddressFamily.IPV6: (socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS),
}

_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="the POSIX transports are not used on Windows")


def test_every_family_has_exactly_one_icmp_row() -> None:
    assert set(_ICMP_FAMILY) == set(AddressFamily)


def test_the_ipv4_icmp_row_holds_the_ipv4_numbers() -> None:
    row = _ICMP_FAMILY[AddressFamily.IPV4]

    assert row.protocol == socket.IPPROTO_ICMP == 1
    assert row.recverr_option == "IP_RECVERR"
    assert row.origin == 2  # SO_EE_ORIGIN_ICMP
    assert row.time_exceeded == packet.TIME_EXCEEDED_V4 == 11
    assert row.hop_option == socket.IP_TTL
    assert row.offender_address == slice(4, 8)


def test_the_ipv6_icmp_row_holds_the_ipv6_numbers() -> None:
    row = _ICMP_FAMILY[AddressFamily.IPV6]

    assert row.protocol == socket.IPPROTO_ICMPV6 == 58
    assert row.recverr_option == "IPV6_RECVERR"
    assert row.origin == 3  # SO_EE_ORIGIN_ICMP6
    assert row.time_exceeded == packet.TIME_EXCEEDED_V6 == 3
    assert row.hop_option == socket.IPV6_UNICAST_HOPS
    assert row.offender_address == slice(8, 24)


def test_the_linux_mtu_rows_hold_the_kernel_abi_values() -> None:
    # include/uapi/linux/in.h and in6.h: IP_MTU_DISCOVER 10, IP_MTU 14,
    # IPV6_MTU_DISCOVER 23, IPV6_MTU 24, IP(V6)_PMTUDISC_DO 2.
    assert set(_LINUX_MTU_OPTIONS) == set(AddressFamily)
    assert _LINUX_MTU_OPTIONS[AddressFamily.IPV4] == (10, 14)
    assert _LINUX_MTU_OPTIONS[AddressFamily.IPV6] == (23, 24)
    assert _IP_PMTUDISC_DO == 2


def _time_exceeded_record(family: AddressFamily, router: str, *, origin: int, icmp_type: int) -> bytes:
    """Return an error-queue control payload naming ``router`` as the offender."""

    address = socket.inet_pton(family.socket_family, router)
    # sockaddr_in: family(2) port(2) addr(4); sockaddr_in6 adds flowinfo(4) first.
    prefix = b"\x00" * (4 if family is AddressFamily.IPV4 else 8)
    header = _EXTENDED_ERR.pack(0, origin, icmp_type, 0, 0, 0, 0)
    return header + prefix + address


@pytest.mark.parametrize(
    ("family", "router", "origin", "icmp_type"),
    [(AddressFamily.IPV4, "192.0.2.1", 2, 11), (AddressFamily.IPV6, "2001:db8::1", 3, 3)],
)
def test_a_time_exceeded_record_names_its_router(family: AddressFamily, router: str, origin: int, icmp_type: int) -> None:
    record = _time_exceeded_record(family, router, origin=origin, icmp_type=icmp_type)

    assert _offender_address(record, family=family) == router


def test_a_record_from_the_other_family_is_not_read_as_a_time_exceeded() -> None:
    # The two families number origin and type differently, so an IPv6 record
    # read as IPv4 must not match - which is what catches a swapped row.
    record = _time_exceeded_record(AddressFamily.IPV6, "2001:db8::1", origin=3, icmp_type=3)

    assert _offender_address(record, family=AddressFamily.IPV4) is None


def test_a_truncated_offender_address_is_refused() -> None:
    record = _time_exceeded_record(AddressFamily.IPV4, "192.0.2.1", origin=2, icmp_type=11)

    assert _offender_address(record[:-1], family=AddressFamily.IPV4) is None


def _udp_factory(opened: list[socket.socket]) -> Callable[[AddressFamily], socket.socket]:
    """Return a socket factory handing out real UDP sockets, kept for inspection."""

    def make(family: AddressFamily) -> socket.socket:
        try:
            sock = socket.socket(family.socket_family, socket.SOCK_DGRAM)
        except OSError as exc:  # pragma: no cover - a host without that stack
            pytest.skip(f"no {family.value} datagram socket on this host: {exc}")
        opened.append(sock)
        return sock

    return make


@_POSIX_ONLY
@pytest.mark.parametrize("family", list(AddressFamily))
def test_the_sync_transport_sets_the_hop_limit_the_kernel_reads_back(family: AddressFamily) -> None:
    opened: list[socket.socket] = []
    with PosixEchoTransport(_LOOPBACK[family], family, socket_factory=_udp_factory(opened)) as transport:
        transport.probe(sequence=1, timeout=0.01, ttl=7)

        assert opened[0].getsockopt(*_STDLIB_HOP_OPTION[family]) == 7


@_POSIX_ONLY
@pytest.mark.parametrize("family", list(AddressFamily))
def test_the_async_transport_sets_the_hop_limit_the_kernel_reads_back(family: AddressFamily) -> None:
    opened: list[socket.socket] = []

    async def probe_and_read() -> int:
        async with AsyncPosixEchoTransport(_LOOPBACK[family], family, socket_factory=_udp_factory(opened)) as transport:
            await transport.probe(sequence=1, timeout=0.01, ttl=9)
            return int(opened[0].getsockopt(*_STDLIB_HOP_OPTION[family]))

    assert asyncio.run(probe_and_read()) == 9


@_POSIX_ONLY
@pytest.mark.parametrize("family", list(AddressFamily))
def test_no_hop_limit_leaves_the_socket_default(family: AddressFamily) -> None:
    opened: list[socket.socket] = []
    with PosixEchoTransport(_LOOPBACK[family], family, socket_factory=_udp_factory(opened)) as transport:
        before = opened[0].getsockopt(*_STDLIB_HOP_OPTION[family])
        transport.probe(sequence=1, timeout=0.01)

        assert opened[0].getsockopt(*_STDLIB_HOP_OPTION[family]) == before


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the error queue exists only on Linux")
@pytest.mark.parametrize(
    ("family", "level", "recverr"),
    # linux/in.h IP_RECVERR 11, linux/in6.h IPV6_RECVERR 25.
    [(AddressFamily.IPV4, socket.IPPROTO_IP, 11), (AddressFamily.IPV6, socket.IPPROTO_IPV6, 25)],
)
def test_the_error_queue_is_switched_on_with_the_family_s_own_option(family: AddressFamily, level: int, recverr: int) -> None:
    opened: list[socket.socket] = []
    with PosixEchoTransport(_LOOPBACK[family], family, socket_factory=_udp_factory(opened)) as transport:
        assert transport.supports_ttl_discovery is True
        assert opened[0].getsockopt(level, recverr) == 1


@_POSIX_ONLY
@pytest.mark.parametrize(("family", "protocol"), [(AddressFamily.IPV4, 1), (AddressFamily.IPV6, 58)])
def test_the_icmp_socket_is_opened_with_the_family_s_protocol(family: AddressFamily, protocol: int) -> None:
    try:
        sock = open_socket(family)
    except IPScoutPermissionError as exc:
        pytest.skip(f"no ICMP socket on this host: {exc}")
    with sock:
        assert sock.family == family.socket_family
        assert sock.proto == protocol
