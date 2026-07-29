"""Port scanning, wake-on-LAN, path MTU and subnet stories.

The connect scan and the magic packet are exercised against real sockets
rather than doubles, so what is asserted is what actually goes on the wire.
The SYN codec is tested as pure bytes, because sending one needs a raw socket
and so cannot run in CI at all.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import threading
from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest

import ipscout
from ipscout.errors import IPScoutPermissionError, IPScoutUnsupportedError
from ipscout.leases_linux import parse_dhclient_lease, parse_networkd_lease
from ipscout.models import PortState, ScanMethod
from ipscout.tcpsyn import ACK, RST, SYN, build_syn, checksum, parse_tcp_reply
from ipscout.wol import MAGIC_PACKET_SIZE, build_magic_packet

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

pytestmark = pytest.mark.os_agnostic


@pytest.fixture
def listening_port() -> Iterator[int]:
    """A real port with something accepting on it."""

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    threading.Thread(target=lambda: [listener.accept() for _ in range(1)], daemon=True).start()
    yield listener.getsockname()[1]
    listener.close()


@pytest.fixture
def refused_port() -> int:
    """A real port with nothing on it, which therefore refuses."""

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


# --------------------------------------------------------------------------
# Port specifications
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("specification", "expected"),
    [("22", [22]), ("22,80", [22, 80]), ("8000-8003", [8000, 8001, 8002, 8003]), ("80,80,79-81", [79, 80, 81]), (" 22 , 80 ", [22, 80])],
)
def test_a_port_specification_is_read_as_written(specification: str, expected: list[int]) -> None:
    assert ipscout.parse_ports(specification) == expected


@pytest.mark.os_agnostic
@pytest.mark.parametrize("bad", ["0", "65536", "-1", "abc", "80-79", "22,abc"])
def test_a_malformed_port_specification_is_refused(bad: str) -> None:
    with pytest.raises(ValueError, match=r"port|number"):
        ipscout.parse_ports(bad)


# --------------------------------------------------------------------------
# The connect scan, against real sockets
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_port_with_a_listener_reads_open(listening_port: int) -> None:
    assert ipscout.scan_ports("127.0.0.1", [listening_port], timeout=1.0)[listening_port] is PortState.OPEN


@pytest.mark.os_agnostic
def test_a_refused_port_is_closed_rather_than_merely_not_open(refused_port: int) -> None:
    # A refusal is an answer: it proves something is there to refuse. Folding
    # it in with silence would hide the difference between a closed port and a
    # firewall, which is the main thing a scan is asked to tell apart.
    #
    # Windows is the measured exception. On a runner it neither refuses nor
    # resets a closed loopback port within the timeout - it simply goes quiet -
    # so a connect scan there cannot separate CLOSED from FILTERED. The check
    # is relaxed to what that platform can actually support rather than
    # asserting a distinction it does not draw.
    import sys

    state = ipscout.scan_ports("127.0.0.1", [refused_port], timeout=1.0)[refused_port]

    if sys.platform == "win32":
        assert state is not PortState.OPEN, f"nothing is listening on {refused_port}, yet it reported {state.value}"
        return
    assert state is PortState.CLOSED, f"port {refused_port} on loopback reported {state.value}, not a refusal"


@pytest.mark.os_agnostic
def test_a_silent_host_reads_filtered_rather_than_closed() -> None:
    # RFC 5737 TEST-NET-1: routable, and nothing answers.
    assert ipscout.scan_ports("192.0.2.1", [80], timeout=0.5)[80] is PortState.FILTERED


@pytest.mark.os_agnostic
def test_only_the_ports_asked_about_are_reported(listening_port: int) -> None:
    # A result covering more than was asked would read as a statement about a
    # whole range that was never scanned.
    result = ipscout.scan_ports("127.0.0.1", [listening_port], timeout=1.0)

    assert list(result) == [listening_port]


@pytest.mark.os_agnostic
def test_the_sync_wrapper_refuses_to_run_inside_an_event_loop() -> None:
    import asyncio

    async def main() -> None:
        with pytest.raises(RuntimeError, match="ascan_ports"):
            ipscout.scan_ports("127.0.0.1", [80])

    asyncio.run(main())


# --------------------------------------------------------------------------
# The SYN scan
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_syn_scan_refuses_loudly_without_the_privilege_it_needs() -> None:
    # It must not quietly become a connect scan: the two measure different
    # things, and one of them completes a handshake the caller asked to avoid.
    import os
    import sys

    if sys.platform == "win32":
        with pytest.raises(IPScoutUnsupportedError, match="raw TCP"):
            ipscout.scan_ports("127.0.0.1", [80], method=ScanMethod.SYN)
        return
    if os.geteuid() == 0:
        pytest.skip("running privileged, so the raw socket is permitted")
    with pytest.raises(IPScoutPermissionError, match=r"CAP_NET_RAW|raw socket"):
        ipscout.scan_ports("127.0.0.1", [80], method=ScanMethod.SYN)


@pytest.mark.os_agnostic
def test_a_syn_packet_carries_the_flag_and_ports_it_should() -> None:
    packet = build_syn(source_ip="192.168.1.2", target_ip="192.168.1.5", source_port=40000, target_port=80)

    assert len(packet) == 40
    assert packet[9] == socket.IPPROTO_TCP
    source_port, target_port = struct.unpack("!HH", packet[20:24])
    assert (source_port, target_port) == (40000, 80)
    assert packet[33] == SYN


@pytest.mark.os_agnostic
def test_the_tcp_checksum_covers_the_addresses_not_just_the_header() -> None:
    # It is computed over a pseudo-header built from both endpoints, so the
    # same TCP header aimed elsewhere must checksum differently. Getting this
    # wrong produces packets every target silently discards.
    here = build_syn(source_ip="192.168.1.2", target_ip="192.168.1.5", source_port=40000, target_port=80)
    there = build_syn(source_ip="192.168.1.2", target_ip="192.168.1.9", source_port=40000, target_port=80)

    assert here[36:38] != there[36:38]


@pytest.mark.os_agnostic
def test_the_checksum_folds_its_carries() -> None:
    assert checksum(b"\xff\xff\xff\xff") == 0
    assert checksum(b"\x00\x00") == 0xFFFF


def _tcp_reply(*, flags: int, source_port: int = 80, target_port: int = 40000, header_words: int = 5) -> bytes:
    """Build an IPv4 packet carrying one TCP reply."""

    ip = struct.pack("!BBHHHBBH4s4s", 0x40 | header_words, 0, 40, 0, 0, 64, socket.IPPROTO_TCP, 0, b"\x01\x02\x03\x04", b"\x05\x06\x07\x08")
    ip += bytes((header_words - 5) * 4)
    tcp = struct.pack("!HHIIBBHHH", source_port, target_port, 0, 1, 5 << 4, flags, 0, 0, 0)
    return ip + tcp


@pytest.mark.os_agnostic
def test_a_syn_ack_means_the_port_is_open() -> None:
    assert parse_tcp_reply(_tcp_reply(flags=SYN | ACK), source_port=40000, target_port=80) is PortState.OPEN


@pytest.mark.os_agnostic
def test_a_reset_means_the_port_is_closed() -> None:
    assert parse_tcp_reply(_tcp_reply(flags=RST), source_port=40000, target_port=80) is PortState.CLOSED


@pytest.mark.os_agnostic
def test_another_conversation_is_not_read_as_our_answer() -> None:
    # A raw TCP socket receives every TCP packet the host sees, so nearly
    # everything that arrives belongs to somebody else.
    assert parse_tcp_reply(_tcp_reply(flags=SYN | ACK, source_port=443), source_port=40000, target_port=80) is None
    assert parse_tcp_reply(_tcp_reply(flags=SYN | ACK, target_port=50000), source_port=40000, target_port=80) is None


@pytest.mark.os_agnostic
def test_ip_options_do_not_shift_the_tcp_header_out_of_view() -> None:
    # The IPv4 header length is variable. Assuming 20 bytes reads the TCP
    # header out of the middle of the options instead.
    with_options = _tcp_reply(flags=SYN | ACK, header_words=8)

    assert parse_tcp_reply(with_options, source_port=40000, target_port=80) is PortState.OPEN


@pytest.mark.os_agnostic
@pytest.mark.parametrize("size", [0, 1, 19, 39])
def test_a_truncated_reply_is_refused_rather_than_misread(size: int) -> None:
    assert parse_tcp_reply(_tcp_reply(flags=SYN | ACK)[:size], source_port=40000, target_port=80) is None


# --------------------------------------------------------------------------
# Wake-on-LAN, on the wire
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_the_magic_packet_has_the_structure_a_nic_looks_for() -> None:
    packet = build_magic_packet("aa:bb:cc:dd:ee:ff")

    assert len(packet) == MAGIC_PACKET_SIZE
    assert packet[:6] == b"\xff" * 6
    assert packet[6:] == bytes.fromhex("aabbccddeeff") * 16


@pytest.mark.os_agnostic
@pytest.mark.parametrize("written", ["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff"])
def test_the_target_address_is_accepted_however_it_is_written(written: str) -> None:
    assert build_magic_packet(written) == build_magic_packet("aa:bb:cc:dd:ee:ff")


@pytest.mark.os_agnostic
def test_something_that_is_not_an_address_is_refused() -> None:
    with pytest.raises(ValueError, match="not a hardware address"):
        build_magic_packet("nonsense")


@pytest.mark.os_agnostic
def test_the_packet_that_arrives_is_the_packet_that_was_built() -> None:
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(3.0)
    try:
        ipscout.wake_on_lan("aa:bb:cc:dd:ee:ff", broadcast="127.0.0.1", port=receiver.getsockname()[1])
        data, _address = receiver.recvfrom(256)
    finally:
        receiver.close()

    assert data == build_magic_packet("aa:bb:cc:dd:ee:ff")


# --------------------------------------------------------------------------
# Path MTU
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_path_mtu_is_a_plausible_size_or_honestly_absent() -> None:
    value = ipscout.path_mtu("127.0.0.1")

    assert value is None or value >= 68


@pytest.mark.os_agnostic
def test_the_loopback_path_is_wider_than_the_ethernet_one() -> None:
    loopback = ipscout.path_mtu("127.0.0.1")
    if loopback is None:
        pytest.skip("this platform does not report a path MTU")

    assert loopback > 1500


# --------------------------------------------------------------------------
# Subnets
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_every_address_falls_inside_the_network_reported_for_it() -> None:
    for item in ipscout.subnet_info():
        assert ipaddress.ip_address(item.address) in ipaddress.ip_network(item.network), item


@pytest.mark.os_agnostic
def test_loopback_is_always_among_the_subnets() -> None:
    assert any(ipaddress.ip_address(item.address).is_loopback for item in ipscout.subnet_info())


@pytest.mark.os_agnostic
def test_ipv6_is_not_given_a_broadcast_address_it_does_not_have() -> None:
    # IPv6 has no broadcast at all; inventing one would be a fact that is
    # simply untrue of the protocol.
    for item in ipscout.subnet_info():
        if ":" in item.address:
            assert item.broadcast is None, item


@pytest.mark.os_agnostic
def test_the_gateway_is_attributed_only_to_the_interface_that_carries_it() -> None:
    subnets = ipscout.subnet_info()
    withgateway = {item.interface for item in subnets if item.gateway}

    assert len(withgateway) <= 1, "a default route leaves by one interface"


# --------------------------------------------------------------------------
# Lease files
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_networkd_lease_is_read() -> None:
    lease = parse_networkd_lease("ADDRESS=192.168.1.50\nSERVER_ADDRESS=192.168.1.1\nROUTER=192.168.1.1\nDNS=192.168.1.1 9.9.9.9\nDOMAINNAME=lan\n")

    assert lease.dhcp_server == "192.168.1.1"
    assert lease.dns_servers == ("192.168.1.1", "9.9.9.9")
    assert lease.domain == "lan"


@pytest.mark.os_agnostic
def test_a_networkd_lease_that_says_nothing_reports_nothing() -> None:
    lease = parse_networkd_lease("")

    assert lease.dhcp_server is None
    assert lease.dns_servers == ()


@pytest.mark.os_agnostic
def test_a_dhclient_lease_is_read() -> None:
    lease = parse_dhclient_lease(
        'lease {\n  interface "eth0";\n  option dhcp-server-identifier 192.168.1.1;\n'
        '  option domain-name-servers 192.168.1.1,9.9.9.9;\n  option domain-name "lan";\n'
        "  expire 2 2026/07/29 10:00:00;\n}\n"
    )

    assert lease.dhcp_server == "192.168.1.1"
    assert lease.dns_servers == ("192.168.1.1", "9.9.9.9")
    assert lease.domain == "lan"
    assert lease.expires == "2026/07/29 10:00:00"


@pytest.mark.os_agnostic
def test_the_last_dhclient_lease_wins_because_the_file_is_append_only() -> None:
    # Earlier blocks are history. Reading the first would report an address
    # the host gave up long ago.
    text = (
        'lease {\n  interface "eth0";\n  option dhcp-server-identifier 10.0.0.1;\n}\n'
        'lease {\n  interface "eth0";\n  option dhcp-server-identifier 192.168.1.1;\n}\n'
    )

    assert parse_dhclient_lease(text).dhcp_server == "192.168.1.1"


@pytest.mark.os_agnostic
def test_a_dhclient_lease_for_another_interface_is_not_borrowed() -> None:
    text = 'lease {\n  interface "wlan0";\n  option dhcp-server-identifier 10.0.0.1;\n}\n'

    assert parse_dhclient_lease(text, "eth0").dhcp_server is None


@pytest.mark.os_agnostic
def test_a_lease_naming_something_that_is_not_an_address_drops_it() -> None:
    lease = parse_networkd_lease("DNS=192.168.1.1 not-an-address 9.9.9.9\n")

    assert lease.dns_servers == ("192.168.1.1", "9.9.9.9")


# --------------------------------------------------------------------------
# Bounded scheduling
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_wide_scan_keeps_only_the_concurrency_limit_alive() -> None:
    # The trap this guards: asyncio.gather over every port with a semaphore
    # inside bounds the sockets but still creates one Task per port, so a
    # full-range scan holds 65535 of them to keep 256 busy.
    import asyncio

    from ipscout.pool import gather_bounded

    live = 0
    peak = 0

    async def work(value: int) -> int:
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0)
        live -= 1
        return value

    results = asyncio.run(gather_bounded(range(500), work, 8))

    assert sorted(results) == list(range(500))
    assert peak <= 8, f"{peak} ran at once against a limit of 8"


@pytest.mark.os_agnostic
def test_a_bounded_run_returns_every_result_exactly_once() -> None:
    import asyncio

    from ipscout.pool import gather_bounded

    async def work(value: int) -> int:
        return value

    results = asyncio.run(gather_bounded(range(100), work, 7))

    assert sorted(results) == list(range(100))


@pytest.mark.os_agnostic
def test_a_sweep_pairs_each_result_with_its_own_target() -> None:
    # The pool completes out of order, so pairing by position would attribute
    # results to the wrong hosts - silently, and only under load.
    if not ipscout.icmp_available():
        pytest.skip("unprivileged ICMP unavailable on this host")

    results = ipscout.ping_many(["127.0.0.1", "::1"], times=1, timeout=1.0)

    assert set(results) == {"127.0.0.1", "::1"}
    for target, result in results.items():
        assert result.target == target


@pytest.mark.os_agnostic
def test_every_port_asked_about_comes_back_from_a_wide_scan() -> None:
    result = ipscout.scan_ports("127.0.0.1", "1-300", timeout=0.05, concurrency=32)

    assert len(result) == 300
    assert set(result) == set(range(1, 301))


# --------------------------------------------------------------------------
# One error hierarchy
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_failed_wake_reports_through_the_library_hierarchy() -> None:
    # Every other public callable reports failure this way; one leaking a bare
    # OSError would make "catch IPScoutError" untrue for exactly one function.
    with pytest.raises(ipscout.IPScoutError):
        ipscout.wake_on_lan("aa:bb:cc:dd:ee:ff", broadcast="300.1.1.1")


# --------------------------------------------------------------------------
# Bounded lease reads
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_only_the_tail_of_an_append_only_lease_file_is_read(tmp_path: Path) -> None:
    # dhclient lease stores are append-only and never trimmed. Reading the
    # whole thing grows without bound on a long-lived host, and the wanted
    # lease is the last one anyway.
    from ipscout.leases_linux import MAX_LEASE_BYTES, read_lease_text

    path = tmp_path / "dhclient.leases"
    filler = 'lease {\n  interface "eth0";\n  option dhcp-server-identifier 10.0.0.1;\n}\n'
    current = 'lease {\n  interface "eth0";\n  option dhcp-server-identifier 192.168.9.9;\n}\n'
    path.write_text(filler * ((MAX_LEASE_BYTES // len(filler)) + 200) + current)

    text = read_lease_text(path)

    assert text is not None
    assert len(text) <= MAX_LEASE_BYTES
    assert "192.168.9.9" in text, "the current lease is at the end and must survive the trim"
    assert text.startswith("lease"), "a half-block at the front would parse as a lease"


@pytest.mark.os_agnostic
def test_a_short_lease_file_is_read_whole(tmp_path: Path) -> None:
    from ipscout.leases_linux import read_lease_text

    path = tmp_path / "lease"
    path.write_text("ADDRESS=192.168.1.50\nSERVER_ADDRESS=192.168.1.1\n")

    assert read_lease_text(path) == "ADDRESS=192.168.1.50\nSERVER_ADDRESS=192.168.1.1\n"
