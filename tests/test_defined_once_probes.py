"""Probe modules moved onto the shared homes for facts they used to restate.

Each test pins what a caller sees once a module reads a fact from its one
home: the bytes a codec writes, the packets a reader still refuses, and the
wording a refusal now carries.
"""

from __future__ import annotations

import os
import socket
import struct
import sys
from typing import Any

import pytest
from dhcp_capture_fixture import REAL_REPLY_FRAMES
from pydantic import ValidationError

from ipscout.arp import ETHERNET_HEADER_SIZE
from ipscout.bootp import DhcpReply
from ipscout.dhcp import DhcpSession
from ipscout.models import PortState
from ipscout.packet import IPV4_MIN_HEADER_SIZE
from ipscout.portscan import syn_scan
from ipscout.tcpsyn import ACK, SYN, TCP_HEADER_SIZE, build_syn, read_reply

pytestmark = pytest.mark.os_agnostic

GUEST_MAC = "02:00:5e:10:00:00"

#: The captured offer, as an Ethernet frame and as the bare IPv4 packet in it.
_OFFER_FRAME = REAL_REPLY_FRAMES["offer_198.51.100.36"]
_OFFER_PACKET = _OFFER_FRAME[ETHERNET_HEADER_SIZE:]


def _untyped(value: object) -> Any:
    """Return ``value`` typed as ``Any``, as a caller without a type checker would pass it."""

    return value


def _is_root() -> bool:
    """Return whether this POSIX process is root; guarded so the Windows type check sees no geteuid."""

    if sys.platform == "win32":
        return False
    return os.geteuid() == 0


def _with_first_byte(data: bytes, first: int) -> bytes:
    """Return ``data`` with its first byte replaced, the version and IHL nibbles of an IPv4 header."""

    return bytes([first]) + data[1:]


# --------------------------------------------------------------------------
# tcpsyn: header bytes derived from the struct sizes
# --------------------------------------------------------------------------


def _syn() -> bytes:
    return build_syn(source_ip="192.0.2.2", target_ip="192.0.2.5", source_port=40000, target_port=80)


def test_a_syn_starts_with_version_4_and_a_five_word_header() -> None:
    assert _syn()[0] == 0x45


def test_a_syn_carries_a_five_word_tcp_header_with_no_options() -> None:
    # The data offset is the high nibble of TCP byte 12, which sits after the
    # 20-byte IPv4 header: byte 32 of the packet.
    assert _syn()[32] == 0x50


def test_a_syn_is_one_option_free_ip_header_and_one_option_free_tcp_header() -> None:
    packet = _syn()

    assert TCP_HEADER_SIZE == 20
    assert len(packet) == IPV4_MIN_HEADER_SIZE + TCP_HEADER_SIZE
    # The total-length field agrees with the bytes built.
    assert struct.unpack("!H", packet[2:4])[0] == len(packet)


def _syn_ack(first_byte: int = 0x45) -> bytes:
    """Return a SYN-ACK from 192.0.2.5:80 to port 40000, with a chosen first IP byte."""

    ip = struct.pack("!BBHHHBBH4s4s", first_byte, 0, 40, 0, 0, 64, socket.IPPROTO_TCP, 0, socket.inet_aton("192.0.2.5"), socket.inet_aton("192.0.2.2"))
    return ip + struct.pack("!HHIIBBHHH", 80, 40000, 0, 1, 5 << 4, SYN | ACK, 0, 0, 0)


def test_a_syn_ack_with_an_ipv4_header_is_read_as_open() -> None:
    # The liveness half of the next test: the same packet with version 4 is read.
    assert read_reply(_syn_ack(), source_port=40000, peer_ip="192.0.2.5") == (80, PortState.OPEN)


@pytest.mark.parametrize("first_byte", [0x65, 0x05], ids=["version-6", "version-0"])
def test_a_reply_whose_version_nibble_is_not_4_is_not_read(first_byte: int) -> None:
    assert read_reply(_syn_ack(first_byte), source_port=40000, peer_ip="192.0.2.5") is None


def test_a_reply_whose_header_length_is_below_five_words_is_not_read() -> None:
    assert read_reply(_syn_ack(0x44), source_port=40000, peer_ip="192.0.2.5") is None


# --------------------------------------------------------------------------
# portscan: a SYN scan reads its ports the way scan_ports does
# --------------------------------------------------------------------------


@pytest.mark.skipif(not _is_root(), reason="a SYN scan needs a raw socket, so root")
def test_a_syn_scan_sends_a_listed_port_once_and_answers_in_port_order() -> None:
    result = syn_scan("127.0.0.1", [9, 7, 9], timeout=0.5)

    assert list(result) == [7, 9]


# --------------------------------------------------------------------------
# bootp: the IHL decoder and the address checks
# --------------------------------------------------------------------------


@pytest.mark.parametrize("data", [_OFFER_FRAME, _OFFER_PACKET], ids=["framed", "bare"])
def test_the_captured_offer_is_read_framed_and_bare(data: bytes) -> None:
    reply = DhcpReply.from_frame(data)

    assert reply is not None
    assert reply.offered_ip == "198.51.100.36"


@pytest.mark.parametrize("first_byte", [0x44, 0x65], ids=["ihl-4", "version-6"])
def test_an_offer_whose_ip_header_is_not_plausible_is_discarded(first_byte: int) -> None:
    framed = _OFFER_FRAME[:ETHERNET_HEADER_SIZE] + _with_first_byte(_OFFER_PACKET, first_byte)

    assert DhcpReply.from_frame(framed) is None
    assert DhcpReply.from_frame(_with_first_byte(_OFFER_PACKET, first_byte)) is None


def _reply(*, offered_ip: str = "198.51.100.36", server_ip: str = "198.51.100.1") -> DhcpReply:
    return DhcpReply(client_mac=GUEST_MAC, offered_ip=offered_ip, server_ip=server_ip, transaction_id=1)


def test_a_server_address_of_the_other_family_is_refused_as_not_ipv4() -> None:
    with pytest.raises(ValidationError, match=r"'::1' is not an ipv4 address"):
        _reply(server_ip="::1")


def test_a_server_address_that_is_no_literal_is_refused_as_such() -> None:
    with pytest.raises(ValidationError, match=r"'dhcp\.example' is not an IP address literal"):
        _reply(server_ip="dhcp.example")


def test_an_offer_of_the_unspecified_address_is_refused() -> None:
    with pytest.raises(ValidationError, match=r"0\.0\.0\.0 hands out no address"):
        _reply(offered_ip="0.0.0.0")  # noqa: S104 - a packet field, nothing is bound to it


def test_an_offered_address_of_the_other_family_is_refused_as_not_ipv4() -> None:
    with pytest.raises(ValidationError, match=r"'2001:db8::5' is not an ipv4 address"):
        _reply(offered_ip="2001:db8::5")


# --------------------------------------------------------------------------
# dhcp: one settings model, one refusal shape
# --------------------------------------------------------------------------


def test_a_dhcp_watch_names_every_bad_argument_in_one_refusal() -> None:
    expected = (
        r"^DHCP watch refused its arguments: "
        r"mac: 'nonsense' is not a hardware address; "
        r"timeout: timeout must be above 0 .*; "
        r"settle: settle must be a finite number of seconds from 0 to .*, got -1\.0$"
    )
    with pytest.raises(ValueError, match=expected):
        DhcpSession("nonsense", timeout=0.0, settle=-1.0)


_NOT_A_NUMBER = [pytest.param(_untyped("2"), id="string"), pytest.param(_untyped(True), id="bool")]


@pytest.mark.parametrize("value", _NOT_A_NUMBER)
def test_a_dhcp_watch_refuses_a_timeout_that_is_not_a_number(value: float) -> None:
    # Strict: "2" read as two seconds would hide a caller passing text through.
    with pytest.raises(ValueError, match=r"^DHCP watch refused its arguments: timeout: Input should be a valid number$"):
        DhcpSession(GUEST_MAC, timeout=value)


@pytest.mark.parametrize("value", _NOT_A_NUMBER)
def test_a_dhcp_watch_refuses_a_settle_that_is_not_a_number(value: float) -> None:
    with pytest.raises(ValueError, match=r"^DHCP watch refused its arguments: settle: Input should be a valid number$"):
        DhcpSession(GUEST_MAC, settle=value)


def test_a_dhcp_watch_takes_whole_seconds_and_any_written_form_of_the_address() -> None:
    session = DhcpSession("02-00-5E-10-00-00", timeout=5, settle=0)

    assert session.mac == GUEST_MAC
