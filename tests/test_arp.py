"""ARP and NDP wire-format stories.

Every test here runs unprivileged on every platform, which is the reason the
codecs are separate from the sockets that carry them: sending either message
needs root or CAP_NET_RAW, so the transmit paths cannot run in CI at all while
all of this can.
"""

from __future__ import annotations

import socket
import struct

import pytest

from ipscout.arp import (
    ARP_REPLY,
    ARP_REQUEST,
    BROADCAST,
    ETH_P_ARP,
    build_arp_request,
    build_neighbour_solicitation,
    format_mac,
    parse_arp_reply,
    parse_neighbour_advertisement,
    solicited_node_multicast,
)

pytestmark = pytest.mark.os_agnostic

SENDER_MAC = "aa:bb:cc:dd:ee:ff"
SENDER_IP = "192.168.1.2"
TARGET_IP = "192.168.1.5"
TARGET_MAC = "11:22:33:44:55:66"

_ETHERNET = struct.Struct("!6s6sH")
_ARP = struct.Struct("!HHBBH6s4s6s4s")


def _reply(*, sender_ip: str = TARGET_IP, sender_mac: str = TARGET_MAC, operation: int = ARP_REPLY) -> bytes:
    """Build an ARP reply frame as it would arrive on the wire."""

    raw = bytes.fromhex(sender_mac.replace(":", ""))
    body = _ARP.pack(1, 0x0800, 6, 4, operation, raw, socket.inet_aton(sender_ip), bytes(6), socket.inet_aton(SENDER_IP))
    return _ETHERNET.pack(bytes.fromhex(SENDER_MAC.replace(":", "")), raw, ETH_P_ARP) + body


# --------------------------------------------------------------------------
# ARP
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_request_is_broadcast_and_leaves_the_answer_blank() -> None:
    frame = build_arp_request(sender_mac=SENDER_MAC, sender_ip=SENDER_IP, target_ip=TARGET_IP)

    destination, source, ethertype = _ETHERNET.unpack(frame[: _ETHERNET.size])
    _h, _p, _hl, _pl, operation, sha, spa, tha, tpa = _ARP.unpack(frame[_ETHERNET.size :])

    assert destination == BROADCAST
    assert ethertype == ETH_P_ARP
    assert operation == ARP_REQUEST
    assert source == sha == bytes.fromhex(SENDER_MAC.replace(":", ""))
    assert socket.inet_ntoa(spa) == SENDER_IP
    assert socket.inet_ntoa(tpa) == TARGET_IP
    # The whole point of the question: the answer is left empty, not guessed.
    assert tha == bytes(6)


@pytest.mark.os_agnostic
def test_a_reply_about_the_address_asked_about_is_read() -> None:
    assert parse_arp_reply(_reply(), TARGET_IP) == TARGET_MAC


@pytest.mark.os_agnostic
def test_a_reply_about_a_different_address_is_ignored() -> None:
    # A link-layer socket sees every frame on the segment, so most of what
    # arrives is somebody else's conversation. Accepting it would answer the
    # question with an unrelated host's address.
    assert parse_arp_reply(_reply(sender_ip="192.168.1.99"), TARGET_IP) is None


@pytest.mark.os_agnostic
def test_somebody_else_s_request_is_not_mistaken_for_our_answer() -> None:
    assert parse_arp_reply(_reply(operation=ARP_REQUEST), TARGET_IP) is None


@pytest.mark.os_agnostic
def test_a_frame_that_is_not_arp_at_all_is_ignored() -> None:
    frame = _ETHERNET.pack(BROADCAST, bytes(6), 0x0800) + bytes(28)

    assert parse_arp_reply(frame, TARGET_IP) is None


@pytest.mark.os_agnostic
@pytest.mark.parametrize("size", [0, 1, 13, 41])
def test_a_truncated_frame_is_refused_rather_than_misread(size: int) -> None:
    assert parse_arp_reply(_reply()[:size], TARGET_IP) is None


@pytest.mark.os_agnostic
def test_a_reply_carrying_no_address_reports_nothing() -> None:
    assert parse_arp_reply(_reply(sender_mac="00:00:00:00:00:00"), TARGET_IP) is None


@pytest.mark.os_agnostic
@pytest.mark.parametrize("written", ["aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff"])
def test_the_sender_address_is_accepted_in_any_written_form(written: str) -> None:
    frame = build_arp_request(sender_mac=written, sender_ip=SENDER_IP, target_ip=TARGET_IP)

    assert frame[6:12] == bytes.fromhex("aabbccddeeff")


# --------------------------------------------------------------------------
# NDP
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_solicitation_goes_to_the_group_derived_from_the_target() -> None:
    # Neighbour discovery does not broadcast. Getting this wrong sends the
    # question to a group the target never joined, so nothing ever answers.
    assert solicited_node_multicast("fe80::1122:3344:5566:7788") == "ff02::1:ff66:7788"
    assert solicited_node_multicast("2001:db8::1") == "ff02::1:ff00:1"


@pytest.mark.os_agnostic
def test_a_solicitation_names_the_target_and_carries_our_address() -> None:
    message = build_neighbour_solicitation(sender_mac=SENDER_MAC, target_ip="fe80::1")

    assert message[0] == 135
    assert socket.inet_ntop(socket.AF_INET6, message[8:24]) == "fe80::1"
    # The source link-layer option lets the answering host reply without
    # having to ask back.
    assert message[24] == 1
    assert message[26:32] == bytes.fromhex("aabbccddeeff")


@pytest.mark.os_agnostic
def test_the_checksum_is_left_for_the_kernel() -> None:
    # It covers a pseudo-header the sender does not otherwise know, and a raw
    # ICMPv6 socket fills it in. Computing a wrong one here would be worse.
    message = build_neighbour_solicitation(sender_mac=SENDER_MAC, target_ip="fe80::1")

    assert message[2:4] == b"\x00\x00"


def _advertisement(*, target: str = "fe80::1", mac: str = TARGET_MAC, option_type: int = 2, units: int = 1) -> bytes:
    """Build a neighbour advertisement as a raw ICMPv6 socket delivers it."""

    header = struct.pack("!BBHI", 136, 0, 0, 0x60000000)
    option = struct.pack("!BB6s", option_type, units, bytes.fromhex(mac.replace(":", "")))
    return header + socket.inet_pton(socket.AF_INET6, target) + option


@pytest.mark.os_agnostic
def test_an_advertisement_about_our_target_yields_its_address() -> None:
    assert parse_neighbour_advertisement(_advertisement(), "fe80::1") == TARGET_MAC


@pytest.mark.os_agnostic
def test_an_advertisement_about_a_different_address_is_ignored() -> None:
    assert parse_neighbour_advertisement(_advertisement(target="fe80::2"), "fe80::1") is None


@pytest.mark.os_agnostic
def test_an_advertisement_written_differently_still_matches_its_target() -> None:
    # The same address can be written several ways; comparing the text rather
    # than the value would miss the answer.
    assert parse_neighbour_advertisement(_advertisement(target="fe80::0:1"), "fe80::1") == TARGET_MAC


@pytest.mark.os_agnostic
def test_an_advertisement_with_no_link_layer_option_reports_nothing() -> None:
    # Legitimate, and it means there is simply nothing to report.
    assert parse_neighbour_advertisement(_advertisement(option_type=1), "fe80::1") is None


@pytest.mark.os_agnostic
def test_an_option_claiming_zero_length_does_not_loop_forever() -> None:
    # A length of zero would not advance the walk, so a malformed or hostile
    # message would spin instead of being rejected.
    assert parse_neighbour_advertisement(_advertisement(units=0), "fe80::1") is None


@pytest.mark.os_agnostic
def test_an_option_claiming_more_than_it_holds_does_not_read_past_the_end() -> None:
    assert parse_neighbour_advertisement(_advertisement(units=9), "fe80::1") is None


@pytest.mark.os_agnostic
@pytest.mark.parametrize("size", [0, 1, 8, 23])
def test_a_truncated_advertisement_is_refused_rather_than_misread(size: int) -> None:
    assert parse_neighbour_advertisement(_advertisement()[:size], "fe80::1") is None


@pytest.mark.os_agnostic
def test_a_solicitation_is_not_mistaken_for_an_advertisement() -> None:
    solicitation = build_neighbour_solicitation(sender_mac=SENDER_MAC, target_ip="fe80::1")

    assert parse_neighbour_advertisement(solicitation, "fe80::1") is None


# --------------------------------------------------------------------------
# Shared
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("raw", "expected"), [(bytes.fromhex("aabbccddeeff"), "aa:bb:cc:dd:ee:ff"), (bytes(6), None), (b"", None), (bytes(7), None)])
def test_only_a_learned_ethernet_address_is_reported(raw: bytes, expected: str | None) -> None:
    assert format_mac(raw) == expected
