"""BOOTP and DHCP wire-format stories.

Every test here runs unprivileged on every platform, which is the reason the
codec is separate from the capture that feeds it: opening a link-layer socket
needs root or ``CAP_NET_RAW``, so the capture cannot run in CI at all while all
of this can.

The frames in ``dhcp_capture_fixture`` are real, captured off a Linux bridge
while a guest cold-booted. Their addressing is rewritten and their option block
is reduced to the message type, for the reason spelled out in
``test_the_shipped_fixture_carries_no_site_configuration``.
"""

from __future__ import annotations

import socket
import struct

import pytest
from dhcp_capture_fixture import REAL_REPLY_FRAMES

from ipscout.arp import ETH_P_IP, ETH_P_IPV6, ETH_P_VLAN, ETHERNET
from ipscout.bootp import (
    BOOTP_FIXED_SIZE,
    BOOTREPLY,
    BOOTREQUEST,
    DHCPACK,
    DHCPNAK,
    DHCPOFFER,
    MAGIC_COOKIE,
    DhcpReply,
    merge_offers,
    offers_from_frames,
)

pytestmark = pytest.mark.os_agnostic

#: The hardware address the captured frames were offered to.
GUEST_MAC = "02:00:5e:10:00:00"

#: The answer the original handover specified, now produced from real bytes.
EXPECTED_OFFERS = ["198.51.100.36", "198.51.100.51"]

_OPT_END = 255
_OPT_MESSAGE_TYPE = 53

#: Ethernet, IPv4 and UDP headers, then the BOOTP fixed header. Everything that
#: identifies an offer sits inside this, so it is the shortest capture that can
#: still answer the question.
_SMALLEST_PARSEABLE = 14 + 20 + 8 + BOOTP_FIXED_SIZE

#: A yiaddr of all zeroes: the value a request and a DHCPNAK both carry.
#: Named so it reads as the DHCP field value it is, not a bind address.
_OFFERS_NOTHING = "0.0.0.0"  # noqa: S104 - a packet field, nothing is bound to it


def _reply_frame(
    *,
    client_mac: str = GUEST_MAC,
    yiaddr: str = "198.51.100.36",
    operation: int = BOOTREPLY,
    message_type: int | None = DHCPOFFER,
    server_ip: str = "198.51.100.1",
    cookie: bool = True,
    tags: int = 0,
    ethertype: int = ETH_P_IP,
    protocol: int = socket.IPPROTO_UDP,
    source_port: int = 67,
    destination_port: int = 68,
    ip_option_words: int = 0,
    link_header: bool = True,
    transaction_id: int = 0x0836190B,
) -> bytes:
    """Assemble one frame, so a test can vary exactly one field of it."""

    chaddr = bytes.fromhex(client_mac.replace(":", "")).ljust(16, b"\x00")
    body = _BOOTP.pack(
        operation,
        1,
        6,
        0,
        transaction_id,
        0,
        0,
        bytes(4),
        socket.inet_aton(yiaddr),
        bytes(4),
        bytes(4),
        chaddr,
        bytes(64),
        bytes(128),
    )
    if cookie:
        options = bytes([_OPT_MESSAGE_TYPE, 1, message_type]) if message_type is not None else b""
        body += MAGIC_COOKIE + options + bytes([_OPT_END])

    datagram = struct.pack("!HHHH", source_port, destination_port, 8 + len(body), 0) + body
    header_words = 5 + ip_option_words
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | header_words,
        0,
        header_words * 4 + len(datagram),
        0,
        0,
        64,
        protocol,
        0,
        socket.inet_aton(server_ip),
        socket.inet_aton(yiaddr),
    ) + bytes(ip_option_words * 4)
    packet = header + datagram
    if not link_header:
        return packet

    destination = bytes.fromhex(client_mac.replace(":", ""))
    source = bytes.fromhex("02005e100001")
    if tags:
        # Each tag is the 802.1Q ethertype followed by its control word; the
        # real ethertype then follows the last one.
        tagging = b"".join(struct.pack("!HH", ETH_P_VLAN, 0x0064) for _ in range(tags))
        return destination + source + tagging + struct.pack("!H", ethertype) + packet
    return ETHERNET.pack(destination, source, ethertype) + packet


_BOOTP = struct.Struct("!BBBBIHH4s4s4s4s16s64s128s")


# --------------------------------------------------------------------------
# The captured exchange
# --------------------------------------------------------------------------


def test_both_offers_for_one_machine_are_returned_in_the_order_they_arrived() -> None:
    # The whole point of the feature. A pool that hands out an address the
    # guest declines offers a working one afterwards, and returning only the
    # first reports a reachable machine as one that never booted.
    assert offers_from_frames(REAL_REPLY_FRAMES.values(), mac=GUEST_MAC) == EXPECTED_OFFERS


def test_a_reply_for_somebody_elses_hardware_address_is_ignored() -> None:
    # Not hypothetical: four NICs took four different addresses in the window
    # this was captured from, so a MAC-blind parse returns a WRONG address
    # rather than merely an extra one.
    foreign = REAL_REPLY_FRAMES["foreign_mac"]

    assert DhcpReply.from_frame(foreign) is not None
    assert offers_from_frames([foreign], mac=GUEST_MAC) == []


def test_a_retransmitted_offer_appears_once_and_keeps_its_place() -> None:
    # The real capture showed OFFER, OFFER, ACK, OFFER, ACK for one address.
    first, second = REAL_REPLY_FRAMES["offer_198.51.100.36"], REAL_REPLY_FRAMES["offer_198.51.100.51"]

    assert offers_from_frames([first, second, first, second, first], mac=GUEST_MAC) == EXPECTED_OFFERS


def test_the_shipped_fixture_carries_no_site_configuration() -> None:
    # A header-level scrub is not enough and this test is what says so. The
    # captured frames originally carried the site's router, DNS and NTP servers
    # and its internal DNS domain in the OPTION block (3, 6, 15, 42, 54, 119),
    # which rewriting the addressing never touches. The block is truncated to
    # the message type; anything richer arriving here is a leak, not an
    # improvement.
    for name, frame in REAL_REPLY_FRAMES.items():
        body = frame[14 + 20 + 8 :]
        options = body[BOOTP_FIXED_SIZE + len(MAGIC_COOKIE) :]
        codes: list[int] = []
        position = 0
        while position < len(options) and options[position] != _OPT_END:
            codes.append(options[position])
            position += 2 + options[position + 1]

        assert codes == [_OPT_MESSAGE_TYPE], f"{name} carries options beyond the message type: {codes}"
        assert not any(options[position + 1 :]), f"{name} has data after the end marker"


# --------------------------------------------------------------------------
# What is not an offer
# --------------------------------------------------------------------------


def test_a_client_request_offers_nothing_and_is_not_a_reply() -> None:
    # This is not a formality. Without promiscuous mode a capture on a bridge
    # sees ONLY the broadcast DISCOVERs, every one of which carries this
    # address, so this rule is what keeps that case returning an honest empty
    # list rather than a fabricated 0.0.0.0.
    assert DhcpReply.from_frame(_reply_frame(yiaddr=_OFFERS_NOTHING)) is None


def test_a_packet_travelling_the_other_way_is_not_a_reply() -> None:
    assert DhcpReply.from_frame(_reply_frame(operation=BOOTREQUEST)) is None


def test_a_refusal_hands_out_no_address_so_it_never_counts() -> None:
    # A DHCPNAK sets yiaddr to zero, so the same rule that drops a request
    # drops it too, without needing to know the message type at all.
    assert DhcpReply.from_frame(_reply_frame(yiaddr=_OFFERS_NOTHING, message_type=DHCPNAK)) is None


@pytest.mark.parametrize(
    "frame",
    [
        pytest.param(_reply_frame(ethertype=ETH_P_IPV6), id="not-ipv4"),
        pytest.param(_reply_frame(protocol=socket.IPPROTO_TCP), id="not-udp"),
        pytest.param(_reply_frame(source_port=12345), id="not-from-the-server-port"),
        pytest.param(_reply_frame(destination_port=53), id="not-to-a-dhcp-port"),
    ],
)
def test_traffic_that_is_not_a_dhcp_reply_is_discarded(frame: bytes) -> None:
    # A capture sees the whole segment, so nearly everything arriving here
    # belongs to somebody else.
    assert DhcpReply.from_frame(frame) is None


# --------------------------------------------------------------------------
# Shapes the wire produces that a naive parse gets wrong
# --------------------------------------------------------------------------


def test_a_variable_length_ip_header_is_measured_not_assumed() -> None:
    # Assuming 20 bytes puts every later field four bytes out and yields a
    # plausible-looking wrong address rather than an obvious failure.
    reply = DhcpReply.from_frame(_reply_frame(ip_option_words=2))

    assert reply is not None
    assert reply.offered_ip == "198.51.100.36"


def test_a_packet_with_no_link_header_is_read_as_readily_as_a_frame() -> None:
    # A datagram packet socket and the Windows promiscuous socket both hand
    # over IP-level data, so the codec cannot require an Ethernet header.
    reply = DhcpReply.from_frame(_reply_frame(link_header=False))

    assert reply is not None
    assert reply.client_mac == GUEST_MAC


def test_a_single_vlan_tag_is_unwrapped() -> None:
    tagged = DhcpReply.from_frame(_reply_frame(tags=1))
    plain = DhcpReply.from_frame(_reply_frame())

    assert tagged is not None
    assert tagged == plain


def test_a_stacked_vlan_tag_is_refused_rather_than_guessed_at() -> None:
    # QinQ is out of scope. Returning nothing is acceptable; returning an
    # address read from the wrong offset is not.
    assert DhcpReply.from_frame(_reply_frame(tags=2)) is None


def test_a_plain_bootp_reply_without_options_still_hands_out_an_address() -> None:
    # Option 53 is not guaranteed to exist. Requiring it would discard a real
    # address because a field nobody asked about was absent.
    reply = DhcpReply.from_frame(_reply_frame(cookie=False))

    assert reply is not None
    assert reply.offered_ip == "198.51.100.36"
    assert reply.message_type is None


# --------------------------------------------------------------------------
# Malformed input is ordinary input
# --------------------------------------------------------------------------


def test_no_prefix_of_a_real_frame_ever_raises() -> None:
    # A capture truncated mid-packet is ordinary input, not an exception.
    frame = REAL_REPLY_FRAMES["offer_198.51.100.36"]

    for cut in range(len(frame) + 1):
        DhcpReply.from_frame(frame[:cut])


def test_a_frame_cut_before_the_fixed_header_ends_yields_nothing() -> None:
    frame = REAL_REPLY_FRAMES["offer_198.51.100.36"]

    for cut in range(_SMALLEST_PARSEABLE):
        assert DhcpReply.from_frame(frame[:cut]) is None


def test_a_frame_cut_after_the_fixed_header_still_reports_its_address() -> None:
    # Deliberate, and worth stating: everything that identifies an offer lives
    # in the 236-byte fixed header, so a capture taken with a small snapshot
    # length still answers the question correctly. Discarding it because the
    # option block was cut away would throw away a good address over a field
    # nobody asked about.
    frame = REAL_REPLY_FRAMES["offer_198.51.100.36"]

    reply = DhcpReply.from_frame(frame[:_SMALLEST_PARSEABLE])

    assert reply is not None
    assert (reply.offered_ip, reply.client_mac) == ("198.51.100.36", GUEST_MAC)
    assert reply.message_type is None


def test_a_truncated_option_block_ends_the_walk_instead_of_raising() -> None:
    frame = _reply_frame()

    # Two bytes into the options: enough for a code, not for its value.
    reply = DhcpReply.from_frame(frame[:-2])

    assert reply is not None
    assert reply.message_type is None


@pytest.mark.parametrize("size", [0, 1, 13, 14, 41, 300, 4096])
def test_arbitrary_bytes_never_raise(size: int) -> None:
    assert DhcpReply.from_frame(bytes(range(256)) * (size // 256) + bytes(range(size % 256))) is None


# --------------------------------------------------------------------------
# The ordering rule, and narrowing
# --------------------------------------------------------------------------


def test_merging_keeps_the_position_an_address_was_first_seen_at() -> None:
    assert merge_offers(["a", "b"], ["b", "c", "a", "d"]) == ["a", "b", "c", "d"]


def test_narrowing_to_one_message_type_selects_only_that_type() -> None:
    offer = _reply_frame(yiaddr="198.51.100.36", message_type=DHCPOFFER)
    ack = _reply_frame(yiaddr="198.51.100.51", message_type=DHCPACK)

    assert offers_from_frames([offer, ack], mac=GUEST_MAC) == EXPECTED_OFFERS
    assert offers_from_frames([offer, ack], mac=GUEST_MAC, message_types=frozenset({DHCPACK})) == ["198.51.100.51"]


def test_a_typeless_reply_matches_only_the_unnarrowed_default() -> None:
    # A plain BOOTP reply has no type to compare, so a caller that narrowed
    # deliberately must not be handed one anyway.
    plain = _reply_frame(cookie=False)

    assert offers_from_frames([plain], mac=GUEST_MAC) == ["198.51.100.36"]
    assert offers_from_frames([plain], mac=GUEST_MAC, message_types=frozenset({DHCPOFFER})) == []
