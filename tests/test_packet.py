"""Protocol-layer stories: what the codec must accept, and what it must refuse."""

from __future__ import annotations

import struct

import pytest

from ipscout import packet


@pytest.mark.os_agnostic
def test_a_request_survives_the_round_trip_home() -> None:
    datagram, token = packet.build_echo_request(sequence=7, token=b"ABCDEFGH")

    parsed = packet.parse_echo_reply(datagram)

    assert parsed is not None
    assert parsed.sequence == 7
    assert parsed.token == token


@pytest.mark.os_agnostic
def test_the_checksum_of_a_stamped_buffer_cancels_itself_out() -> None:
    body = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + b"payload here"

    stamped = body[:2] + packet.checksum(body).to_bytes(2, "big") + body[4:]

    # A receiver validates by summing the whole buffer and expecting zero.
    assert packet.checksum(stamped) == 0


@pytest.mark.os_agnostic
def test_an_odd_length_buffer_is_padded_rather_than_rejected() -> None:
    odd = b"\x08\x00\x00\x00\x00\x01\xff"

    assert 0 <= packet.checksum(odd) <= 0xFFFF


@pytest.mark.os_agnostic
def test_ipv6_leaves_the_checksum_field_to_the_kernel() -> None:
    # The ICMPv6 checksum covers a pseudo-header containing the source address,
    # which user space does not reliably know, so the kernel fills it in.
    datagram, _ = packet.build_echo_request(sequence=1, is_ipv6=True, token=b"ABCDEFGH")

    assert datagram[0] == packet.ECHO_REQUEST_V6
    assert datagram[2:4] == b"\x00\x00"


@pytest.mark.os_agnostic
def test_ipv4_stamps_its_own_checksum() -> None:
    datagram, _ = packet.build_echo_request(sequence=1, token=b"ABCDEFGH")

    assert datagram[0] == packet.ECHO_REQUEST_V4
    assert datagram[2:4] != b"\x00\x00"
    assert packet.checksum(datagram) == 0


@pytest.mark.os_agnostic
@pytest.mark.parametrize("truncated", [b"", b"\x00", b"\x00\x00\x00", b"\x00" * (packet.HEADER_SIZE - 1)])
def test_a_datagram_too_short_to_be_a_header_is_refused(truncated: bytes) -> None:
    assert packet.parse_echo_reply(truncated) is None


@pytest.mark.os_agnostic
def test_a_header_with_no_payload_parses_but_carries_no_token() -> None:
    headerless = struct.pack("!BBHHH", 0, 0, 0, 1, 2)

    parsed = packet.parse_echo_reply(headerless)

    assert parsed is not None
    assert parsed.token is None


@pytest.mark.os_agnostic
def test_a_stranger_s_payload_is_not_mistaken_for_ours() -> None:
    # Several processes on one host can hold ICMP sockets and be handed copies
    # of each other's replies; a foreign payload must never match.
    foreign = struct.pack("!BBHHH", 0, 0, 0, 1, 2) + b"someone elses data entirely"

    parsed = packet.parse_echo_reply(foreign)

    assert parsed is not None
    assert parsed.payload is None
    assert parsed.token is None


@pytest.mark.os_agnostic
def test_a_payload_carrying_our_magic_but_a_different_token_still_parses() -> None:
    # Parsing succeeds; it is the caller's job to compare tokens and reject it.
    ours, _ = packet.build_echo_request(sequence=1, token=b"AAAAAAAA")
    theirs, _ = packet.build_echo_request(sequence=1, token=b"BBBBBBBB")

    parsed_ours = packet.parse_echo_reply(ours)
    parsed_theirs = packet.parse_echo_reply(theirs)

    assert parsed_ours is not None
    assert parsed_theirs is not None
    assert parsed_ours.token != parsed_theirs.token


@pytest.mark.os_agnostic
def test_a_payload_smaller_than_the_token_is_grown_to_fit() -> None:
    datagram, token = packet.build_echo_request(sequence=1, payload_size=0, token=b"ABCDEFGH")

    parsed = packet.parse_echo_reply(datagram)

    assert parsed is not None
    assert parsed.token == token


@pytest.mark.os_agnostic
@pytest.mark.parametrize("size", [56, 512, 4096, 65000])
def test_a_large_payload_is_padded_to_exactly_the_size_asked_for(size: int) -> None:
    datagram, _ = packet.build_echo_request(sequence=1, payload_size=size, token=b"ABCDEFGH")

    assert len(datagram) == packet.HEADER_SIZE + size


@pytest.mark.os_agnostic
def test_an_echo_request_is_not_counted_as_an_echo_reply() -> None:
    datagram, _ = packet.build_echo_request(sequence=1, token=b"ABCDEFGH")

    parsed = packet.parse_echo_reply(datagram)

    assert parsed is not None
    assert not packet.is_echo_reply(parsed, is_ipv6=False)


@pytest.mark.os_agnostic
def test_the_two_families_do_not_share_type_numbers() -> None:
    v4 = packet.parse_echo_reply(struct.pack("!BBHHH", packet.ECHO_REPLY_V4, 0, 0, 1, 1))
    v6 = packet.parse_echo_reply(struct.pack("!BBHHH", packet.ECHO_REPLY_V6, 0, 0, 1, 1))

    assert v4 is not None
    assert v6 is not None
    assert packet.is_echo_reply(v4, is_ipv6=False)
    assert not packet.is_echo_reply(v4, is_ipv6=True)
    assert packet.is_echo_reply(v6, is_ipv6=True)
    assert not packet.is_echo_reply(v6, is_ipv6=False)


@pytest.mark.os_agnostic
def test_every_generated_token_differs_from_the_last() -> None:
    tokens = {packet.build_echo_request(sequence=n)[1] for n in range(200)}

    assert len(tokens) == 200


@pytest.mark.os_agnostic
def test_the_identifier_we_send_is_carried_but_never_relied_upon() -> None:
    # Documenting the measured kernel behaviour this design works around: on an
    # unprivileged datagram socket the kernel overwrites this field, so the
    # value here is informational only and matching must use the token.
    datagram, _ = packet.build_echo_request(sequence=1, identifier=0xBEEF, token=b"ABCDEFGH")

    parsed = packet.parse_echo_reply(datagram)

    assert parsed is not None
    assert parsed.identifier == 0xBEEF
