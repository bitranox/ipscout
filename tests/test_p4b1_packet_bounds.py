"""The echo records hold only what the wire can carry, and a wrong token is refused."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ipscout import packet


@pytest.mark.os_agnostic
@pytest.mark.parametrize("token", [b"", b"x", b"1234567", b"123456789"])
def test_a_payload_refuses_a_token_of_any_length_but_the_one_every_producer_makes(token: bytes) -> None:
    # A short token read back as itself plus the head of the filler, so the
    # reply could never match the request that carried it.
    with pytest.raises(ValidationError):
        packet.EchoPayload(token=token, filler=b"1234567pad")


@pytest.mark.os_agnostic
def test_a_payload_refuses_more_filler_than_any_echo_can_carry() -> None:
    largest = packet.MAX_PAYLOAD_SIZE_IPV6 - packet.MIN_PAYLOAD_SIZE

    packet.EchoPayload(token=b"ABCDEFGH", filler=bytes(largest))
    with pytest.raises(ValidationError):
        packet.EchoPayload(token=b"ABCDEFGH", filler=bytes(largest + 1))


@pytest.mark.os_agnostic
def test_reading_bytes_longer_than_any_echo_payload_finds_none_of_ours() -> None:
    too_long = packet.MAGIC + b"ABCDEFGH" + bytes(packet.MAX_PAYLOAD_SIZE_IPV6)

    assert packet.EchoPayload.from_bytes(too_long) is None


@pytest.mark.os_agnostic
@pytest.mark.parametrize("token", [b"x", b"123456789"])
def test_building_a_request_with_a_wrong_length_token_says_so(token: bytes) -> None:
    with pytest.raises(ValueError, match=f"token must be exactly {packet.TOKEN_SIZE} bytes, got {len(token)}") as caught:
        packet.build_echo_request(sequence=1, token=token)

    assert not isinstance(caught.value, ValidationError)


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("argument", "value"),
    [("sequence", -1), ("sequence", 65536), ("identifier", -1), ("identifier", 65536)],
)
def test_building_a_request_refuses_a_field_wider_than_its_sixteen_wire_bits(argument: str, value: int) -> None:
    arguments = {"sequence": 1, "identifier": 0, argument: value}

    with pytest.raises(ValueError, match=f"{argument} out of range 0-65535: {value}"):
        packet.build_echo_request(sequence=arguments["sequence"], identifier=arguments["identifier"], token=b"ABCDEFGH")


@pytest.mark.os_agnostic
def test_the_widest_sixteen_bit_fields_still_build_and_round_trip() -> None:
    datagram, token = packet.build_echo_request(sequence=65535, identifier=65535, token=b"ABCDEFGH")

    parsed = packet.parse_echo_reply(datagram)

    assert parsed is not None
    assert (parsed.sequence, parsed.identifier, parsed.token) == (65535, 65535, token)


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("field", "value"),
    [("icmp_type", 256), ("icmp_type", -1), ("code", 256), ("identifier", 65536), ("sequence", 65536), ("sequence", -1)],
)
def test_a_parsed_reply_refuses_a_value_wider_than_its_wire_field(field: str, value: int) -> None:
    fields: dict[str, int] = {"icmp_type": 0, "code": 0, "identifier": 0, "sequence": 0, field: value}

    with pytest.raises(ValidationError):
        packet.ParsedReply(
            icmp_type=fields["icmp_type"],
            code=fields["code"],
            identifier=fields["identifier"],
            sequence=fields["sequence"],
            payload=None,
        )
