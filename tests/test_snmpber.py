"""BER for SNMP: known vectors, the device's own object identifier, and hostile replies."""

from __future__ import annotations

import socket

import pytest
from snmp_agent import FakeAgent, honest

from ipscout.snmpber import (
    GET_REQUEST,
    GET_RESPONSE,
    NULL,
    OBJECT_IDENTIFIER,
    TIMETICKS,
    BerError,
    SnmpMessage,
    VarBind,
    decode_oid,
    encode_get_request,
    encode_message,
    encode_oid,
    parse_message,
)

pytestmark = pytest.mark.os_agnostic

SYS_UPTIME = "1.3.6.1.2.1.1.3.0"

# SNMPv1 GetRequest for sysUpTime.0, community "public", request id 1, assembled by hand:
# SEQUENCE { INTEGER 0, OCTET STRING "public", GetRequest { INTEGER 1, INTEGER 0, INTEGER 0,
# SEQUENCE { SEQUENCE { OID 1.3.6.1.2.1.1.3.0, NULL } } } }
UPTIME_REQUEST = bytes.fromhex("3026 020100 04067075626c6963 a019 020101 020100 020100 300e 300c 06082b06010201010300 0500")

# The matching GetResponse carrying TimeTicks 0x7eeeb0 (8318640), the value a print server
# reported when this was written.
UPTIME_RESPONSE = bytes.fromhex("3029 020100 04067075626c6963 a21c 020101 020100 020100 3011 300f 06082b06010201010300 43037eeeb0")


def test_a_get_request_is_encoded_byte_for_byte() -> None:
    assert encode_get_request(version=0, community=b"public", request_id=1, oids=[SYS_UPTIME]) == UPTIME_REQUEST


def test_a_get_response_is_taken_apart_by_structure() -> None:
    message = parse_message(UPTIME_RESPONSE)

    assert message == SnmpMessage(
        version=0,
        community=b"public",
        pdu_tag=GET_RESPONSE,
        request_id=1,
        error_status=0,
        error_index=0,
        bindings=(VarBind(oid=SYS_UPTIME, tag=TIMETICKS, value=bytes.fromhex("7eeeb0")),),
    )


def test_a_request_parses_back_to_what_was_encoded() -> None:
    message = parse_message(UPTIME_REQUEST)

    assert (message.pdu_tag, message.bindings) == (GET_REQUEST, (VarBind(oid=SYS_UPTIME, tag=NULL, value=b""),))


def test_the_object_identifier_a_print_server_sent_decodes() -> None:
    # sysObjectID.0 exactly as a print server returned it.
    assert decode_oid(bytes.fromhex("2b06010401 0b02030901")) == "1.3.6.1.4.1.11.2.3.9.1"


@pytest.mark.parametrize("dotted", ["1.3.6.1.4.1.311.1", f"1.3.6.1.4.1.{2**28 + 1}", "2.999.3", "0.39"])
def test_object_identifiers_round_trip_including_multi_byte_sub_identifiers(dotted: str) -> None:
    assert decode_oid(encode_oid(dotted)) == dotted


def test_a_sub_identifier_of_311_takes_two_octets() -> None:
    assert encode_oid("1.3.6.1.4.1.311") == bytes.fromhex("2b0601040182 37")


@pytest.mark.parametrize("dotted", ["", "1", "1.3.", "1..3", "3.1", "1.40", "1.3.a", "1.3.-1", "1.3.6\n"])
def test_a_malformed_dotted_identifier_is_refused(dotted: str) -> None:
    with pytest.raises(ValueError, match="object identifier"):
        encode_oid(dotted)


@pytest.mark.parametrize(
    ("body", "reason"),
    [(b"", "empty"), (bytes.fromhex("2b86"), "ends inside"), (bytes.fromhex("2b8001"), "leading 0x80")],
    ids=["empty", "unfinished", "non-minimal"],
)
def test_a_malformed_encoded_identifier_is_refused(body: bytes, reason: str) -> None:
    with pytest.raises(BerError, match=reason):
        decode_oid(body)


def test_a_value_longer_than_127_bytes_uses_the_long_length_form() -> None:
    description = b"x" * 300
    message = SnmpMessage(
        version=0,
        community=b"public",
        pdu_tag=GET_RESPONSE,
        request_id=9,
        error_status=0,
        error_index=0,
        bindings=(VarBind(oid="1.3.6.1.2.1.1.1.0", tag=0x04, value=description),),
    )

    assert parse_message(encode_message(message)) == message


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (UPTIME_RESPONSE[:-1], "past"),
        (UPTIME_RESPONSE + b"\x00", "after the message"),
        (bytes.fromhex("3080") + UPTIME_RESPONSE[2:], "indefinite"),
        (bytes.fromhex("3085ffffffffff"), "length field"),
        (bytes.fromhex("30"), "past"),
        (bytes.fromhex("3003 020100"), "community"),
        (bytes.fromhex("3029 020100 04067075626c6963 a21c 020101 020100 020100 3011 300f 0408 2b06010201010300 43037eeeb0"), "name"),
        (bytes.fromhex("3024 020100 04067075626c6963 a217 020101 020100 020100 300c 300a 06082b06010201010300"), "past"),
    ],
    ids=[
        "truncated",
        "trailing-bytes",
        "indefinite-length",
        "five-octet-length",
        "header-only",
        "no-community",
        "name-not-an-oid",
        "binding-without-value",
    ],
)
def test_a_malformed_reply_is_refused_naming_what_is_wrong(data: bytes, reason: str) -> None:
    with pytest.raises(BerError, match=reason):
        parse_message(data)


def test_a_binding_with_more_than_a_name_and_a_value_is_refused() -> None:
    # A binding carrying a NULL after its TimeTicks value; lengths computed, not typed.
    extra = bytes.fromhex("3011 06082b06010201010300 43037eeeb0 0500")
    data = bytes.fromhex("302b 020100 04067075626c6963 a21e 020101 020100 020100 3013") + extra

    with pytest.raises(BerError, match="more than a name and a value"):
        parse_message(data)


def test_an_object_identifier_tag_is_what_names_a_binding() -> None:
    assert OBJECT_IDENTIFIER == 0x06


def test_the_fake_agent_answers_a_real_request() -> None:
    with FakeAgent(honest()) as agent, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2.0)
        client.sendto(UPTIME_REQUEST, ("127.0.0.1", agent.port))
        reply = parse_message(client.recv(65535))

    assert reply.bindings == (VarBind(oid=SYS_UPTIME, tag=TIMETICKS, value=(12345).to_bytes(2, "big")),)
