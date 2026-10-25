"""SNMP system reads against a scripted agent on loopback: every state, every refusal."""

from __future__ import annotations

import asyncio
import socket
import time
from typing import TYPE_CHECKING, Any

import pytest
from snmp_agent import DESCRIPTION, NAME, NO_SUCH_NAME, OBJECT_ID, SYSTEM, UPTIME, FakeAgent, answer, honest

from ipscout import SnmpState, SnmpSystem, SnmpVersion, aread_snmp_system, read_snmp_system
from ipscout.snmpber import END_OF_MIB_VIEW, GET_RESPONSE, INTEGER, NULL, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE, TIMETICKS

if TYPE_CHECKING:
    from snmp_agent import Script

    from ipscout.snmpber import SnmpMessage

pytestmark = pytest.mark.os_agnostic

COMMUNITY = "s3cret-community"


def _read(agent: FakeAgent, **kwargs: Any) -> SnmpSystem:
    kwargs.setdefault("timeout", 1.0)
    return read_snmp_system(["127.0.0.1"], port=agent.port, **kwargs)["127.0.0.1"]


def test_an_agent_with_all_four_values_answers_them_all() -> None:
    with FakeAgent(honest()) as agent:
        system = _read(agent)

    assert system == SnmpSystem(
        host="127.0.0.1", state=SnmpState.ANSWERED, uptime_seconds=123.45, name="PRINTER", description="A print server", object_id="1.3.6.1.4.1.11.2.3.9.1"
    )


def test_one_request_asks_for_all_four_in_oid_order_with_the_callers_community() -> None:
    with FakeAgent(honest()) as agent:
        _read(agent, community=COMMUNITY)

    (request,) = agent.requests
    assert [binding.oid for binding in request.bindings] == [DESCRIPTION, OBJECT_ID, UPTIME, NAME]
    assert (request.version, request.community) == (0, COMMUNITY.encode())


def test_v2c_is_sent_as_version_1_on_the_wire() -> None:
    with FakeAgent(honest()) as agent:
        _read(agent, version=SnmpVersion.V2C)

    assert agent.requests[0].version == 1


@pytest.mark.parametrize(("ticks", "seconds"), [(0, 0.0), (2**31, 21474836.48), (2**32 - 1, 42949672.95)], ids=["zero", "sign-bit", "largest"])
def test_timeticks_are_read_unsigned(ticks: int, seconds: float) -> None:
    body = ticks.to_bytes(ticks.bit_length() // 8 + 1, "big")
    with FakeAgent(honest({**SYSTEM, UPTIME: (TIMETICKS, body)})) as agent:
        assert _read(agent).uptime_seconds == seconds


def test_a_long_description_arrives_whole() -> None:
    with FakeAgent(honest({**SYSTEM, DESCRIPTION: (OCTET_STRING, b"d" * 300)})) as agent:
        assert _read(agent).description == "d" * 300


def test_bytes_that_are_not_utf8_are_replaced_rather_than_fatal() -> None:
    with FakeAgent(honest({**SYSTEM, NAME: (OCTET_STRING, b"PR\xffNTER")})) as agent:
        assert _read(agent).name == "PR\ufffdNTER"


def test_v1_asks_again_without_a_value_the_agent_does_not_know() -> None:
    values = {oid: value for oid, value in SYSTEM.items() if oid != OBJECT_ID}
    with FakeAgent(honest(values)) as agent:
        system = _read(agent)

    assert (system.state, system.object_id, system.name) == (SnmpState.ANSWERED, None, "PRINTER")
    assert [len(request.bindings) for request in agent.requests] == [4, 3]
    assert agent.requests[0].request_id != agent.requests[1].request_id


def test_v1_with_none_of_the_values_is_still_an_answer() -> None:
    with FakeAgent(honest({})) as agent:
        system = _read(agent)

    assert system == SnmpSystem(host="127.0.0.1", state=SnmpState.ANSWERED)
    assert len(agent.requests) == 4


def test_v2c_reports_a_missing_value_as_none_in_one_exchange() -> None:
    values = {oid: value for oid, value in SYSTEM.items() if oid != NAME}
    with FakeAgent(honest(values)) as agent:
        system = _read(agent, version=SnmpVersion.V2C)

    assert (system.state, system.name, system.uptime_seconds) == (SnmpState.ANSWERED, None, 123.45)
    assert len(agent.requests) == 1


def test_a_v2c_exception_value_in_a_v1_reply_is_an_error() -> None:
    with FakeAgent(lambda request: [answer(request, {**SYSTEM, NAME: (END_OF_MIB_VIEW, b"")})]) as agent:
        system = _read(agent)

    assert system.state is SnmpState.ERROR
    assert system.error is not None and "name" in system.error


def test_a_value_of_the_wrong_type_is_an_error_naming_it() -> None:
    with FakeAgent(honest({**SYSTEM, UPTIME: (INTEGER, b"\x01")})) as agent:
        system = _read(agent)

    assert system.state is SnmpState.ERROR
    assert system.error is not None and "uptime" in system.error


def test_a_reply_to_another_request_is_set_aside_until_the_right_one_arrives() -> None:
    def script(request: SnmpMessage) -> list[bytes]:
        return [answer(request, request_id=request.request_id + 1), b"\x30\x00garbage", answer(request)]

    with FakeAgent(script) as agent:
        assert _read(agent).state is SnmpState.ANSWERED


def test_only_replies_to_other_requests_end_as_an_error_saying_so() -> None:
    with FakeAgent(lambda request: [answer(request, request_id=request.request_id + 1)]) as agent:
        system = _read(agent, timeout=0.5)

    assert system.state is SnmpState.ERROR
    assert system.error is not None and "another request" in system.error


def test_only_garbage_ends_as_an_error_saying_it_was_malformed() -> None:
    with FakeAgent(lambda request: [b"\x30\x05\x02\x01"]) as agent:
        system = _read(agent, timeout=0.5)

    assert system.state is SnmpState.ERROR
    assert system.error is not None and "malformed" in system.error


#: Replies that echo the request id but answer something else, and the words the error must use.
#: Declared as a typed table so each lambda's ``request`` takes its type from ``Script``.
_MISMATCHED: list[tuple[Script, str]] = [
    (lambda request: [answer(request, oids=[NAME, UPTIME, OBJECT_ID, DESCRIPTION])], "other values"),
    (lambda request: [answer(request, version=1)], "version"),
    (lambda request: [answer(request, error_status=5, error_index=1)], "genErr"),
    (lambda request: [answer(request, pdu_tag=0xA0)], "not a response"),
]


@pytest.mark.parametrize(("script", "said"), _MISMATCHED, ids=["other-oids", "other-version", "gen-err", "not-a-response"])
def test_a_reply_that_matches_the_request_id_but_not_the_request_is_an_error(script: Script, said: str) -> None:
    with FakeAgent(script) as agent:
        system = _read(agent)

    assert system.state is SnmpState.ERROR
    assert system.error is not None and said in system.error


def test_a_v1_no_such_name_with_an_index_outside_the_request_is_an_error() -> None:
    with FakeAgent(lambda request: [answer(request, error_status=NO_SUCH_NAME, error_index=9)]) as agent:
        assert _read(agent).state is SnmpState.ERROR


def test_an_agent_that_never_answers_is_silent() -> None:
    with FakeAgent(lambda request: []) as agent:
        system = _read(agent, timeout=0.3)

    assert system == SnmpSystem(host="127.0.0.1", state=SnmpState.SILENT)


@pytest.mark.parametrize(("host", "family"), [("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6)], ids=["ipv4", "ipv6"])
def test_a_closed_port_is_refused(host: str, family: socket.AddressFamily) -> None:
    # A connected UDP socket hears the ICMP port unreachable, spelled per platform. Measured
    # 2026-10-25: Linux ConnectionRefusedError (errno 111); Windows ProactorEventLoop OSError
    # winerror 1234 and SelectorEventLoop ConnectionResetError 10054. macOS: from CI.
    with socket.socket(family, socket.SOCK_DGRAM) as probe:
        probe.bind((host, 0))
        closed = probe.getsockname()[1]

    assert read_snmp_system([host], port=closed, timeout=1.0)[host].state is SnmpState.REFUSED


def test_a_closed_port_is_refused_under_the_selector_loop_too() -> None:
    # Windows' default loop is the proactor; a caller may run the selector loop instead, which
    # reports the same ICMP message differently (see the test above).
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        closed = probe.getsockname()[1]

    loop = asyncio.SelectorEventLoop()
    try:
        results = loop.run_until_complete(aread_snmp_system(["127.0.0.1"], port=closed, timeout=1.0))
    finally:
        loop.close()

    assert results["127.0.0.1"].state is SnmpState.REFUSED


def test_a_name_that_does_not_resolve_is_unreachable_not_raised() -> None:
    system = read_snmp_system(["nothing.invalid"], timeout=1.0)["nothing.invalid"]

    assert system.state is SnmpState.UNREACHABLE
    assert system.error


def test_an_ipv6_agent_answers() -> None:
    with FakeAgent(honest(), host="::1") as agent:
        system = read_snmp_system(["::1"], port=agent.port, timeout=1.0)["::1"]

    assert system.state is SnmpState.ANSWERED


def test_results_come_back_in_input_order_and_a_repeat_is_read_once() -> None:
    with FakeAgent(honest()) as agent:
        results = read_snmp_system(["nothing.invalid", "127.0.0.1", "nothing.invalid"], port=agent.port, timeout=1.0)

    assert list(results) == ["nothing.invalid", "127.0.0.1"]


def test_the_awaitable_form_gives_the_same_answer() -> None:
    with FakeAgent(honest()) as agent:
        system = asyncio.run(aread_snmp_system(["127.0.0.1"], port=agent.port, timeout=1.0))["127.0.0.1"]

    assert system.state is SnmpState.ANSWERED


def test_the_blocking_form_refuses_to_run_inside_an_event_loop() -> None:
    async def inside() -> None:
        read_snmp_system(["127.0.0.1"])

    with pytest.raises(RuntimeError, match="aread_snmp_system"):
        asyncio.run(inside())


@pytest.mark.parametrize(
    ("kwargs", "named"),
    [
        ({"port": 0}, "port"),
        ({"port": 65536}, "port"),
        ({"port": True}, "port"),
        ({"timeout": 0}, "timeout"),
        ({"timeout": "1"}, "timeout"),
        ({"concurrency": 0}, "concurrency"),
        ({"version": "v1"}, "version"),
        ({"community": ""}, "community"),
        ({"community": "x" * 256}, "community"),
    ],
    ids=["port-zero", "port-too-big", "port-bool", "timeout-zero", "timeout-text", "concurrency-zero", "version-text", "community-empty", "community-too-long"],
)
def test_bad_arguments_are_refused_before_anything_is_sent(kwargs: dict[str, Any], named: str) -> None:
    with FakeAgent(honest()) as agent, pytest.raises(ValueError, match=rf"{named}: ") as refused:
        arguments: dict[str, Any] = {"port": agent.port, **kwargs}
        read_snmp_system(["127.0.0.1"], **arguments)

    assert agent.requests == []
    assert "x" * 256 not in str(refused.value)


def test_one_bare_string_is_refused_as_hosts() -> None:
    with pytest.raises(ValueError, match="hosts: one string is a single host"):
        read_snmp_system("printer.test")


def test_the_community_never_appears_in_an_error() -> None:
    with FakeAgent(lambda request: [b"\x30\x05garbage"]) as agent:
        system = _read(agent, community=COMMUNITY, timeout=0.3)

    assert system.error is not None and COMMUNITY not in system.error


def test_the_deadline_bounds_a_host_whose_agent_never_answers() -> None:
    with FakeAgent(lambda request: []) as agent:
        started = time.monotonic()
        _read(agent, timeout=0.4)

    assert time.monotonic() - started < 2.0


#: An identifier body far past what SMI allows: one arc of thousands of digits.
HOSTILE_OID = b"\x2b" + b"\xff" * 2100 + b"\x7f"


def _tlv(tag: int, body: bytes) -> bytes:
    """One BER element, built here so a test can send what the library's encoder would refuse."""
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    size = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + body


def _reply_naming(request: SnmpMessage, name_body: bytes) -> bytes:
    """A GetResponse to ``request`` whose one binding NAME is ``name_body``."""
    binding = _tlv(SEQUENCE, _tlv(OBJECT_IDENTIFIER, name_body) + _tlv(NULL, b""))
    integers = b"".join(_tlv(INTEGER, value.to_bytes(4, "big", signed=True)) for value in (request.request_id, 0, 0))
    pdu = _tlv(GET_RESPONSE, integers + _tlv(SEQUENCE, binding))
    return _tlv(SEQUENCE, _tlv(INTEGER, b"\x00") + _tlv(OCTET_STRING, request.community) + pdu)


def test_an_object_id_value_past_what_smi_allows_is_an_error_not_a_raise() -> None:
    with FakeAgent(honest({**SYSTEM, OBJECT_ID: (OBJECT_IDENTIFIER, HOSTILE_OID)})) as agent:
        system = _read(agent)

    assert system.state is SnmpState.ERROR
    assert system.error is not None and "object_id" in system.error


def test_a_binding_name_past_what_smi_allows_is_set_aside_not_raised() -> None:
    with FakeAgent(lambda request: [_reply_naming(request, HOSTILE_OID)]) as agent:
        system = _read(agent, timeout=0.5)

    assert system.state is SnmpState.ERROR
    assert system.error is not None and "malformed" in system.error


@pytest.mark.parametrize(("body", "seconds"), [(b"\xff\xff\xff\xff", 42949672.95), (b"\x80\x00\x00\x00", 21474836.48)], ids=["largest", "top-bit"])
def test_four_timeticks_octets_without_the_leading_zero_are_read_unsigned(body: bytes, seconds: float) -> None:
    # X.690 reads a set top bit as negative, which TimeTicks never is; embedded agents that drop
    # the leading zero mean the unsigned value, as net-snmp reads it.
    with FakeAgent(honest({**SYSTEM, UPTIME: (TIMETICKS, body)})) as agent:
        assert _read(agent).uptime_seconds == seconds


def test_a_shorter_timeticks_with_its_top_bit_set_is_still_an_error() -> None:
    with FakeAgent(honest({**SYSTEM, UPTIME: (TIMETICKS, b"\xff")})) as agent:
        system = _read(agent)

    assert system.state is SnmpState.ERROR
    assert system.error is not None and "uptime" in system.error


def test_a_v2c_reply_saying_no_such_name_is_an_error_not_a_re_ask() -> None:
    with FakeAgent(lambda request: [answer(request, error_status=NO_SUCH_NAME, error_index=1)]) as agent:
        system = _read(agent, version=SnmpVersion.V2C)

    assert system.state is SnmpState.ERROR
    assert system.error is not None and "noSuchName" in system.error
    assert len(agent.requests) == 1


def test_one_deadline_covers_every_v1_re_ask() -> None:
    # Each answer drops one value after a pause; four rounds of 0.3 s would take 1.2 s if each
    # re-ask got a fresh deadline.
    delayed = honest({})

    def slow(request: SnmpMessage) -> list[bytes]:
        time.sleep(0.3)
        return delayed(request)

    with FakeAgent(slow) as agent:
        started = time.monotonic()
        _read(agent, timeout=0.7)
        elapsed = time.monotonic() - started

    assert elapsed < 1.0
    assert len(agent.requests) < 4
