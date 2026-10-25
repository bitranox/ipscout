"""SnmpSystem refuses every pairing of state and fields that cannot happen."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from ipscout.models import MAX_UPTIME_SECONDS, CommandName, SnmpState, SnmpSystem, SnmpVersion

pytestmark = pytest.mark.os_agnostic


def test_an_answer_carries_its_values() -> None:
    system = SnmpSystem(
        host="printer.test", state=SnmpState.ANSWERED, uptime_seconds=83186.4, name="PRINTER", description="A print server", object_id="1.3.6.1.4.1.11.2.3.9.1"
    )

    assert (system.uptime_seconds, system.name, system.object_id) == (83186.4, "PRINTER", "1.3.6.1.4.1.11.2.3.9.1")


def test_an_answer_may_lack_every_value() -> None:
    assert SnmpSystem(host="h", state=SnmpState.ANSWERED).name is None


@pytest.mark.parametrize(
    "fields",
    [
        {"state": SnmpState.SILENT, "name": "x"},
        {"state": SnmpState.REFUSED, "uptime_seconds": 1.0},
        {"state": SnmpState.ERROR, "error": "bad", "description": "x"},
        {"state": SnmpState.ANSWERED, "error": "why"},
        {"state": SnmpState.ERROR},
        {"state": SnmpState.UNREACHABLE},
        {"state": SnmpState.SILENT, "error": "why"},
        {"state": SnmpState.ERROR, "error": ""},
        {"state": SnmpState.ANSWERED, "uptime_seconds": -0.01},
        {"state": SnmpState.ANSWERED, "uptime_seconds": MAX_UPTIME_SECONDS + 0.01},
        {"state": SnmpState.ANSWERED, "object_id": "1.3.6.\n"},
        {"state": SnmpState.ANSWERED, "object_id": "iso.3.6"},
    ],
    ids=[
        "silent-with-name",
        "refused-with-uptime",
        "error-with-value",
        "answered-with-error",
        "error-without-reason",
        "unreachable-without-reason",
        "silent-with-error",
        "empty-error",
        "negative-uptime",
        "uptime-past-timeticks",
        "oid-with-newline",
        "oid-not-dotted",
    ],
)
def test_an_impossible_record_is_refused(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SnmpSystem(host="h", **fields)


def test_versions_carry_their_wire_numbers() -> None:
    assert (SnmpVersion.V1.wire_number, SnmpVersion.V2C.wire_number) == (0, 1)


def test_the_command_has_a_name() -> None:
    assert CommandName.SNMP_SYSTEM.value == "snmp-system"
