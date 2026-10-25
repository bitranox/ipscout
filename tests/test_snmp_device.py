"""One read of a real SNMP agent, named by the environment; skipped everywhere else."""

from __future__ import annotations

import os

import pytest

from ipscout import SnmpState, SnmpVersion, read_snmp_system

HOST = os.environ.get("IPSCOUT_SNMP_TEST_HOST", "")
COMMUNITY = os.environ.get("IPSCOUT_SNMP_TEST_COMMUNITY", "public")

pytestmark = [
    pytest.mark.local_only,
    pytest.mark.skipif(not HOST, reason="IPSCOUT_SNMP_TEST_HOST names no agent to read"),
]


def test_a_real_agent_answers_all_four_values_over_v1() -> None:
    system = read_snmp_system([HOST], community=COMMUNITY)[HOST]

    assert system.state is SnmpState.ANSWERED
    assert system.uptime_seconds is not None and system.uptime_seconds > 0
    assert system.name and system.description and system.object_id


@pytest.mark.skipif(os.environ.get("IPSCOUT_SNMP_TEST_V1_ONLY") != "1", reason="the agent is not declared v1-only")
def test_a_v1_only_agent_stays_silent_to_v2c() -> None:
    assert read_snmp_system([HOST], community=COMMUNITY, version=SnmpVersion.V2C, timeout=2.0)[HOST].state is SnmpState.SILENT
