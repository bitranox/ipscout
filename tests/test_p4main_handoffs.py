"""Refusals at the entry of lookup_mac and DhcpSession.

Both used to accept an input no caller could mean and answer as though it
were an observation: a host name made lookup_mac report "nothing known about
this address", and a NaN window made a DHCP session watch, then fail while
building its own report.
"""

from __future__ import annotations

import math

import pytest

import ipscout
from ipscout.dhcp import DhcpSession

GUEST_MAC = "02:00:5e:10:00:00"


@pytest.mark.parametrize("written", ["example.test", "999.1.1.1", "192.0.2.1%eth0", ""])
def test_lookup_mac_refuses_what_is_not_an_address_literal(written: str) -> None:
    with pytest.raises(ValueError, match="is not an IP address literal"):
        ipscout.lookup_mac(written)


def test_lookup_mac_still_answers_for_a_literal() -> None:
    answer = ipscout.lookup_mac("127.0.0.1")

    assert answer.ip == "127.0.0.1"


@pytest.mark.parametrize("value", [math.nan, math.inf])
def test_a_dhcp_session_refuses_a_non_finite_timeout_before_capturing(value: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        DhcpSession(GUEST_MAC, timeout=value)


@pytest.mark.parametrize("value", [math.nan, math.inf])
def test_a_dhcp_session_refuses_a_non_finite_settle_before_capturing(value: float) -> None:
    with pytest.raises(ValueError, match="settle"):
        DhcpSession(GUEST_MAC, settle=value)
