"""Pass-5 follow-ups: producers held to the bounds their records now declare."""

from __future__ import annotations

import socket

import pytest

from ipscout.dhcp import DhcpSession
from ipscout.models import MAX_TIMEOUT, SweepScope
from ipscout.resolve import reverse_dns

pytestmark = pytest.mark.os_agnostic


def test_one_network_written_as_text_is_refused_rather_than_split_into_characters() -> None:
    with pytest.raises(ValueError, match=r"not one network as text; pass \['192\.0\.2\.0/24'\]"):
        SweepScope.from_networks("192.0.2.0/24", limit=256)
    assert SweepScope.from_networks(["192.0.2.0/24"], limit=256).limit == 256


def test_a_dhcp_settle_past_the_longest_wait_is_refused_before_the_watch() -> None:
    # The report the CLI builds from this session refuses such a settle, so
    # accepting it here would run the whole watch and then fail to report it.
    with pytest.raises(ValueError, match="settle must be a finite number of seconds from 0 to"):
        DhcpSession("02:00:5e:10:00:00", interface="lo", timeout=1.0, settle=MAX_TIMEOUT + 1)
    DhcpSession("02:00:5e:10:00:00", interface="lo", timeout=1.0, settle=MAX_TIMEOUT)


def test_an_empty_ptr_answer_reads_as_no_name(monkeypatch: pytest.MonkeyPatch) -> None:
    # socket.gethostbyaddr is the network edge; a resolver answering a PTR
    # with an empty name must not reach a TraceHop, which refuses hostname "".
    def empty_answer(ip: str) -> tuple[str, list[str], list[str]]:
        return "", [], [ip]

    monkeypatch.setattr(socket, "gethostbyaddr", empty_answer)

    assert reverse_dns("192.0.2.1") is None
