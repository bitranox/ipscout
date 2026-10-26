"""Which status one IcmpSendEcho call reports, and what the MTU bisection reads from it.

The call reports in two places. With no reply it returns 0 and the status is
in GetLastError; with a reply it returns the count, and the status is in the
reply's own Status field - which is not SUCCESS when the reply is an ICMP
error. The rows below are what a Windows host returned (Python 3.13,
2026-10-26): a router's TTL expiry came back as count 1 with Status 11013,
a packet larger than the local MTU as count 0 with 11009, and an address
nobody holds as count 0 with 11010.
"""

from __future__ import annotations

import pytest

from ipscout.mtu import fits_unfragmented
from ipscout.winapi import IpStatus, echo_status

pytestmark = pytest.mark.os_agnostic


@pytest.mark.parametrize(
    ("replies", "reply_status", "last_error", "expected"),
    [
        (1, 0, 0, IpStatus.SUCCESS),
        (1, 11013, 0, IpStatus.TTL_EXPIRED_TRANSIT),
        (0, 11009, 11009, IpStatus.PACKET_TOO_BIG),
        (0, 11010, 11010, IpStatus.REQ_TIMED_OUT),
        # A reply's own status wins over a stale GetLastError, and with no
        # reply the buffer is not read at all.
        (1, 11009, 0, IpStatus.PACKET_TOO_BIG),
        (0, 0, 11010, IpStatus.REQ_TIMED_OUT),
    ],
)
def test_the_status_comes_from_the_reply_when_there_is_one(replies: int, reply_status: int, last_error: int, expected: IpStatus) -> None:
    assert echo_status(replies, reply_status=reply_status, last_error=last_error) is expected


def test_an_unlisted_code_reads_as_none() -> None:
    assert echo_status(0, reply_status=0, last_error=99999) is None


@pytest.mark.parametrize(
    ("replies", "reply_status", "last_error", "fits"),
    [
        (1, 0, 0, True),
        # A router's "packet too big" arrives as a reply carrying that status.
        # Before, any reply counted as fitting and the MTU came out too large.
        (1, 11009, 0, False),
        (0, 11009, 11009, False),
        # No evidence of a size limit: a silent host, a hop limit spent, an
        # unlisted code. The bisection keeps climbing, as Linux reports the
        # route's MTU for a host that is down.
        (0, 11010, 11010, True),
        (1, 11013, 0, True),
        (0, 0, 99999, True),
    ],
)
def test_only_packet_too_big_says_a_size_does_not_fit(replies: int, reply_status: int, last_error: int, fits: bool) -> None:
    assert fits_unfragmented(echo_status(replies, reply_status=reply_status, last_error=last_error)) is fits
