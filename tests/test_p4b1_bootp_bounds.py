"""A DHCP reply record holds only what a captured reply can carry, and a MAC spelled another way is refused."""

from __future__ import annotations

import ipaddress

import pytest
from dhcp_capture_fixture import REAL_REPLY_FRAMES
from pydantic import ValidationError

from ipscout.bootp import DhcpReply, offers_from_frames

pytestmark = pytest.mark.os_agnostic

#: The hardware address the captured frames were offered to.
GUEST_MAC = "02:00:5e:10:00:00"

#: The yiaddr a request and a DHCPNAK carry, built rather than spelled so it
#: does not read as a bind address.
_OFFERS_NOTHING = str(ipaddress.IPv4Address(0))

_VALID = {"client_mac": GUEST_MAC, "offered_ip": "198.51.100.36", "server_ip": "198.51.100.1", "transaction_id": 1}


def test_every_captured_reply_still_parses_into_a_valid_record() -> None:
    replies = [DhcpReply.from_frame(frame) for frame in REAL_REPLY_FRAMES.values()]

    assert all(reply is not None for reply in replies)
    assert [reply.offered_ip for reply in replies if reply is not None] == ["198.51.100.36", "198.51.100.51", "198.51.100.99"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("client_mac", "junk"),
        ("client_mac", "02:00:5E:10:00:00"),
        ("client_mac", "02-00-5e-10-00-00"),
        ("client_mac", "00:00:00:00:00:00"),
        ("offered_ip", _OFFERS_NOTHING),
        ("offered_ip", "2001:db8::1"),
        ("offered_ip", "not an address"),
        ("server_ip", "2001:db8::1"),
        ("server_ip", ""),
        ("transaction_id", -1),
        ("transaction_id", 2**32),
    ],
)
def test_a_reply_record_refuses_a_value_no_captured_reply_can_carry(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        DhcpReply.model_validate({**_VALID, field: value})


def test_the_widest_transaction_id_is_still_a_reply() -> None:
    reply = DhcpReply.model_validate({**_VALID, "transaction_id": 2**32 - 1})

    assert reply.transaction_id == 2**32 - 1


@pytest.mark.parametrize("spelling", ["02:00:5E:10:00:00", "02-00-5e-10-00-00", "0200.5e10.0000"])
def test_offers_match_every_written_form_of_the_address(spelling: str) -> None:
    # Before, each of these silently returned [], which reads as "nothing was
    # offered to that machine" while the offers were right there in the frames.
    assert offers_from_frames(REAL_REPLY_FRAMES.values(), mac=spelling) == ["198.51.100.36", "198.51.100.51"]


@pytest.mark.parametrize("spelling", ["nonsense", ""])
def test_offers_refuse_a_mac_that_is_no_address_rather_than_finding_nothing(spelling: str) -> None:
    with pytest.raises(ValueError, match="is not a hardware address") as caught:
        offers_from_frames(REAL_REPLY_FRAMES.values(), mac=spelling)

    assert not isinstance(caught.value, ValidationError)
    assert repr(spelling) in str(caught.value)


def test_offers_still_match_the_canonical_spelling() -> None:
    assert offers_from_frames(REAL_REPLY_FRAMES.values(), mac=GUEST_MAC) == ["198.51.100.36", "198.51.100.51"]
