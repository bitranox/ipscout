"""Caller mistakes refused at entry: active resolution, the ARP/NDP codecs, the echo builder, the DHCP watch.

Each refusal must come before anything is sent, before any buffer is sized from the
argument, and before a capture opens - so every test here runs unprivileged, and a test
that reached the network would fail with a permission error instead of the refusal it
asserts. Addresses are RFC 5737 / 3849 documentation addresses; hardware addresses are
RFC 7042 documentation values.
"""

from __future__ import annotations

import math
import socket

import pytest

from ipscout import lookup_mac, observe_dhcp_first_reachable
from ipscout.arp import build_arp_request, build_neighbour_solicitation
from ipscout.errors import IPScoutResolutionError, IPScoutUnsupportedError
from ipscout.models import AddressFamily
from ipscout.neighbours import resolve_active
from ipscout.packet import MAX_PAYLOAD_SIZE_IPV4, MAX_PAYLOAD_SIZE_IPV6, MIN_PAYLOAD_SIZE, build_echo_request

GUEST_MAC = "02:00:5e:10:00:00"


def _loopback_name() -> str:
    """Return this host's loopback interface name (``lo`` on Linux, ``lo0`` on macOS)."""

    return next(name for _index, name in socket.if_nameindex() if name.startswith("lo"))


# --------------------------------------------------------------------------
# resolve_active
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize("timeout", [0, -1.0, math.nan, math.inf, True, "5"])
def test_resolve_active_refuses_a_timeout_that_is_no_wait(timeout: object) -> None:
    with pytest.raises(ValueError, match=r"^active resolution refused its arguments: timeout: "):
        resolve_active("192.0.2.1", timeout=timeout)  # pyright: ignore[reportArgumentType] - the wrong type is the subject


@pytest.mark.os_agnostic
def test_resolve_active_refuses_text_that_is_not_an_address_in_the_callers_terms() -> None:
    with pytest.raises(ValueError, match=r"^active resolution refused its arguments: ip: 'nonsense' is not an IP address literal$"):
        resolve_active("nonsense")


@pytest.mark.os_agnostic
def test_resolve_active_refuses_an_int_rather_than_reading_it_as_an_address() -> None:
    # ip_address(5) is IPv4Address('0.0.0.5'): taking it would resolve an address nobody named.
    with pytest.raises(ValueError, match=r"^active resolution refused its arguments: ip: must be an address literal as text, not int$"):
        resolve_active(5)  # pyright: ignore[reportArgumentType] - the wrong type is the subject


@pytest.mark.os_posix
@pytest.mark.parametrize("by_index", [False, True])
def test_resolve_active_sends_on_the_interface_the_zone_names(*, by_index: bool) -> None:
    # The zone names loopback, which has no hardware address, so the refusal names it.
    # Without the zone honoured the route lookup picks some Ethernet interface and the
    # call dies on the raw socket (or, privileged, packs a zoned address and answers None).
    loopback = _loopback_name()
    zone = str(socket.if_nametoindex(loopback)) if by_index else loopback
    with pytest.raises(IPScoutUnsupportedError, match=rf"^{loopback} has no hardware address"):
        resolve_active(f"fe80::1%{zone}")


@pytest.mark.os_posix
def test_resolve_active_refuses_a_zone_naming_no_interface() -> None:
    with pytest.raises(IPScoutResolutionError, match=r"no interface named 'nosuchif0'"):
        resolve_active("fe80::1%nosuchif0")


@pytest.mark.os_posix
def test_lookup_mac_active_keeps_the_zone_it_was_given() -> None:
    loopback = _loopback_name()
    with pytest.raises(IPScoutUnsupportedError, match=rf"^{loopback} has no hardware address"):
        lookup_mac(f"fe80::1%{loopback}", active=True)


# --------------------------------------------------------------------------
# ARP / NDP codecs
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize("mac", ["02:00:5e:10", "02:00:5e:10:00:00:00", "02:00:5e:10:00:zz", ""])
def test_build_arp_request_refuses_a_sender_that_is_not_six_bytes(mac: str) -> None:
    with pytest.raises(ValueError, match=r"is not a 6-byte Ethernet hardware address$"):
        build_arp_request(sender_mac=mac, sender_ip="192.0.2.10", target_ip="192.0.2.1")


@pytest.mark.os_agnostic
@pytest.mark.parametrize("mac", ["02:00:5e:10", "02:00:5e:10:00:00:00"])
def test_build_neighbour_solicitation_refuses_a_sender_that_is_not_six_bytes(mac: str) -> None:
    with pytest.raises(ValueError, match=r"is not a 6-byte Ethernet hardware address$"):
        build_neighbour_solicitation(sender_mac=mac, target_ip="2001:db8::1")


@pytest.mark.os_agnostic
def test_every_written_form_of_one_address_builds_the_same_frame() -> None:
    frames = {
        build_arp_request(sender_mac=mac, sender_ip="192.0.2.10", target_ip="192.0.2.1") for mac in ("02:00:5e:10:00:00", "02-00-5E-10-00-00", "0200.5e10.0000")
    }
    assert len(frames) == 1
    (frame,) = frames
    assert frame[6:12] == bytes.fromhex("02005e100000")


# --------------------------------------------------------------------------
# build_echo_request
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("family", "size"),
    [
        (AddressFamily.IPV4, MAX_PAYLOAD_SIZE_IPV4 + 1),
        (AddressFamily.IPV4, MAX_PAYLOAD_SIZE_IPV6),
        (AddressFamily.IPV4, 70000),
        (AddressFamily.IPV6, MAX_PAYLOAD_SIZE_IPV6 + 1),
    ],
)
def test_build_echo_request_refuses_a_payload_the_family_cannot_carry(family: AddressFamily, size: int) -> None:
    limit = MAX_PAYLOAD_SIZE_IPV6 if family is AddressFamily.IPV6 else MAX_PAYLOAD_SIZE_IPV4
    with pytest.raises(ValueError, match=rf"^payload_size above the {family.value} maximum of {limit} bytes: {size}$"):
        build_echo_request(sequence=1, payload_size=size, family=family, token=b"abcdefgh")


@pytest.mark.os_agnostic
def test_build_echo_request_refuses_a_huge_payload_before_allocating_it() -> None:
    with pytest.raises(ValueError, match=r"^payload_size above the ipv4 maximum"):
        build_echo_request(sequence=1, payload_size=10**12, token=b"abcdefgh")


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("family", "size"), [(AddressFamily.IPV4, MAX_PAYLOAD_SIZE_IPV4), (AddressFamily.IPV6, MAX_PAYLOAD_SIZE_IPV6)])
def test_build_echo_request_builds_the_largest_payload_each_family_carries(family: AddressFamily, size: int) -> None:
    request = build_echo_request(sequence=1, payload_size=size, family=family, token=b"abcdefgh")
    assert len(request.datagram) == 8 + size
    assert size > MIN_PAYLOAD_SIZE


# --------------------------------------------------------------------------
# observe_dhcp_first_reachable
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("arguments", "field"),
    [
        ({"probe_timeout": 0}, "probe_timeout"),
        ({"probe_timeout": math.nan}, "probe_timeout"),
        ({"probe_timeout": -1.0}, "probe_timeout"),
        ({"probe_timeout": "2"}, "probe_timeout"),
        ({"tcp_port": 0}, "tcp_port"),
        ({"tcp_port": 65536}, "tcp_port"),
        ({"tcp_port": True}, "tcp_port"),
    ],
)
def test_first_reachable_refuses_its_probe_arguments_before_the_capture_opens(arguments: dict[str, object], field: str) -> None:
    # No capture is injected, so reaching the capture would raise IPScoutPermissionError
    # unprivileged (or watch the window out and answer None privileged): the ValueError
    # proves the refusal came first.
    with pytest.raises(ValueError, match=rf"^first-reachable DHCP watch refused its arguments: {field}: "):
        observe_dhcp_first_reachable(GUEST_MAC, interface="lo", timeout=0.2, **arguments)  # pyright: ignore[reportArgumentType] - wrong types are the subject
