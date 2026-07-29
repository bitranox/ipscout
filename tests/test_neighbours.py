"""Neighbour-cache stories: the scoped MAC answer, and each platform's format.

The macOS and Windows decoders get synthetic-buffer coverage because neither
can execute on the Linux development host, and both are variable-length walks
that go wrong silently.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import socket
import struct

import pytest

import ipscout
from ipscout import bsdroute
from ipscout import neighbours_linux as linux
from ipscout import neighbours_macos as macos
from ipscout import neighbours_windows as windows
from ipscout.models import AddressFamily, MacScope, Neighbour, NeighbourState
from ipscout.neighbours import resolve_active

pytestmark = pytest.mark.os_agnostic


# --------------------------------------------------------------------------
# Comparing hardware addresses across how they are written
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "written",
    ["aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "aabbccddeeff"],
)
def test_every_common_written_form_compares_equal(written: str) -> None:
    # A caller pasting an address from a switch, a DHCP lease or another tool
    # gets a different separator each time; refusing all but one would make
    # the search useless in practice.
    assert ipscout.normalise_mac(written) == "aa:bb:cc:dd:ee:ff"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("bad", ["", "nonsense", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "gg:bb:cc:dd:ee:ff"])
def test_something_that_is_not_a_hardware_address_is_refused(bad: str) -> None:
    assert ipscout.normalise_mac(bad) is None


# --------------------------------------------------------------------------
# The scoped answer
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_routed_address_answers_with_the_next_hop_and_says_so() -> None:
    # The whole reason MacLookup carries a scope. The frame sent toward a
    # routed address carries the ROUTER's hardware address; the remote host's
    # own never appears here. Reporting it as though it were the host's would
    # be a lie a bare string could not avoid telling.
    answer = ipscout.lookup_mac("8.8.8.8")

    if answer.scope is MacScope.UNKNOWN:
        pytest.skip("this host has no route to a public address")
    assert answer.scope is MacScope.NEXT_HOP
    assert answer.via_ip is not None
    assert answer.via_ip != "8.8.8.8"


@pytest.mark.os_agnostic
def test_the_strict_function_refuses_to_answer_for_a_routed_address() -> None:
    # It could return the gateway's address, and that is exactly what it must
    # not do without saying so.
    assert ipscout.get_mac_address("8.8.8.8") is None


@pytest.mark.os_agnostic
def test_an_unknown_address_is_its_own_state_rather_than_an_error() -> None:
    # RFC 5737 TEST-NET-3: nothing on this network is reachable.
    answer = ipscout.lookup_mac("203.0.113.199")

    assert answer.scope in {MacScope.UNKNOWN, MacScope.NEXT_HOP}
    if answer.scope is MacScope.UNKNOWN:
        assert answer.mac is None


@pytest.mark.os_agnostic
def test_every_cache_entry_names_a_learned_address() -> None:
    # An entry with no hardware address is an unanswered query, not a
    # neighbour, and including it would put nulls into any scan built on this.
    assert all(entry.mac for entry in ipscout.neighbours())


@pytest.mark.os_agnostic
def test_searching_for_an_unknown_hardware_address_finds_nothing() -> None:
    assert ipscout.find_ip_by_mac("aa:bb:cc:dd:ee:ff") == []


@pytest.mark.os_agnostic
def test_searching_for_something_that_is_not_an_address_is_refused() -> None:
    with pytest.raises(ValueError, match="not a hardware address"):
        ipscout.find_ip_by_mac("nonsense")


@pytest.mark.os_agnostic
def test_a_known_address_is_found_however_it_is_written() -> None:
    entries = ipscout.neighbours()
    if not entries:
        pytest.skip("this host's neighbour cache is empty")
    mac = entries[0].mac
    assert mac is not None

    found = ipscout.find_ip_by_mac(mac)
    also_found = ipscout.find_ip_by_mac(mac.upper().replace(":", "-"))

    assert entries[0].ip in found
    assert found == also_found


@pytest.mark.os_agnostic
def test_a_sweep_too_wide_to_be_reasonable_names_the_network_at_fault() -> None:
    # The default set comes from this host's own interfaces, so a container
    # bridge on a /16 is enough to trip it. An error that does not say which
    # network is at fault leaves the caller with nothing to act on.
    with pytest.raises(ValueError, match=r"holds \d+ addresses"):
        ipscout.arp_scan("10.0.0.0/8")


# --------------------------------------------------------------------------
# Linux wire format
# --------------------------------------------------------------------------


def _nd_message(*, family: int, state: int, ip: bytes, mac: bytes, ifindex: int = 1) -> bytes:
    """Build one RTM_NEWNEIGH message with its attributes."""

    body = linux._NDMSG.pack(family, 0, 0, ifindex, state, 0, 0)
    attributes = b""
    for kind, value in ((linux._NDA_DST, ip), (linux._NDA_LLADDR, mac)):
        padded = value + b"\x00" * (-(len(value) + 4) % 4)
        attributes += struct.pack("=HH", 4 + len(value), kind) + padded
    payload = body + attributes
    return struct.pack("=IHHII", 16 + len(payload), linux._RTM_NEWNEIGH, 0, 0, 0) + payload


@pytest.mark.os_agnostic
def test_a_linux_entry_is_decoded_with_its_address_and_state() -> None:
    message = _nd_message(
        family=socket.AF_INET,
        state=linux._NUD_REACHABLE,
        ip=socket.inet_aton("192.168.1.5"),
        mac=bytes.fromhex("aabbccddeeff"),
    )

    entries, done = linux.parse_neighbour_dump(message)

    assert done is False
    assert [(e.ip, e.mac, e.state) for e in entries] == [("192.168.1.5", "aa:bb:cc:dd:ee:ff", NeighbourState.REACHABLE)]


@pytest.mark.os_agnostic
@pytest.mark.parametrize("state", [0x01, 0x20])
def test_an_unanswered_or_failed_linux_query_is_not_a_neighbour(state: int) -> None:
    message = _nd_message(family=socket.AF_INET, state=state, ip=socket.inet_aton("192.168.1.9"), mac=bytes(6))

    entries, _done = linux.parse_neighbour_dump(message)

    assert entries == []


@pytest.mark.os_agnostic
def test_a_linux_entry_with_an_all_zero_address_is_dropped() -> None:
    # Point-to-point interfaces report all zeros, meaning nothing was learned
    # rather than an address of zero.
    message = _nd_message(family=socket.AF_INET, state=linux._NUD_STALE, ip=socket.inet_aton("10.1.2.3"), mac=bytes(6))

    entries, _done = linux.parse_neighbour_dump(message)

    assert entries == []


@pytest.mark.os_agnostic
def test_a_multicast_linux_entry_is_not_a_neighbour() -> None:
    # Its link address is derived from the group, not learned from a host, so
    # it would be noise in any answer to "who holds this address".
    message = _nd_message(
        family=socket.AF_INET6,
        state=linux._NUD_REACHABLE,
        ip=socket.inet_pton(socket.AF_INET6, "ff02::16"),
        mac=bytes.fromhex("333300000016"),
    )

    entries, _done = linux.parse_neighbour_dump(message)

    assert entries == []


@pytest.mark.os_agnostic
def test_a_linux_ipv6_entry_carries_its_family() -> None:
    message = _nd_message(
        family=socket.AF_INET6,
        state=linux._NUD_STALE,
        ip=socket.inet_pton(socket.AF_INET6, "fe80::1"),
        mac=bytes.fromhex("aabbccddeeff"),
    )

    entries, _done = linux.parse_neighbour_dump(message)

    assert entries[0].family is AddressFamily.IPV6


@pytest.mark.os_agnostic
def test_the_end_of_a_linux_dump_is_reported() -> None:
    done_message = struct.pack("=IHHII", 16, 3, 0, 0, 0)

    _entries, done = linux.parse_neighbour_dump(done_message)

    assert done is True


@pytest.mark.os_agnostic
@pytest.mark.parametrize("size", [0, 1, 15, 20])
def test_a_truncated_linux_dump_is_refused_rather_than_misread(size: int) -> None:
    message = _nd_message(
        family=socket.AF_INET,
        state=linux._NUD_REACHABLE,
        ip=socket.inet_aton("192.168.1.5"),
        mac=bytes.fromhex("aabbccddeeff"),
    )

    entries, _done = linux.parse_neighbour_dump(message[:size])

    assert entries == []


# --------------------------------------------------------------------------
# macOS wire format
# --------------------------------------------------------------------------


def _sockaddr_dl(mac: bytes, name: bytes = b"en0") -> bytes:
    """Build a sockaddr_dl: the name and the address share one buffer."""

    data = name + mac
    length = bsdroute.SOCKADDR_DL.size + len(data)
    return bsdroute.SOCKADDR_DL.pack(length, bsdroute.AF_LINK, 1, 6, len(name), len(mac), 0) + data


def _arp_message(ip: str, link: bytes) -> bytes:
    """Build one NET_RT_FLAGS entry: header, destination, link address."""

    dst = struct.pack("=BBH4s8s", 16, socket.AF_INET, 0, socket.inet_aton(ip), b"\x00" * 8)
    payload = dst + link + b"\x00" * (-len(link) % 4)
    header = bsdroute.RT_MSGHDR.pack(
        bsdroute.RT_MSGHDR.size + len(payload),
        5,
        0x04,
        1,
        bsdroute.RTF_UP | bsdroute.RTF_LLINFO,
        bsdroute.RTA_DST | bsdroute.RTA_GATEWAY,
        0,
        0,
        0,
        0,
        0,
        b"\x00" * 56,
    )
    return header + payload


@pytest.mark.os_agnostic
def test_a_macos_entry_is_decoded_with_its_hardware_address() -> None:
    message = _arp_message("192.168.1.5", _sockaddr_dl(bytes.fromhex("aabbccddeeff")))

    entries = macos.parse_neighbour_dump(message, AddressFamily.IPV4)

    assert [(e.ip, e.mac) for e in entries] == [("192.168.1.5", "aa:bb:cc:dd:ee:ff")]


@pytest.mark.os_agnostic
def test_a_macos_link_address_is_found_after_a_name_of_any_length() -> None:
    # sockaddr_dl stores the interface name and the address back to back, so
    # reading the address at a fixed offset works only while the name happens
    # to be the length you assumed.
    for name in (b"e", b"en0", b"bridge100"):
        message = _arp_message("192.168.1.7", _sockaddr_dl(bytes.fromhex("112233445566"), name))

        entries = macos.parse_neighbour_dump(message, AddressFamily.IPV4)

        assert [e.mac for e in entries] == ["11:22:33:44:55:66"], name


@pytest.mark.os_agnostic
def test_a_macos_entry_with_no_learned_address_is_dropped() -> None:
    message = _arp_message("192.168.1.8", _sockaddr_dl(bytes(6)))

    assert macos.parse_neighbour_dump(message, AddressFamily.IPV4) == []


@pytest.mark.os_agnostic
@pytest.mark.parametrize("size", [0, 1, 50, 91])
def test_a_truncated_macos_dump_is_refused_rather_than_misread(size: int) -> None:
    message = _arp_message("192.168.1.5", _sockaddr_dl(bytes.fromhex("aabbccddeeff")))

    assert macos.parse_neighbour_dump(message[:size], AddressFamily.IPV4) == []


@pytest.mark.os_agnostic
def test_a_link_sockaddr_claiming_more_than_it_holds_does_not_read_past_the_end() -> None:
    truncated = _sockaddr_dl(bytes.fromhex("aabbccddeeff"))[:6]

    assert bsdroute.link_address_of(truncated) is None


# --------------------------------------------------------------------------
# Windows decoding
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_windows_hardware_address_is_read_from_its_declared_length() -> None:
    # The row carries a fixed 32-byte buffer; only the declared length is
    # meaningful, and reading the whole buffer would append 26 zero bytes.
    assert windows.format_mac(bytes.fromhex("aabbccddeeff") + bytes(26), 6) == "aa:bb:cc:dd:ee:ff"


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("raw", "length"), [(bytes(32), 6), (bytes.fromhex("aabbccddeeff") + bytes(26), 0), (bytes(32), 8)])
def test_a_windows_row_without_a_learned_address_reports_none(raw: bytes, length: int) -> None:
    assert windows.format_mac(raw, length) is None


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, NeighbourState.FAILED), (1, NeighbourState.INCOMPLETE), (4, NeighbourState.STALE), (5, NeighbourState.REACHABLE), (6, NeighbourState.PERMANENT)],
)
def test_windows_numbers_its_states_differently_from_linux(value: int, expected: NeighbourState) -> None:
    # Windows uses an enumeration where Linux uses a bitmask, so the two
    # mappings cannot be shared and this pins the one that is easy to get
    # wrong by assuming they match.
    assert windows.state_of(value) is expected


@pytest.mark.os_agnostic
def test_an_unrecognised_windows_state_is_not_guessed() -> None:
    assert windows.state_of(99) is NeighbourState.OTHER


# --------------------------------------------------------------------------
# The record itself
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_neighbour_record_cannot_be_edited_after_the_fact() -> None:
    from pydantic import ValidationError

    entry = Neighbour(ip="192.168.1.5", mac="aa:bb:cc:dd:ee:ff")

    with pytest.raises(ValidationError):
        entry.mac = "11:22:33:44:55:66"


# --------------------------------------------------------------------------
# Active resolution, and what it refuses
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_active_resolution_refuses_where_it_would_need_root() -> None:
    # The send is implemented on every platform, but Linux and macOS need a
    # raw socket for it. Unprivileged, that must be a loud, actionable error
    # rather than a quiet fallback to whatever the cache happens to hold.
    import sys

    if sys.platform == "win32":
        pytest.skip("Windows resolves IPv4 actively through SendARP, which needs no elevation")

    with pytest.raises(ipscout.IPScoutError) as caught:
        resolve_active("192.0.2.1")
    # Either there is no route to that address, or the raw socket was denied.
    # Both are honest refusals; neither is a cache read.
    assert isinstance(caught.value, (ipscout.IPScoutPermissionError, ipscout.IPScoutUnsupportedError))


@pytest.mark.os_agnostic
def test_active_resolution_never_quietly_becomes_a_cache_read() -> None:
    # The failure mode worth guarding: a caller asks to resolve actively, the
    # platform cannot, and it hands back a stale cache entry as though it were
    # fresh. It must raise instead.
    import sys

    if sys.platform == "win32":
        pytest.skip("Windows has an unprivileged active path")

    entries = ipscout.neighbours()
    if not entries:
        pytest.skip("this host's neighbour cache is empty")

    known = entries[0].ip
    assert ipscout.lookup_mac(known).mac is not None  # passively, it is known

    with pytest.raises(ipscout.IPScoutError):
        ipscout.lookup_mac(known, active=True)


@pytest.mark.os_agnostic
def test_the_passive_default_still_does_not_raise() -> None:
    assert ipscout.lookup_mac("203.0.113.199").scope in {MacScope.UNKNOWN, MacScope.NEXT_HOP}
