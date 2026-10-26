"""The neighbour backends and the Linux capture, read through the shared homes.

Each test drives a real backend function and checks what a caller sees: the
family a Linux dump entry is labelled with, the interface name an entry's index
becomes, which entries are dropped as no neighbour at all, the refusal texts,
and that the active and capture paths still fail the way their callers expect.
The tests that open a raw socket are root-only and skip otherwise.
"""

from __future__ import annotations

import errno
import os
import socket
import struct
import sys
import time

import pytest

from ipscout import bsdroute, dhcp_linux
from ipscout import neighbours_linux as linux
from ipscout import neighbours_macos as macos
from ipscout.errors import (
    PERMISSION_ERRNOS,
    IPScoutError,
    IPScoutPermissionError,
    IPScoutUnsupportedError,
    kernel_refused_neighbour_change,
)
from ipscout.models import AddressFamily, Neighbour, NeighbourChange, NeighbourState
from ipscout.neighbours import of_family

#: RFC 7042 documentation MAC and RFC 5737 / RFC 3849 documentation addresses.
DOC_MAC = bytes.fromhex("00005e005307")
DOC_MAC_TEXT = "00:00:5e:00:53:07"
DOC_IPV4 = "192.0.2.7"
DOC_IPV6 = "2001:db8::7"

#: Linux's AF_BRIDGE, a neighbour-table family that is not IP. Written as a
#: number because the constant is absent from ``socket`` off Linux.
_AF_BRIDGE = 7


def _is_root() -> bool:
    """Return whether this POSIX process is root; guarded so the Windows type check sees no geteuid."""

    if sys.platform == "win32":
        return False
    return os.geteuid() == 0


def _known_interface() -> tuple[int, str] | None:
    """Return one ``(index, name)`` this host has, or None where it lists none."""

    listing = getattr(socket, "if_nameindex", None)
    if listing is None:
        return None
    known: list[tuple[int, str]] = listing()
    return known[0] if known else None


def _unknown_index() -> int:
    """Return an interface index no interface here has."""

    listing = getattr(socket, "if_nameindex", None)
    known: list[tuple[int, str]] = listing() if listing is not None else []
    return max((index for index, _name in known), default=0) + 1000


def _nd_message(*, family: int, ip: bytes, ifindex: int = 0, mac: bytes = DOC_MAC) -> bytes:
    """Build one RTM_NEWNEIGH message in state REACHABLE, laid out from ``linux/neighbour.h``."""

    body = struct.pack("=BBHiHBB", family, 0, 0, ifindex, 0x02, 0, 0)
    attributes = b""
    for kind, value in ((1, ip), (2, mac)):  # NDA_DST, NDA_LLADDR
        attributes += struct.pack("=HH", 4 + len(value), kind) + value + b"\x00" * (-(len(value) + 4) % 4)
    payload = body + attributes
    return struct.pack("=IHHII", 16 + len(payload), 28, 0, 0, 0) + payload  # 28 = RTM_NEWNEIGH


def _rt_message(ip: str, *, index: int) -> bytes:
    """Build one macOS NET_RT_FLAGS entry for ``ip`` on interface ``index``."""

    name = b"en0"
    link = bsdroute.SOCKADDR_DL.pack(bsdroute.SOCKADDR_DL.size + len(name) + len(DOC_MAC), bsdroute.AF_LINK, index, 6, len(name), len(DOC_MAC), 0)
    link += name + DOC_MAC
    destination = struct.pack("=BBH4s8s", 16, socket.AF_INET, 0, socket.inet_aton(ip), bytes(8))
    payload = destination + link + b"\x00" * (-len(link) % 4)
    header = bsdroute.RT_MSGHDR.pack(
        bsdroute.RT_MSGHDR.size + len(payload),
        5,
        0x04,
        index,
        bsdroute.RTF_UP | bsdroute.RTF_LLINFO,
        bsdroute.RTA_DST | bsdroute.RTA_GATEWAY,
        0,
        0,
        0,
        0,
        0,
        bytes(56),
    )
    return header + payload


# --------------------------------------------------------------------------
# Linux dump: family, interface, which entries are neighbours
# --------------------------------------------------------------------------
@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("family", "packed", "expected"),
    [
        (socket.AF_INET, socket.inet_aton(DOC_IPV4), AddressFamily.IPV4),
        (socket.AF_INET6, socket.inet_pton(socket.AF_INET6, DOC_IPV6), AddressFamily.IPV6),
    ],
)
def test_a_linux_entry_is_labelled_with_the_family_its_header_names(family: int, packed: bytes, expected: AddressFamily) -> None:
    entries, _done = linux.parse_neighbour_dump(_nd_message(family=family, ip=packed))

    assert [(entry.family, entry.mac) for entry in entries] == [(expected, DOC_MAC_TEXT)]


@pytest.mark.os_agnostic
@pytest.mark.parametrize("family", [socket.AF_UNSPEC, _AF_BRIDGE])
def test_a_linux_entry_of_a_family_that_is_not_ip_is_skipped(family: int) -> None:
    entries, _done = linux.parse_neighbour_dump(_nd_message(family=family, ip=socket.inet_aton(DOC_IPV4)))

    assert entries == []


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("family", "address"),
    [(socket.AF_INET, "224.0.0.251"), (socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::"), (socket.AF_INET6, "ff02::1")],  # noqa: S104 - an entry, not a bind
)
def test_a_linux_entry_for_a_group_or_the_unspecified_address_is_no_neighbour(family: int, address: str) -> None:
    entries, _done = linux.parse_neighbour_dump(_nd_message(family=family, ip=socket.inet_pton(family, address)))

    assert entries == []


@pytest.mark.os_agnostic
def test_a_linux_entry_names_the_interface_its_index_belongs_to() -> None:
    known = _known_interface()
    if known is None:
        pytest.skip("this host lists no interfaces")
    index, name = known

    entries, _done = linux.parse_neighbour_dump(_nd_message(family=socket.AF_INET, ip=socket.inet_aton(DOC_IPV4), ifindex=index))

    assert [entry.interface for entry in entries] == [name]


@pytest.mark.os_agnostic
@pytest.mark.parametrize("which", ["zero", "unknown", "negative"])
def test_a_linux_entry_whose_index_names_no_interface_has_none(which: str) -> None:
    index = {"zero": 0, "unknown": _unknown_index(), "negative": -1}[which]

    entries, _done = linux.parse_neighbour_dump(_nd_message(family=socket.AF_INET, ip=socket.inet_aton(DOC_IPV4), ifindex=index))

    assert [entry.interface for entry in entries] == [None]


# --------------------------------------------------------------------------
# macOS dump: interface and which entries are neighbours
# --------------------------------------------------------------------------
@pytest.mark.os_agnostic
def test_a_macos_entry_names_the_interface_its_index_belongs_to() -> None:
    known = _known_interface()
    if known is None:
        pytest.skip("this host lists no interfaces")
    index, name = known

    entries = macos.parse_neighbour_dump(_rt_message(DOC_IPV4, index=index), AddressFamily.IPV4)

    assert [entry.interface for entry in entries] == [name]


@pytest.mark.os_agnostic
@pytest.mark.parametrize("which", ["zero", "unknown"])
def test_a_macos_entry_whose_index_names_no_interface_has_none(which: str) -> None:
    index = 0 if which == "zero" else _unknown_index()

    entries = macos.parse_neighbour_dump(_rt_message(DOC_IPV4, index=index), AddressFamily.IPV4)

    assert [entry.interface for entry in entries] == [None]


@pytest.mark.os_agnostic
@pytest.mark.parametrize("address", ["224.0.0.251", "0.0.0.0"])  # noqa: S104 - an entry, not a bind
def test_a_macos_entry_for_a_group_or_the_unspecified_address_is_no_neighbour(address: str) -> None:
    assert macos.parse_neighbour_dump(_rt_message(address, index=0), AddressFamily.IPV4) == []


@pytest.mark.os_agnostic
def test_a_macos_entry_of_the_other_family_is_skipped_not_refused() -> None:
    assert macos.parse_neighbour_dump(_rt_message(DOC_IPV4, index=0), AddressFamily.IPV6) == []


# --------------------------------------------------------------------------
# neighbours.of_family
# --------------------------------------------------------------------------
@pytest.mark.os_agnostic
def test_a_family_filter_keeps_exactly_the_entries_of_that_family() -> None:
    v4 = Neighbour(ip=DOC_IPV4, mac=DOC_MAC_TEXT, state=NeighbourState.OTHER, family=AddressFamily.IPV4)
    v6 = Neighbour(ip=DOC_IPV6, mac=DOC_MAC_TEXT, state=NeighbourState.OTHER, family=AddressFamily.IPV6)
    entries = (v4, v6)

    assert of_family(entries, AddressFamily.IPV4) == (v4,)
    assert of_family(entries, AddressFamily.IPV6) == (v6,)
    assert of_family(entries, None) == entries


# --------------------------------------------------------------------------
# Refusal texts
# --------------------------------------------------------------------------
@pytest.mark.os_posix
@pytest.mark.skipif(sys.platform == "darwin" and _is_root(), reason="root on macOS may claim a BPF device, so there is no refusal to read")
def test_the_macos_active_refusal_ends_with_the_shared_way_out() -> None:
    # Off macOS no /dev/bpf* exists, and on macOS an unprivileged open is
    # refused: either way the claim fails and the refusal is what a caller reads.
    with pytest.raises(IPScoutPermissionError) as caught:
        macos.resolve_active_ipv4(DOC_IPV4, interface="en0", source_ip="192.0.2.1", source_mac=DOC_MAC_TEXT, timeout=0.2)

    text = str(caught.value)
    assert text.startswith("active ARP on macOS needs a BPF device, and /dev/bpf* is root-only: ")
    # The literal words, not the shared name, so a change to that name shows here.
    assert text.endswith(". Run as root, or use arp_scan(), which resolves the same addresses unprivileged")


@pytest.mark.os_agnostic
@pytest.mark.parametrize("error", sorted(PERMISSION_ERRNOS))
def test_both_privilege_errnos_name_the_privilege_on_linux_and_macos(error: int) -> None:
    with pytest.raises(IPScoutPermissionError, match="CAP_NET_ADMIN"):
        linux.raise_for_ack(error, action=NeighbourChange.ADD)
    with pytest.raises(IPScoutPermissionError, match="needs root on macOS"):
        macos.raise_for_route_errno(error, action=NeighbourChange.ADD)


@pytest.mark.os_agnostic
@pytest.mark.parametrize("action", list(NeighbourChange))
def test_another_kernel_refusal_is_the_shared_error_and_no_privilege_error(action: NeighbourChange) -> None:
    expected = str(kernel_refused_neighbour_change(action.value, errno.EEXIST))
    for raise_it in (linux.raise_for_ack, macos.raise_for_route_errno):
        with pytest.raises(IPScoutError) as caught:
            raise_it(errno.EEXIST, action=action)
        assert type(caught.value) is IPScoutError
        assert str(caught.value) == expected


# --------------------------------------------------------------------------
# The Linux capture opener
# --------------------------------------------------------------------------
@pytest.mark.os_linux
def test_capture_available_answers_whether_the_capture_socket_opens() -> None:
    try:
        probe = socket.socket(getattr(socket, "AF_PACKET", -1), socket.SOCK_RAW, socket.htons(0x0800))
    except OSError:
        opens = False
    else:
        probe.close()
        opens = True

    assert dhcp_linux.capture_available() is opens


@pytest.mark.os_linux
@pytest.mark.skipif(_is_root(), reason="root may open the socket, so there is no refusal to see")
def test_an_unprivileged_capture_is_refused_for_want_of_the_privilege() -> None:
    if dhcp_linux.capture_available():
        pytest.skip("this interpreter holds CAP_NET_RAW")
    with pytest.raises(IPScoutPermissionError, match="CAP_NET_RAW"):
        dhcp_linux.open_capture("lo")


@pytest.mark.os_agnostic
@pytest.mark.skipif(sys.platform.startswith("linux"), reason="off Linux only: there is no packet socket to open")
def test_off_linux_the_capture_is_unsupported_not_a_permission_problem() -> None:
    assert dhcp_linux.capture_available() is False
    with pytest.raises(IPScoutUnsupportedError, match="AF_PACKET is a Linux facility"):
        dhcp_linux.open_capture("lo0")


# --------------------------------------------------------------------------
# Linux active resolution (root-only: a raw socket must open first)
# --------------------------------------------------------------------------
@pytest.mark.os_linux
@pytest.mark.skipif(not _is_root(), reason="opening a raw ICMPv6 socket needs root")
def test_a_solicitation_on_an_unknown_interface_is_could_not_ask() -> None:
    with pytest.raises(IPScoutUnsupportedError, match=r"^could not ask for fe80::7 on nosuchif0: "):
        linux.resolve_active_ipv6("fe80::7", interface="nosuchif0", source_mac=DOC_MAC_TEXT, timeout=0.2)


@pytest.mark.os_linux
@pytest.mark.skipif(not _is_root(), reason="opening a link-layer socket needs root")
def test_an_unanswered_arp_request_is_none_within_its_timeout() -> None:
    # Loopback carries the request back to this socket, where it is not a reply,
    # so nothing answers and the wait must end at the timeout, not before or long after.
    timeout = 0.3
    started = time.monotonic()

    answer = linux.resolve_active_ipv4(DOC_IPV4, interface="lo", source_ip="192.0.2.1", source_mac=DOC_MAC_TEXT, timeout=timeout)

    elapsed = time.monotonic() - started
    assert answer is None
    assert timeout * 0.9 <= elapsed < timeout + 1.0
