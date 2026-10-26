"""The shared homes for facts several modules used to state for themselves.

Each test pins one shared name: its edge cases, and - where a backend still
spells the same words out for itself - that the shared text matches what that
backend says today, so moving the backend onto the shared name changes no
message a caller sees.
"""

from __future__ import annotations

import errno
import os
import socket
import sys
import time

import pytest

from ipscout import deadline, ports
from ipscout.deadline import MIN_WAIT, seconds_left
from ipscout.errors import (
    ARP_SCAN_ALTERNATIVE,
    PERMISSION_ERRNOS,
    IPScoutError,
    IPScoutResolutionError,
    kernel_refused_neighbour_change,
)
from ipscout.models import NeighbourChange
from ipscout.neighbours_linux import raise_for_ack
from ipscout.neighbours_macos import raise_for_route_errno
from ipscout.resolve import MAX_INTERFACE_INDEX, interface_name, resolve
from ipscout.unixio import packet_family

pytestmark = pytest.mark.os_agnostic


# --------------------------------------------------------------------------
# resolve: interface index range and names
# --------------------------------------------------------------------------
def test_the_largest_interface_index_is_what_a_uint32_scope_field_holds() -> None:
    assert MAX_INTERFACE_INDEX == 0xFFFFFFFF


@pytest.mark.parametrize("index", [0, -1, MAX_INTERFACE_INDEX + 1, 2**64])
def test_an_index_outside_the_interface_range_names_no_interface(index: int) -> None:
    assert interface_name(index) is None


def test_an_index_in_range_that_no_interface_has_names_none() -> None:
    taken = {index for index, _name in socket.if_nameindex()}
    unused = next(index for index in range(MAX_INTERFACE_INDEX, 0, -1) if index not in taken)
    assert interface_name(unused) is None


def test_a_real_interface_index_names_that_interface() -> None:
    known = socket.if_nameindex()
    if not known:
        pytest.skip("this host lists no interfaces")
    index, name = known[0]
    assert interface_name(index) == name


# --------------------------------------------------------------------------
# resolve: a malformed zone, each refusal in its order
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("fe80::1%", "'fe80::1%' ends with % but names no interface: write one after it, or drop the %"),
        ("127.0.0.1%", "'127.0.0.1%' ends with % but names no interface: write one after it, or drop the %"),
        ("fe80::1%%", "'fe80::1%%' names more than one interface: an address carries one zone, written once after a single %"),
        ("fe80::1%a%b", "'fe80::1%a%b' names more than one interface: an address carries one zone, written once after a single %"),
        (
            "127.0.0.1%eth0",
            "'127.0.0.1%eth0' is an IPv4 address with a zone: an interface belongs to an IPv6 link-local address and to nothing else",
        ),
        (
            "example.test%eth0",
            "'example.test%eth0' puts a zone on 'example.test', which is not an address literal: an interface can only be written after one",
        ),
    ],
)
def test_a_malformed_zone_is_refused_with_its_own_words(target: str, message: str) -> None:
    with pytest.raises(IPScoutResolutionError) as refused:
        resolve(target)
    assert str(refused.value) == message


# --------------------------------------------------------------------------
# resolve: a getaddrinfo result of a family nobody asked for
# --------------------------------------------------------------------------
def test_a_result_of_neither_ip_family_is_skipped_not_called_ipv4(monkeypatch: pytest.MonkeyPatch) -> None:
    # getaddrinfo is the system resolver, an external edge with no seam to
    # inject through, and no real resolver can be made to answer with a third
    # family on demand - so it is substituted here, and only here.
    answers: list[tuple[object, ...]] = [
        (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("192.0.2.1", 0)),
        (socket.AF_UNSPEC, socket.SOCK_DGRAM, 17, "", ("192.0.2.2", 0)),
        (socket.AF_INET6, socket.SOCK_DGRAM, 17, "", ("2001:db8::1", 0, 0, 0)),
    ]

    def answer(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        return answers

    monkeypatch.setattr(socket, "getaddrinfo", answer)
    assert resolve("example.test") == ["192.0.2.1", "2001:db8::1"]


# --------------------------------------------------------------------------
# deadline: the floor under every blocking wait
# --------------------------------------------------------------------------
def test_the_wait_floor_is_one_millisecond_and_ports_names_the_same_value() -> None:
    assert MIN_WAIT == 0.001
    assert ports.MIN_CAPTURE_WAIT is deadline.MIN_WAIT


def test_a_deadline_already_passed_leaves_the_floor_not_zero_or_negative() -> None:
    assert seconds_left(time.monotonic() - 60) == MIN_WAIT


def test_a_deadline_just_now_still_leaves_the_floor() -> None:
    assert seconds_left(time.monotonic()) == MIN_WAIT


def test_a_future_deadline_leaves_the_time_until_it() -> None:
    left = seconds_left(time.monotonic() + 30)
    assert 29 < left <= 30


# --------------------------------------------------------------------------
# errors: the unprivileged way out, privilege errnos, a kernel refusal
# --------------------------------------------------------------------------
def test_the_arp_scan_alternative_is_the_words_every_backend_offers() -> None:
    # The literal tail of the Linux backend's advice, ", or use arp_scan(), ...":
    # pinned as text so moving a backend onto the shared name changes no word.
    linux_advice_tail = "or use arp_scan(), which resolves the same addresses unprivileged"
    assert linux_advice_tail == f"or {ARP_SCAN_ALTERNATIVE}"


def test_the_permission_errnos_are_eperm_and_eacces_only() -> None:
    assert frozenset({errno.EPERM, errno.EACCES}) == PERMISSION_ERRNOS
    assert errno.EEXIST not in PERMISSION_ERRNOS


@pytest.mark.parametrize("verb", ["add", "delete"])
def test_a_kernel_refusal_reads_exactly_as_the_backends_word_it(verb: str) -> None:
    error = errno.EEXIST
    expected = f"the kernel refused to {verb} the neighbour entry: {os.strerror(error)} (errno {error})"
    refused = kernel_refused_neighbour_change(verb, error)
    assert type(refused) is IPScoutError
    assert str(refused) == expected


@pytest.mark.parametrize("action", list(NeighbourChange))
def test_the_shared_kernel_refusal_matches_the_linux_and_macos_backends(action: NeighbourChange) -> None:
    shared = str(kernel_refused_neighbour_change(action.value, errno.ENOENT))
    with pytest.raises(IPScoutError) as linux:
        raise_for_ack(errno.ENOENT, action=action)
    with pytest.raises(IPScoutError) as macos:
        raise_for_route_errno(errno.ENOENT, action=action)
    assert str(linux.value) == shared
    assert str(macos.value) == shared


# --------------------------------------------------------------------------
# unixio: the packet-socket family
# --------------------------------------------------------------------------
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="AF_PACKET exists only on Linux")
def test_the_packet_family_on_linux_is_af_packet() -> None:
    assert packet_family() == getattr(socket, "AF_PACKET", None)
