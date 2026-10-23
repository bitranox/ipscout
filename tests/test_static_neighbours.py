"""Static neighbour entries: the three wire formats, the error mapping, and the write itself.

The encoders are asserted against bytes derived by hand from the C headers (``linux/neighbour.h``
and ``linux/netlink.h``; ``net/route.h`` and ``net/if_dl.h``; ``netioapi.h``), never against the
encoder's own output: a test that compares an encoder with itself passes whatever the encoder does.
The macOS and Windows writes cannot run on the Linux development host, so for them these bytes are
the only check before a real kernel reads them.

Only the last test writes anything, and it runs only when opted into with
``IPSCOUT_HOST_WRITE_TESTS=1`` - see ``tests/conftest.py``.
"""

from __future__ import annotations

import ctypes
import errno
import ipaddress
import json
import os
import sys

import pytest
from click.testing import CliRunner

import ipscout
from ipscout import bsdroute, winapi
from ipscout import neighbours_linux as linux
from ipscout import neighbours_macos as macos
from ipscout import neighbours_windows as windows
from ipscout.cli import EXIT_ERROR, cli
from ipscout.errors import IPScoutError, IPScoutPermissionError, IPScoutUnsupportedError
from ipscout.models import AddressFamily, Interface, InterfaceAddress, NeighbourState
from ipscout.netlink import parse_ack
from ipscout.static_neighbours import interface_index, ipv4_station_address, station_mac, subnet_interface_index

pytestmark = pytest.mark.os_agnostic

#: RFC 5737 TEST-NET-1 and the RFC 7042 documentation MAC block: nothing real owns either.
DOC_IP = "192.0.2.7"
DOC_MAC = "00:00:5e:00:53:07"
DOC_MAC_BYTES = bytes.fromhex("00005e005307")


def _hex(*parts: str) -> bytes:
    """Join hex fragments written field by field, spaces allowed, into bytes."""

    return bytes.fromhex("".join(parts).replace(" ", ""))


def _running_as_root() -> bool:
    """Return whether this POSIX process is root; guarded so the Windows type check sees no geteuid."""

    if sys.platform == "win32":
        return False
    return os.geteuid() == 0


def _loopback_index() -> int:
    """Return this host's loopback interface index, which exists everywhere."""

    loopback = next((item for item in ipscout.local_interfaces() if item.is_loopback and item.index), None)
    if loopback is None or loopback.index is None:
        pytest.skip("this host reports no loopback interface index")
    return loopback.index


# --------------------------------------------------------------------------
# Linux: netlink RTM_NEWNEIGH / RTM_DELNEIGH
# --------------------------------------------------------------------------


def test_the_linux_set_request_is_the_message_ip_neigh_replace_sends() -> None:
    expected = _hex(
        # nlmsghdr: len 48, RTM_NEWNEIGH 28, REQUEST|ACK|REPLACE|CREATE 0x505, seq 1, pid 0
        "30000000 1c00 0505 01000000 00000000",
        # ndmsg: AF_INET, pad, pad, ifindex 2, NUD_PERMANENT 0x80, flags 0, type 0
        "02 00 0000 02000000 8000 00 00",
        # NDA_DST: rta_len 8, type 1, 192.0.2.7
        "0800 0100 c0000207",
        # NDA_LLADDR: rta_len 10, type 2, the MAC, then two bytes of alignment
        "0a00 0200 00005e005307 0000",
    )

    assert linux.build_set_request(DOC_IP, DOC_MAC_BYTES, 2) == expected


def test_the_linux_remove_request_names_the_address_and_the_interface() -> None:
    expected = _hex(
        # nlmsghdr: len 36, RTM_DELNEIGH 29, REQUEST|ACK 0x05, seq 1, pid 0
        "24000000 1d00 0500 01000000 00000000",
        # ndmsg: AF_INET, ifindex 2, no state
        "02 00 0000 02000000 0000 00 00",
        "0800 0100 c0000207",
    )

    assert linux.build_remove_request(DOC_IP, 2) == expected


def test_the_sequence_number_is_carried_for_the_acknowledgement_to_echo() -> None:
    assert linux.build_set_request(DOC_IP, DOC_MAC_BYTES, 2, sequence=7)[8:12] == _hex("07000000")


@pytest.mark.parametrize(("code", "expected"), [("00000000", 0), ("ffffffff", errno.EPERM), ("feffffff", errno.ENOENT)])
def test_the_acknowledgement_yields_the_kernels_errno(code: str, expected: int) -> None:
    # NLMSG_ERROR: len 36, type 2, flags NLM_F_CAPPED, seq 1, pid 0; then the
    # negative errno and the header of the request it answers.
    chunk = _hex("24000000 0200 0001 01000000 00000000", code, "30000000 1c00 0505 01000000 00000000")

    assert parse_ack(chunk) == expected


def test_a_reply_that_is_not_an_acknowledgement_carries_no_verdict() -> None:
    # An RTM_NEWNEIGH notification, which arrives on a listening socket, is not an answer.
    assert parse_ack(_hex("14000000 1c00 0000 01000000 00000000", "00000000")) is None


@pytest.mark.parametrize("code", [errno.EPERM, errno.EACCES])
def test_a_linux_refusal_for_privilege_names_cap_net_admin(code: int) -> None:
    with pytest.raises(IPScoutPermissionError, match="CAP_NET_ADMIN"):
        linux.raise_for_ack(code, action="add")


def test_a_linux_refusal_for_another_reason_is_not_called_a_permission_problem() -> None:
    with pytest.raises(IPScoutError) as caught:
        linux.raise_for_ack(errno.ENODEV, action="add")

    assert not isinstance(caught.value, IPScoutPermissionError)
    assert f"errno {errno.ENODEV}" in str(caught.value)


def test_no_acknowledgement_is_an_error_rather_than_a_silent_success() -> None:
    with pytest.raises(IPScoutError, match="did not acknowledge"):
        linux.raise_for_ack(None, action="add")


def test_a_linux_delete_of_nothing_is_an_answer_not_an_error() -> None:
    assert (linux.removed_from_ack(0), linux.removed_from_ack(errno.ENOENT)) == (True, False)
    with pytest.raises(IPScoutPermissionError):
        linux.removed_from_ack(errno.EPERM)


# --------------------------------------------------------------------------
# macOS: routing socket RTM_ADD / RTM_DELETE, as arp -s / arp -d
# --------------------------------------------------------------------------

#: rt_metrics: fourteen zero 32-bit fields.
_NO_METRICS = "00" * 56


def test_the_macos_add_message_is_the_one_arp_s_writes() -> None:
    expected = _hex(
        # rt_msghdr: msglen 128, RTM_VERSION 5, RTM_ADD 1, index 0, 2 pad bytes,
        # flags HOST|LLINFO|STATIC 0x0c04, addrs DST|GATEWAY 3, pid 1234, seq 2,
        # errno 0, use 0, inits RTV_EXPIRE 4, then the zero metrics
        "8000 05 01 0000 0000 040c0000 03000000 d2040000 02000000 00000000 00000000 04000000",
        _NO_METRICS,
        # sockaddr_in: len 16, AF_INET 2, port 0, 192.0.2.7, zero
        "10 02 0000 c0000207 0000000000000000",
        # sockaddr_dl: len 20, AF_LINK 18, index 4, IFT_ETHER 6, nlen 0, alen 6, slen 0, MAC, zero
        "14 12 0400 06 00 06 00 00005e005307 000000000000",
    )

    assert macos.build_add_message(DOC_IP, DOC_MAC_BYTES, 4, pid=1234, seq=2) == expected


def test_the_macos_delete_message_names_only_the_destination() -> None:
    expected = _hex(
        "6c00 05 02 0000 0000 040c0000 01000000 d2040000 01000000 00000000 00000000 04000000",
        _NO_METRICS,
        "10 02 0000 c0000207 0000000000000000",
    )

    assert macos.build_delete_message(DOC_IP, pid=1234, seq=1) == expected


def test_the_macos_add_message_reads_back_through_the_existing_decoder() -> None:
    # A second oracle the encoder did not write: the decoder the neighbour dump
    # already uses must find the same address and hardware address in it.
    message = macos.build_add_message(DOC_IP, DOC_MAC_BYTES, 4, pid=1, seq=1)
    header = bsdroute.RT_MSGHDR.unpack(message[: bsdroute.RT_MSGHDR.size])

    sockaddrs = bsdroute.split_sockaddrs(message[bsdroute.RT_MSGHDR.size :], header[5])

    assert sockaddrs.destination is not None
    assert sockaddrs.gateway is not None
    assert bsdroute.address_of(sockaddrs.destination) == DOC_IP
    assert bsdroute.link_address_of(sockaddrs.gateway) == DOC_MAC
    assert header[0] == len(message)


def test_the_link_gateway_is_as_long_as_the_kernel_demands() -> None:
    # xnu's arp_rtrequest refuses a gateway shorter than sizeof(struct sockaddr_dl).
    assert len(bsdroute.pack_sockaddr_dl(4, DOC_MAC_BYTES)) == 20


@pytest.mark.parametrize("code", [errno.EPERM, errno.EACCES])
def test_a_macos_refusal_for_privilege_names_root(code: int) -> None:
    with pytest.raises(IPScoutPermissionError, match="root"):
        macos.raise_for_route_errno(code, action="add")


def test_a_macos_add_onto_an_occupied_address_is_an_error_not_a_permission_problem() -> None:
    with pytest.raises(IPScoutError) as caught:
        macos.raise_for_route_errno(errno.EEXIST, action="add")

    assert not isinstance(caught.value, IPScoutPermissionError)


def test_a_macos_delete_of_nothing_is_an_answer_not_an_error() -> None:
    assert (macos.removed_from_route_errno(0), macos.removed_from_route_errno(errno.ESRCH)) == (True, False)


# --------------------------------------------------------------------------
# Windows: MIB_IPNET_ROW2 for CreateIpNetEntry2 / DeleteIpNetEntry2
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "offset", "width"),
    [
        ("Address", 0, 28),
        ("InterfaceIndex", 28, 4),
        ("InterfaceLuid", 32, 8),
        ("PhysicalAddress", 40, 32),
        ("PhysicalAddressLength", 72, 4),
        ("State", 76, 4),
        ("Flags", 80, 4),
        ("ReachabilityTime", 84, 4),
    ],
)
def test_every_neighbour_row_field_sits_where_netioapi_h_puts_it(field: str, offset: int, width: int) -> None:
    # NET_LUID is 64-bit, so it starts on 32, not 28. In the header Flags is a
    # one-byte union followed by three bytes of padding; declared as 32 bits it
    # covers the same four bytes, which is what keeps ReachabilityTime at 84.
    descriptor = getattr(winapi.MIB_IPNET_ROW2, field)

    assert (int(descriptor.offset), int(descriptor.size)) == (offset, width)


def test_the_neighbour_row_is_as_large_as_the_c_structure() -> None:
    # A short row would let CreateIpNetEntry2 read past the buffer it was given.
    assert ctypes.sizeof(winapi.MIB_IPNET_ROW2) == 88


def test_the_windows_row_carries_a_permanent_ipv4_entry() -> None:
    expected = _hex(
        # SOCKADDR_INET, IPv4 arm: AF_INET 2, port 0, 192.0.2.7, sin_zero, then the rest of the union
        "0200 0000 c0000207 0000000000000000",
        "00" * 12,
        "04000000",  # InterfaceIndex
        "00" * 8,  # InterfaceLuid: the index is enough
        "00005e005307",
        "00" * 26,  # PhysicalAddress[32]
        "06000000",  # PhysicalAddressLength
        "06000000",  # State: NlnsPermanent
        "00000000",  # Flags
        "00000000",  # ReachabilityTime
    )

    assert bytes(windows.ipv4_neighbour_row(DOC_IP, DOC_MAC_BYTES, 4)) == expected


def test_a_windows_refusal_for_privilege_names_administrator() -> None:
    with pytest.raises(IPScoutPermissionError, match="Administrator"):
        windows.raise_for_status(5, action="add")


def test_another_windows_failure_carries_its_code() -> None:
    with pytest.raises(IPScoutError, match="Win32 error 87") as caught:
        windows.raise_for_status(87, action="add")

    assert not isinstance(caught.value, IPScoutPermissionError)


def test_a_windows_delete_of_nothing_is_an_answer_not_an_error() -> None:
    assert (windows.removed_from_status(0), windows.removed_from_status(1168)) == (True, False)
    with pytest.raises(IPScoutPermissionError):
        windows.removed_from_status(5)


# --------------------------------------------------------------------------
# What is refused before anything is written
# --------------------------------------------------------------------------


def test_an_ipv6_address_is_refused_by_name() -> None:
    with pytest.raises(IPScoutUnsupportedError, match="IPv6"):
        ipscout.set_neighbour("2001:db8::7", DOC_MAC)
    with pytest.raises(IPScoutUnsupportedError, match="IPv6"):
        ipscout.remove_neighbour("2001:db8::7")


@pytest.mark.parametrize("ip", ["nonsense", "192.0.2", "224.0.0.1", str(ipaddress.IPv4Address(0)), "255.255.255.255"])
def test_an_address_that_names_no_single_station_is_refused(ip: str) -> None:
    with pytest.raises(ValueError, match=ip):
        ipv4_station_address(ip)


@pytest.mark.parametrize("mac", ["nonsense", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "33:33:00:00:00:01"])
def test_a_hardware_address_no_single_device_owns_is_refused(mac: str) -> None:
    with pytest.raises(ValueError, match=mac):
        station_mac(mac)


def test_a_station_address_in_any_written_form_is_accepted() -> None:
    assert station_mac("00-00-5E-00-53-07") == DOC_MAC


def _lan(name: str, index: int | None, address: str, *, mac: str | None = DOC_MAC) -> Interface:
    """Return an interface carrying one IPv4 address in a /24."""

    return Interface(name=name, index=index, mac=mac, ipv4=(InterfaceAddress(address=address, prefix_len=24),))


def test_the_interface_is_the_one_whose_subnet_holds_the_address() -> None:
    interfaces = [_lan("eth0", 2, "198.51.100.1"), _lan("eth1", 3, "192.0.2.1")]

    assert subnet_interface_index(DOC_IP, interfaces) == 3


def test_an_interface_without_a_link_layer_is_never_chosen() -> None:
    # Loopback and tunnels report no hardware address; an entry there maps to nothing.
    with pytest.raises(IPScoutUnsupportedError, match="no interface"):
        subnet_interface_index(DOC_IP, [_lan("tun0", 5, "192.0.2.1", mac=None), _lan("eth0", None, "192.0.2.2")])


def test_two_interfaces_on_the_subnet_are_refused_by_name_rather_than_guessed() -> None:
    with pytest.raises(IPScoutUnsupportedError, match=r"eth0, eth1"):
        subnet_interface_index(DOC_IP, [_lan("eth0", 2, "192.0.2.1"), _lan("eth1", 3, "192.0.2.2")])


def test_an_address_on_no_subnet_here_asks_for_the_interface() -> None:
    with pytest.raises(IPScoutUnsupportedError, match="--interface"):
        subnet_interface_index(DOC_IP, [_lan("eth0", 2, "198.51.100.1")])


def test_a_windows_friendly_name_is_taken_from_the_interface_list() -> None:
    # The friendly name is in no namespace if_nametoindex knows, so it is found by listing.
    assert interface_index("Ethernet 4", [Interface(name="Ethernet 4", index=7)]) == 7


def test_an_interface_given_by_number_must_exist() -> None:
    index = _loopback_index()

    assert interface_index(str(index), []) == index
    with pytest.raises(ValueError, match="no interface with index"):
        interface_index("4000000000", [])


@pytest.mark.parametrize("name", ["no-such-interface-here", chr(0x00B2)])
def test_an_unknown_interface_is_refused(name: str) -> None:
    # A superscript two is a digit to str.isdigit and not to int(); it is a name, and unknown.
    with pytest.raises(ValueError, match="no interface"):
        interface_index(name, [])


def test_removing_an_entry_the_cache_does_not_list_answers_false_without_privilege() -> None:
    assert ipscout.remove_neighbour("192.0.2.254") is False


@pytest.mark.os_posix
def test_writing_without_privilege_raises_a_permission_error() -> None:
    # The real kernel's refusal, end to end: through the public call, the
    # backend and its error mapping. Root would write, so root is skipped.
    if _running_as_root():
        pytest.skip("running as root, which would write the entry")

    with pytest.raises(IPScoutPermissionError):
        ipscout.set_neighbour(DOC_IP, DOC_MAC, interface=str(_loopback_index()))


@pytest.mark.os_linux
def test_removing_from_a_named_interface_without_privilege_raises_on_linux() -> None:
    # Naming the interface skips the cache read, so the kernel is asked - and refuses.
    if _running_as_root():
        pytest.skip("running as root, which would be allowed")

    with pytest.raises(IPScoutPermissionError, match="CAP_NET_ADMIN"):
        ipscout.remove_neighbour(DOC_IP, interface=str(_loopback_index()))


# --------------------------------------------------------------------------
# The CLI
# --------------------------------------------------------------------------


def test_set_neighbour_reports_a_refusal_in_the_envelope() -> None:
    result = CliRunner().invoke(cli, ["--json", "set-neighbour", "2001:db8::7", DOC_MAC])

    payload = json.loads(result.output)
    assert result.exit_code == EXIT_ERROR
    assert (payload["ok"], payload["command"], payload["error"]["type"]) == (False, "set-neighbour", "IPScoutUnsupportedError")


def test_set_neighbour_reports_a_refusal_bare() -> None:
    result = CliRunner().invoke(cli, ["--json-bare", "set-neighbour", DOC_IP, "ff:ff:ff:ff:ff:ff"])

    assert result.exit_code == EXIT_ERROR
    assert json.loads(result.output)["type"] == "ValueError"


def test_set_neighbour_reports_a_refusal_to_a_person_without_a_class_name() -> None:
    result = CliRunner().invoke(cli, ["set-neighbour", DOC_IP, "nonsense"])

    assert result.exit_code == EXIT_ERROR
    assert "not a hardware address" in result.output
    assert "ValueError" not in result.output


def test_remove_neighbour_says_so_when_there_was_nothing() -> None:
    result = CliRunner().invoke(cli, ["remove-neighbour", "192.0.2.254"])

    assert "(no entry)" in result.output


# --------------------------------------------------------------------------
# The write itself, opt-in
# --------------------------------------------------------------------------

#: A second documentation address and MAC, so the round trip cannot be confused with the encoders' fixtures.
_WRITE_IP = "192.0.2.77"
_WRITE_MACS = ("00:00:5e:00:53:77", "00:00:5e:00:53:78")


def _listed(ip: str) -> list[tuple[str | None, NeighbourState]]:
    """Return what the cache holds for ``ip``: hardware address and state per entry."""

    return [(entry.mac, entry.state) for entry in ipscout.neighbours(family=AddressFamily.IPV4) if entry.ip == ip]


@pytest.mark.host_mutating
def test_a_static_entry_is_written_read_back_replaced_and_removed() -> None:
    # Borrows the interface carrying the default route, for an address in no
    # subnet it holds, so nothing this host talks to is shadowed. Removed in a
    # finally: a static entry outlives the process.
    route = ipscout.default_gateway()
    if route is None or route.interface is None:
        pytest.skip("no default route to borrow an interface from")
    interface = route.interface
    first, second = _WRITE_MACS
    permanent_state = NeighbourState.OTHER if sys.platform == "darwin" else NeighbourState.PERMANENT

    try:
        written = ipscout.set_neighbour(_WRITE_IP, first, interface=interface)
        assert (written.ip, written.mac, written.state) == (_WRITE_IP, first, permanent_state)
        assert _listed(_WRITE_IP) == [(first, permanent_state)]

        replaced = ipscout.set_neighbour(_WRITE_IP, second, interface=interface)
        assert replaced.mac == second
        assert _listed(_WRITE_IP) == [(second, permanent_state)]
    finally:
        removed = ipscout.remove_neighbour(_WRITE_IP, interface=interface)

    assert removed is True
    assert _listed(_WRITE_IP) == []
    assert ipscout.remove_neighbour(_WRITE_IP, interface=interface) is False
