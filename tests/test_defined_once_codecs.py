"""The shared codecs and socket steps that each fact's one home provides.

Every name here used to be written out at several call sites. These tests pin
the single definition, so the call sites can be pointed at it without each
re-proving the edge cases: which written hardware addresses are accepted and
how a refusal reads, the bytes a ``SOCKADDR_INET`` carries in each arm, how
strict the ``IPAddr`` parser is, and how the receive loop treats unrelated
frames, silence and a broken socket.
"""

from __future__ import annotations

import errno
import re
import socket
import sys
import time

import pytest

from ipscout import bsdroute, winapi
from ipscout.arp import (
    BROADCAST,
    MAC_LENGTH,
    await_answer,
    build_neighbour_solicitation,
    packed_mac,
    require_mac,
    send_neighbour_solicitation,
    solicited_node_multicast,
)
from ipscout.models import AddressFamily

pytestmark = pytest.mark.os_agnostic

_CANONICAL = "02:00:5e:10:00:0a"


# --------------------------------------------------------------------------
# require_mac / packed_mac
# --------------------------------------------------------------------------


@pytest.mark.parametrize("written", ["02:00:5E:10:00:0A", "02-00-5e-10-00-0a", "0200.5e10.000a", "02005e10000a", _CANONICAL])
def test_require_mac_reads_every_common_spelling_as_one_address(written: str) -> None:
    assert require_mac(written) == _CANONICAL


@pytest.mark.parametrize(
    "written",
    [
        "",
        "02:00:5e:10",
        "02:00:5e:10:00:0a:00",
        "02:00:5e:10:00:0",
        "02:00:5e:10:00:zz",
        # Non-ASCII look-alikes of hex digits: an Arabic-Indic two and a
        # fullwidth A. Neither is a hex digit, whatever str.isdigit says.
        "02:00:5e:10:00:0" + chr(0x0662),
        "02:00:5e:10:00:0" + chr(0xFF21),
    ],
)
def test_require_mac_refuses_what_is_not_a_six_byte_address(written: str) -> None:
    with pytest.raises(ValueError, match=r"^" + re.escape(repr(written)) + r" is not a hardware address$"):
        require_mac(written)


def test_packed_mac_returns_the_six_bytes_in_transmission_order() -> None:
    assert packed_mac("02-00-5E-10-00-0A") == bytes((0x02, 0x00, 0x5E, 0x10, 0x00, 0x0A))
    assert len(packed_mac(_CANONICAL)) == MAC_LENGTH


@pytest.mark.parametrize("written", ["02:00:5e:10", "02:00:5e:10:00:0a:00", "nonsense"])
def test_packed_mac_refuses_with_the_require_mac_wording(written: str) -> None:
    with pytest.raises(ValueError, match=r"is not a hardware address$"):
        packed_mac(written)


def test_broadcast_is_one_all_ones_hardware_address() -> None:
    assert BROADCAST == b"\xff\xff\xff\xff\xff\xff"


# --------------------------------------------------------------------------
# await_answer
# --------------------------------------------------------------------------


def _datagram_pair() -> tuple[socket.socket, socket.socket]:
    """Return a receiver and a sender connected over loopback UDP.

    Datagrams rather than ``socket.socketpair()``'s default stream: a stream
    may coalesce two sends into one read, and the loop under test is defined
    per frame. UDP keeps the boundaries on every platform, where a datagram
    ``AF_UNIX`` pair does not exist on Windows.
    """

    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.connect(receiver.getsockname())
    return receiver, sender


def test_await_answer_drops_frames_that_parse_to_none_and_returns_the_match() -> None:
    receiver, sender = _datagram_pair()
    seen: list[bytes] = []

    def parse(frame: bytes) -> str | None:
        seen.append(frame)
        return "answer" if frame == b"match" else None

    try:
        for frame in (b"noise-1", b"noise-2", b"match", b"after"):
            sender.send(frame)
        assert await_answer(receiver, timeout=2.0, parse=parse) == "answer"
    finally:
        receiver.close()
        sender.close()
    assert seen == [b"noise-1", b"noise-2", b"match"]


def test_await_answer_returns_none_when_the_peer_stays_silent() -> None:
    receiver, sender = _datagram_pair()
    started = time.monotonic()
    try:
        assert await_answer(receiver, timeout=0.05, parse=lambda _frame: "never") is None
    finally:
        receiver.close()
        sender.close()
    assert time.monotonic() - started < 2.0


def test_await_answer_returns_none_when_only_unrelated_frames_arrive() -> None:
    receiver, sender = _datagram_pair()
    try:
        sender.send(b"noise")
        assert await_answer(receiver, timeout=0.05, parse=lambda _frame: None) is None
    finally:
        receiver.close()
        sender.close()


def test_await_answer_reads_nothing_once_the_deadline_has_passed() -> None:
    receiver, sender = _datagram_pair()
    parsed: list[bytes] = []

    def parse(frame: bytes) -> str | None:
        parsed.append(frame)
        return "answer"

    try:
        sender.send(b"match")
        assert await_answer(receiver, timeout=0.0, parse=parse) is None
    finally:
        receiver.close()
        sender.close()
    assert parsed == []


class _FailingReadSocket(socket.socket):
    """A real UDP socket whose read fails, so the failure arises inside the receive loop itself."""

    def recv(self, bufsize: int, flags: int = 0, /) -> bytes:
        del bufsize, flags
        raise ConnectionRefusedError(errno.ECONNREFUSED, "the read failed")


def test_await_answer_lets_a_read_failure_reach_the_caller() -> None:
    # The socket is open and settimeout succeeds, so only the read can fail:
    # a loop that swallowed it would report "nobody answered" for "could not read".
    with _FailingReadSocket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, pytest.raises(ConnectionRefusedError, match="the read failed"):
        await_answer(receiver, timeout=1.0, parse=lambda _frame: "never")


# --------------------------------------------------------------------------
# send_neighbour_solicitation
# --------------------------------------------------------------------------


class _RecordingSocket(socket.socket):
    """A real IPv6 datagram socket that records the send instead of making it.

    Everything before the send (interface lookup, the multicast option, the
    timeout) runs against the kernel for real; only the transmission, which
    needs the raw ICMPv6 socket and its privilege, is captured.
    """

    def __init__(self, refusal: OSError | None = None) -> None:
        super().__init__(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sent: list[tuple[object, tuple[object, ...]]] = []
        self._refusal = refusal

    def sendto(self, data: object, *args: object) -> int:
        if self._refusal is not None:
            raise self._refusal
        self.sent.append((data, args))
        return 0


def _loopback_interface() -> tuple[str, int]:
    """Return the loopback interface's name and index, by its name on each POSIX host."""

    for index, name in socket.if_nameindex():
        if name in {"lo", "lo0"}:
            return name, index
    pytest.skip("no loopback interface named lo or lo0 on this host")


_SKIP_NO_IPV6 = pytest.mark.skipif(not socket.has_ipv6, reason="this Python has no IPv6 support")
#: The two senders that share this preamble are neighbours_linux and
#: neighbours_macos; Windows resolves through iphlpapi and never calls it.
_SKIP_WINDOWS = pytest.mark.skipif(sys.platform == "win32", reason="neighbour solicitation is sent only by the Linux and macOS backends")


@_SKIP_NO_IPV6
@_SKIP_WINDOWS
def test_send_neighbour_solicitation_pins_the_interface_and_addresses_the_group() -> None:
    name, index = _loopback_interface()
    target = "fe80::1122:3344:5566:7788"
    with _RecordingSocket() as sock:
        send_neighbour_solicitation(sock, interface=name, target_ip=target, source_mac=_CANONICAL, timeout=0.5)
        egress = sock.getsockopt(AddressFamily.IPV6.ip_option_level, socket.IPV6_MULTICAST_IF)
        assert sock.gettimeout() == 0.5
        assert sock.sent == [(build_neighbour_solicitation(sender_mac=_CANONICAL, target_ip=target), ((solicited_node_multicast(target), 0, 0, index),))]
    assert egress == index


@_SKIP_NO_IPV6
@_SKIP_WINDOWS
def test_send_neighbour_solicitation_lets_a_refused_send_reach_the_caller() -> None:
    name, _index = _loopback_interface()
    with _RecordingSocket(refusal=PermissionError("refused")) as sock, pytest.raises(PermissionError, match=r"^refused$"):
        send_neighbour_solicitation(sock, interface=name, target_ip="fe80::1", source_mac=_CANONICAL, timeout=0.5)


def test_send_neighbour_solicitation_refuses_an_unknown_interface_before_sending() -> None:
    with socket.socket() as sock, pytest.raises(OSError, match=r"."):
        send_neighbour_solicitation(sock, interface="no-such-if0", target_ip="fe80::1", source_mac=_CANONICAL, timeout=0.5)


# --------------------------------------------------------------------------
# winapi.sockaddr_inet / string_to_ipv4
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("family", "text", "tag"),
    [
        (AddressFamily.IPV4, "192.0.2.1", winapi.WIN_AF_INET),
        (AddressFamily.IPV6, "2001:db8::1", winapi.WIN_AF_INET6),
        (AddressFamily.IPV6, "fe80::1122:3344:5566:7788", winapi.WIN_AF_INET6),
    ],
)
def test_sockaddr_inet_round_trips_through_sockaddr_inet_address(family: AddressFamily, text: str, tag: int) -> None:
    packed = socket.inet_pton(family.socket_family, text)
    sockaddr = winapi.sockaddr_inet(packed, family)
    assert sockaddr.si_family == tag
    address = winapi.sockaddr_inet_address(sockaddr)
    assert address is not None
    assert address.packed == packed


@pytest.mark.parametrize(("family", "size"), [(AddressFamily.IPV4, 16), (AddressFamily.IPV6, 4), (AddressFamily.IPV4, 3)])
def test_sockaddr_inet_refuses_an_address_of_the_wrong_length(family: AddressFamily, size: int) -> None:
    with pytest.raises(ValueError, match="same size"):
        winapi.sockaddr_inet(bytes(size), family)


@pytest.mark.parametrize("text", ["127.0.0.1", "192.0.2.1", "198.51.100.7", "255.255.255.255"])
def test_string_to_ipv4_round_trips_a_full_dotted_quad(text: str) -> None:
    assert winapi.ipv4_to_string(winapi.string_to_ipv4(text)) == text


@pytest.mark.parametrize("text", ["127.1", "0x7f.0.0.1", "1.2.3", "256.0.0.1", " 1.2.3.4", "1.2.3.4\n", ""])
def test_string_to_ipv4_refuses_shorthand_and_malformed_text(text: str) -> None:
    with pytest.raises(OSError, match=r"."):
        winapi.string_to_ipv4(text)


# --------------------------------------------------------------------------
# bsdroute.AF_LINK
# --------------------------------------------------------------------------


def test_af_link_is_exported_and_is_the_family_a_packed_sockaddr_dl_carries() -> None:
    assert "AF_LINK" in bsdroute.__all__
    assert bsdroute.pack_sockaddr_dl(4, packed_mac(_CANONICAL))[1] == bsdroute.AF_LINK
