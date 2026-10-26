"""ARP and NDP message codecs, and the socket steps every sender repeats.

Contents:
    require_mac / packed_mac: A written hardware address, checked or packed.
    build_arp_request: An Ethernet frame asking who holds an IPv4 address.
    parse_arp_reply: The hardware address in a reply, if it answers our query.
    build_neighbour_solicitation: The ICMPv6 equivalent for IPv6.
    parse_neighbour_advertisement: The hardware address in its reply.
    solicited_node_multicast: The IPv6 group a solicitation is sent to.
    send_neighbour_solicitation: Send a solicitation on a socket the caller
        opened.
    await_answer: Read frames until one answers or the time runs out.

Note:
    Separated from the code that opens the sockets so the wire formats can be
    tested without the privileges those sockets need. That matters here more
    than anywhere else in this package: sending either message requires root
    or ``CAP_NET_RAW``, so the transmit paths cannot run in CI at all. The two
    socket helpers take a socket already opened and leave every exception to
    the caller, so they run against an ordinary unprivileged socket in tests.

"""

from __future__ import annotations

import ipaddress
import socket
import struct
import time
from typing import TYPE_CHECKING

from .deadline import seconds_left
from .models import AddressFamily, require_address

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = [
    "ETHERNET",
    "ETHERNET_HEADER_SIZE",
    "FRAME_RECEIVE_SIZE",
    "HTYPE_ETHERNET",
    "await_answer",
    "build_arp_request",
    "build_neighbour_solicitation",
    "format_hardware_address",
    "format_mac",
    "normalise_mac",
    "packed_mac",
    "parse_arp_reply",
    "parse_neighbour_advertisement",
    "require_mac",
    "send_neighbour_solicitation",
    "solicited_node_multicast",
]

#: Ethernet: destination, source, ethertype.
ETHERNET = struct.Struct("!6s6sH")
ETHERNET_HEADER_SIZE = ETHERNET.size
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_VLAN = 0x8100
ETH_P_IPV6 = 0x86DD

#: An Ethernet hardware address is six bytes.
MAC_LENGTH = 6

BROADCAST = b"\xff" * MAC_LENGTH

#: ARP: hardware type, protocol type, lengths, operation, then the addresses.
_ARP = struct.Struct("!HHBBH6s4s6s4s")
HTYPE_ETHERNET = 1
#: ARP names the protocol it resolves by that protocol's EtherType (RFC 826),
#: so IPv4's protocol type is the IPv4 EtherType, not a number of its own.
_PTYPE_IPV4 = ETH_P_IP
_HLEN = MAC_LENGTH
_PLEN = 4
ARP_REQUEST = 1
ARP_REPLY = 2

#: ICMPv6 neighbour discovery.
ICMPV6_NEIGHBOUR_SOLICITATION = 135
ICMPV6_NEIGHBOUR_ADVERTISEMENT = 136
_ND_OPT_SOURCE_LINK_ADDRESS = 1
_ND_OPT_TARGET_LINK_ADDRESS = 2

#: Bytes read for one link-layer frame (an ARP reply, a neighbour
#: advertisement, a captured DHCP reply). A standard Ethernet frame fits
#: whole; anything longer is cut, which loses nothing the parsers read.
FRAME_RECEIVE_SIZE = 2048

#: Header sizes used when bounds-checking a received message.
_NA_HEADER = 24
_OPTION_UNIT = 8


#: Separators seen in written hardware addresses: colons, hyphens, and the
#: dotted form Cisco equipment uses.
_SEPARATORS = str.maketrans("", "", ":-.")


def normalise_mac(mac: str) -> str | None:
    """Return a hardware address in one canonical form for comparison.

    Args:
        mac: An address in any common written form - ``aa:bb:cc:dd:ee:ff``,
            ``AA-BB-CC-DD-EE-FF`` or ``aabb.ccdd.eeff``.

    Returns:
        The lowercase colon-separated form, or ``None`` when the input is not
        an Ethernet address at all.

    Examples:
        >>> normalise_mac("AA-BB-CC-DD-EE-FF")
        'aa:bb:cc:dd:ee:ff'
        >>> normalise_mac("aabb.ccdd.eeff")
        'aa:bb:cc:dd:ee:ff'
        >>> normalise_mac("nonsense") is None
        True

    """

    digits = mac.translate(_SEPARATORS).lower()
    if len(digits) != 2 * MAC_LENGTH or any(character not in "0123456789abcdef" for character in digits):
        return None
    return ":".join(digits[index : index + 2] for index in range(0, 2 * MAC_LENGTH, 2))


def format_hardware_address(raw: bytes) -> str | None:
    """Return a hardware address of any length as colon-separated lowercase hex.

    Interfaces report addresses other than six-byte Ethernet ones (a Windows
    adapter up to eight bytes, an InfiniBand port twenty), so only the
    rendering is shared here; :func:`format_mac` adds the Ethernet length.

    Returns:
        The text form, or None for an empty or all-zero address, which no
        interface reports for a real one.

    Examples:
        >>> format_hardware_address(bytes.fromhex("0011223344556677"))
        '00:11:22:33:44:55:66:77'
        >>> format_hardware_address(bytes(8)) is None
        True

    """

    if not any(raw):
        return None
    return ":".join(f"{octet:02x}" for octet in raw)


def format_mac(raw: bytes) -> str | None:
    """Return the canonical ``aa:bb:cc:dd:ee:ff`` form, or None if not one.

    Examples:
        >>> format_mac(bytes.fromhex("aabbccddeeff"))
        'aa:bb:cc:dd:ee:ff'
        >>> format_mac(bytes(6)) is None
        True

    """

    if len(raw) != MAC_LENGTH:
        return None
    return format_hardware_address(raw)


def require_mac(mac: str) -> str:
    """Return a written hardware address in canonical form, or refuse it.

    The refusing counterpart of :func:`normalise_mac`, for a caller that has
    no use for an address it cannot read: one wording for the refusal, so
    every entry point that takes a hardware address says the same thing.

    Args:
        mac: An address in any form :func:`normalise_mac` accepts.

    Returns:
        The lowercase colon-separated form.

    Raises:
        ValueError: ``mac`` is not a six-byte Ethernet address.

    Examples:
        >>> require_mac("AA-BB-CC-DD-EE-FF")
        'aa:bb:cc:dd:ee:ff'
        >>> require_mac("aa:bb")
        Traceback (most recent call last):
        ...
        ValueError: 'aa:bb' is not a hardware address

    """

    canonical = normalise_mac(mac)
    if canonical is None:
        msg = f"{mac!r} is not a hardware address"
        raise ValueError(msg)
    return canonical


def packed_mac(mac: str) -> bytes:
    """Return a written hardware address as its six bytes, or refuse it.

    Read through :func:`require_mac`, so a frame is never built from a short
    or long address: two bytes would be zero-padded by the frame layout into
    an address nobody holds, and a seventh byte would be kept and dropped
    silently by ``struct``.

    Args:
        mac: An address in any form :func:`normalise_mac` accepts.

    Returns:
        The six bytes, in transmission order.

    Raises:
        ValueError: ``mac`` is not a six-byte Ethernet address.

    Examples:
        >>> packed_mac("02-00-5E-10-00-00").hex()
        '02005e100000'
        >>> packed_mac("aa:bb:cc:dd:ee:ff:00")
        Traceback (most recent call last):
        ...
        ValueError: 'aa:bb:cc:dd:ee:ff:00' is not a hardware address

    """

    return bytes.fromhex(require_mac(mac).replace(":", ""))


def build_arp_request(*, sender_mac: str, sender_ip: str, target_ip: str) -> bytes:
    """Build the Ethernet frame that asks who holds an IPv4 address.

    Args:
        sender_mac: This host's hardware address on the sending interface.
        sender_ip: This host's address on the target's subnet. The reply comes
            back to it, so an address from the wrong subnet gets no answer.
        target_ip: The address being asked about.

    Returns:
        A complete frame, ready to write to a link-layer socket.

    Raises:
        ValueError: ``sender_mac`` is not a six-byte Ethernet address.

    Examples:
        >>> frame = build_arp_request(sender_mac="aa:bb:cc:dd:ee:ff",
        ...                           sender_ip="192.168.1.2", target_ip="192.168.1.5")
        >>> len(frame), frame[:6] == BROADCAST
        (42, True)

    """

    sender = packed_mac(sender_mac)
    body = _ARP.pack(
        HTYPE_ETHERNET,
        _PTYPE_IPV4,
        _HLEN,
        _PLEN,
        ARP_REQUEST,
        sender,
        require_address(sender_ip, AddressFamily.IPV4).packed,
        # The target's hardware address is what is being asked for, so it is
        # left empty rather than guessed.
        bytes(MAC_LENGTH),
        require_address(target_ip, AddressFamily.IPV4).packed,
    )
    return ETHERNET.pack(BROADCAST, sender, ETH_P_ARP) + body


def parse_arp_reply(frame: bytes, target_ip: str) -> str | None:
    """Return the hardware address in an ARP reply about one address.

    Args:
        frame: A frame as read from the link-layer socket.
        target_ip: The address the query asked about.

    Returns:
        The hardware address, or ``None`` when this frame is not a reply, is
        about a different address, or is malformed. A link-layer socket sees
        every frame on the segment, so most of what arrives is somebody
        else's traffic and must be discarded rather than parsed.

    Examples:
        >>> parse_arp_reply(b"", "192.168.1.5") is None
        True

    """

    if len(frame) < ETHERNET.size + _ARP.size:
        return None
    _dst, _src, ethertype = ETHERNET.unpack(frame[: ETHERNET.size])
    if ethertype != ETH_P_ARP:
        return None

    htype, ptype, hlen, plen, operation, sender_mac, sender_ip, _tha, _tpa = _ARP.unpack(frame[ETHERNET.size : ETHERNET.size + _ARP.size])
    if (htype, ptype, hlen, plen, operation) != (HTYPE_ETHERNET, _PTYPE_IPV4, _HLEN, _PLEN, ARP_REPLY):
        return None
    # struct "4s" always yields four bytes, so this conversion cannot fail.
    if socket.inet_ntoa(sender_ip) != target_ip:
        return None
    return format_mac(sender_mac)


def solicited_node_multicast(target_ip: str) -> str:
    """Return the IPv6 group a solicitation for one address is sent to.

    Neighbour discovery does not broadcast. It addresses the solicited-node
    multicast group derived from the low 24 bits of the target, so only hosts
    whose address ends the same way have to process it.

    Examples:
        >>> solicited_node_multicast("fe80::1122:3344:5566:7788")
        'ff02::1:ff66:7788'

    """

    packed = socket.inet_pton(socket.AF_INET6, target_ip)
    prefix = socket.inet_pton(socket.AF_INET6, "ff02::1:ff00:0")
    return socket.inet_ntop(socket.AF_INET6, prefix[:13] + packed[13:])


def build_neighbour_solicitation(*, sender_mac: str, target_ip: str) -> bytes:
    """Build the ICMPv6 body asking who holds an IPv6 address.

    Args:
        sender_mac: This host's hardware address, carried as an option so the
            answering host can reply without asking back.
        target_ip: The address being asked about.

    Returns:
        The ICMPv6 message. The checksum is left zero: a raw ICMPv6 socket
        computes it in the kernel, because it covers a pseudo-header the
        sender does not otherwise know.

    Raises:
        ValueError: ``sender_mac`` is not a six-byte Ethernet address.

    Examples:
        >>> message = build_neighbour_solicitation(sender_mac="aa:bb:cc:dd:ee:ff",
        ...                                        target_ip="fe80::1")
        >>> message[0], len(message)
        (135, 32)

    """

    header = struct.pack("!BBHI", ICMPV6_NEIGHBOUR_SOLICITATION, 0, 0, 0)
    option = struct.pack("!BB6s", _ND_OPT_SOURCE_LINK_ADDRESS, 1, packed_mac(sender_mac))
    return header + socket.inet_pton(socket.AF_INET6, target_ip) + option


def _target_link_address(message: bytes) -> str | None:
    """Return the target link-layer option's address, if the message has one.

    Options are a type/length list where the length counts 8-byte units,
    including the two header bytes. A zero length would not advance the walk,
    so it ends it rather than looping forever.
    """

    position = _NA_HEADER
    while position + 2 <= len(message):
        option_type = message[position]
        units = message[position + 1]
        end = position + units * _OPTION_UNIT
        if units == 0 or end > len(message):
            return None
        if option_type == _ND_OPT_TARGET_LINK_ADDRESS:
            return format_mac(message[position + 2 : position + 2 + MAC_LENGTH])
        position = end
    return None


def parse_neighbour_advertisement(message: bytes, target_ip: str) -> str | None:
    """Return the hardware address in a neighbour advertisement.

    Args:
        message: The ICMPv6 message, without its IPv6 header, as a raw
            ICMPv6 socket delivers it.
        target_ip: The address the solicitation asked about.

    Returns:
        The hardware address from the target link-layer option, or ``None``
        when this is not an advertisement about that address. An
        advertisement may legitimately carry no option, in which case there is
        nothing to report.

    Examples:
        >>> parse_neighbour_advertisement(b"", "fe80::1") is None
        True

    """

    if len(message) < _NA_HEADER or message[0] != ICMPV6_NEIGHBOUR_ADVERTISEMENT:
        return None
    try:
        if socket.inet_ntop(socket.AF_INET6, message[8:24]) != ipaddress.ip_address(target_ip).compressed:
            return None
    except (OSError, ValueError):  # pragma: no cover - malformed kernel data
        return None

    return _target_link_address(message)


def send_neighbour_solicitation(sock: socket.socket, *, interface: str, target_ip: str, source_mac: str, timeout: float) -> None:
    """Send a neighbour solicitation on a raw ICMPv6 socket the caller opened.

    The multicast interface is pinned before sending because the
    solicited-node group exists on every link: left to the routing table, the
    solicitation could leave by an interface the target is not on.

    Args:
        sock: An ICMPv6 socket. Opening it is the caller's, because that is
            where the privilege is needed and each platform words the refusal
            differently.
        interface: The interface to send on; its index scopes both the
            multicast egress and the destination.
        target_ip: The IPv6 address being asked about.
        source_mac: This host's hardware address, carried as an option.
        timeout: Seconds the socket waits on each later operation.

    Raises:
        OSError: The interface is unknown, the option or the send was refused.
            Nothing is caught here: each caller maps the failure itself, and a
            ``PermissionError`` from the send must stay distinguishable.
        ValueError: ``source_mac`` is not a six-byte Ethernet address.

    Examples:
        >>> import socket
        >>> sock = socket.socket()
        >>> try:
        ...     send_neighbour_solicitation(sock, interface="no-such-if0", target_ip="fe80::1",
        ...                                 source_mac="02:00:5e:10:00:00", timeout=1.0)
        ... except OSError:
        ...     print("refused")
        ... finally:
        ...     sock.close()
        refused

    """

    index = socket.if_nametoindex(interface)
    sock.setsockopt(AddressFamily.IPV6.ip_option_level, socket.IPV6_MULTICAST_IF, index)
    sock.settimeout(timeout)
    group = solicited_node_multicast(target_ip)
    # Port 0 and flow info 0: ICMPv6 has no ports, and the scope id is the
    # interface index so a link-local group resolves on the right link.
    sock.sendto(build_neighbour_solicitation(sender_mac=source_mac, target_ip=target_ip), (group, 0, 0, index))


def await_answer(sock: socket.socket, *, timeout: float, parse: Callable[[bytes], str | None]) -> str | None:
    """Read frames until one parses to an answer, or the time runs out.

    A link-layer or raw ICMPv6 socket sees traffic that is not the reply
    being waited for, so each frame goes to ``parse`` and the ones it rejects
    are dropped. The socket timeout is reset to what is left before every
    read, so a stream of unrelated frames cannot stretch the wait past
    ``timeout``.

    Args:
        sock: The socket the request went out on.
        timeout: Seconds to wait in total, counted from this call.
        parse: Returns the answer a frame carries, or ``None`` for a frame
            that is not one.

    Returns:
        The first non-``None`` result of ``parse``, or ``None`` when the time
        ran out first. A timeout is an answer ("nobody replied"), which is why
        it is the only exception handled here.

    Raises:
        OSError: Reading failed for any reason other than the timeout.
            Uncaught on purpose: "could not read" is not "nobody answered",
            and each caller maps it to its own error.

    Examples:
        >>> import socket
        >>> receiver, sender = socket.socketpair()
        >>> _ = sender.send(b"reply")
        >>> await_answer(receiver, timeout=1.0, parse=lambda frame: frame.decode())
        'reply'
        >>> receiver.close(); sender.close()

    """

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sock.settimeout(seconds_left(deadline))
        try:
            frame = sock.recv(FRAME_RECEIVE_SIZE)
        except TimeoutError:
            return None
        found = parse(frame)
        if found is not None:
            return found
    return None
