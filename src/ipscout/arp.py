"""ARP and NDP message codecs. Pure bytes in, pure bytes out, no I/O.

Contents:
    build_arp_request: An Ethernet frame asking who holds an IPv4 address.
    parse_arp_reply: The hardware address in a reply, if it answers our query.
    build_neighbour_solicitation: The ICMPv6 equivalent for IPv6.
    parse_neighbour_advertisement: The hardware address in its reply.
    solicited_node_multicast: The IPv6 group a solicitation is sent to.

Note:
    Separated from the sockets that carry these so the wire formats can be
    tested without the privileges the sockets need. That matters here more
    than anywhere else in this package: sending either message requires root
    or ``CAP_NET_RAW``, so the transmit paths cannot run in CI at all, while
    everything in this module can.

"""

from __future__ import annotations

import ipaddress
import socket
import struct

__all__ = [
    "ETHERNET",
    "ETHERNET_HEADER_SIZE",
    "build_arp_request",
    "build_neighbour_solicitation",
    "format_mac",
    "parse_arp_reply",
    "parse_neighbour_advertisement",
    "solicited_node_multicast",
]

#: Ethernet: destination, source, ethertype.
ETHERNET = struct.Struct("!6s6sH")
ETHERNET_HEADER_SIZE = ETHERNET.size
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_VLAN = 0x8100
ETH_P_IPV6 = 0x86DD
BROADCAST = b"\xff" * 6

#: ARP: hardware type, protocol type, lengths, operation, then the addresses.
_ARP = struct.Struct("!HHBBH6s4s6s4s")
_HTYPE_ETHERNET = 1
_PTYPE_IPV4 = 0x0800
_HLEN = 6
_PLEN = 4
ARP_REQUEST = 1
ARP_REPLY = 2

#: ICMPv6 neighbour discovery.
ICMPV6_NEIGHBOUR_SOLICITATION = 135
ICMPV6_NEIGHBOUR_ADVERTISEMENT = 136
_ND_OPT_SOURCE_LINK_ADDRESS = 1
_ND_OPT_TARGET_LINK_ADDRESS = 2

#: An Ethernet hardware address is six bytes.
MAC_LENGTH = 6

#: Header sizes used when bounds-checking a received message.
_NA_HEADER = 24
_OPTION_UNIT = 8


def format_mac(raw: bytes) -> str | None:
    """Return the canonical ``aa:bb:cc:dd:ee:ff`` form, or None if not one.

    Examples:
        >>> format_mac(bytes.fromhex("aabbccddeeff"))
        'aa:bb:cc:dd:ee:ff'
        >>> format_mac(bytes(6)) is None
        True

    """

    if len(raw) != MAC_LENGTH or not any(raw):
        return None
    return ":".join(f"{octet:02x}" for octet in raw)


def _packed_mac(mac: str) -> bytes:
    """Return a written hardware address as its six bytes."""

    digits = mac.replace(":", "").replace("-", "").replace(".", "")
    return bytes.fromhex(digits)


def build_arp_request(*, sender_mac: str, sender_ip: str, target_ip: str) -> bytes:
    """Build the Ethernet frame that asks who holds an IPv4 address.

    Args:
        sender_mac: This host's hardware address on the sending interface.
        sender_ip: This host's address on the target's subnet. The reply comes
            back to it, so an address from the wrong subnet gets no answer.
        target_ip: The address being asked about.

    Returns:
        A complete frame, ready to write to a link-layer socket.

    Examples:
        >>> frame = build_arp_request(sender_mac="aa:bb:cc:dd:ee:ff",
        ...                           sender_ip="192.168.1.2", target_ip="192.168.1.5")
        >>> len(frame), frame[:6] == BROADCAST
        (42, True)

    """

    sender = _packed_mac(sender_mac)
    body = _ARP.pack(
        _HTYPE_ETHERNET,
        _PTYPE_IPV4,
        _HLEN,
        _PLEN,
        ARP_REQUEST,
        sender,
        socket.inet_aton(sender_ip),
        # The target's hardware address is what is being asked for, so it is
        # left empty rather than guessed.
        bytes(MAC_LENGTH),
        socket.inet_aton(target_ip),
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
    if (htype, ptype, hlen, plen, operation) != (_HTYPE_ETHERNET, _PTYPE_IPV4, _HLEN, _PLEN, ARP_REPLY):
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

    Examples:
        >>> message = build_neighbour_solicitation(sender_mac="aa:bb:cc:dd:ee:ff",
        ...                                        target_ip="fe80::1")
        >>> message[0], len(message)
        (135, 32)

    """

    header = struct.pack("!BBHI", ICMPV6_NEIGHBOUR_SOLICITATION, 0, 0, 0)
    option = struct.pack("!BB6s", _ND_OPT_SOURCE_LINK_ADDRESS, 1, _packed_mac(sender_mac))
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
