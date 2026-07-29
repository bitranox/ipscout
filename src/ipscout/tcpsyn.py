"""TCP SYN packet codec. Pure bytes in, pure bytes out, no I/O.

Contents:
    build_syn: An IPv4 + TCP SYN packet aimed at one port.
    parse_tcp_reply: What a reply says about that port, if it is ours.
    checksum: The one's-complement sum both headers use.

Note:
    Separated from the raw socket that carries these, because sending them
    needs root or ``CAP_NET_RAW`` and so cannot run in CI, while every test of
    this module can.

    The TCP checksum covers a pseudo-header built from the IP addresses and
    the protocol, which is why this needs both endpoints to compute a packet
    that will not simply be dropped.

"""

from __future__ import annotations

import socket
import struct

from .models import PortState

__all__ = ["TCP_HEADER_SIZE", "build_syn", "checksum", "parse_tcp_reply"]

#: IPv4 header without options, and the TCP header without options.
_IPV4 = struct.Struct("!BBHHHBBH4s4s")
_TCP = struct.Struct("!HHIIBBHHH")
IPV4_HEADER_SIZE = 20
TCP_HEADER_SIZE = 20

#: TCP flag bits this module cares about.
FIN = 0x01
SYN = 0x02
RST = 0x04
ACK = 0x10

#: Version 4, header length 5 words, packed into one byte.
_VERSION_IHL = 0x45
_DEFAULT_TTL = 64

#: A data offset of five 32-bit words: a header with no options.
_DATA_OFFSET = 5 << 4

#: Advertised window. Any plausible value works; the target never sends data.
_WINDOW = 65535

#: The low nibble of the first byte counts 32-bit words.
_IHL_MASK = 0x0F
_WORD = 4


def checksum(data: bytes) -> int:
    """Return the one's-complement checksum used by IP and TCP.

    Args:
        data: The bytes to sum, padded internally if their length is odd.

    Returns:
        The 16-bit checksum, ready to place in a header.

    Examples:
        >>> checksum(b"\\x00\\x00")
        65535
        >>> checksum(b"") == 0xFFFF
        True

    """

    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    # Fold the carries back in, twice, since the first fold can carry again.
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _pseudo_header(source_ip: str, target_ip: str, length: int) -> bytes:
    """Return the pseudo-header the TCP checksum is computed over."""

    return struct.pack(
        "!4s4sBBH",
        socket.inet_aton(source_ip),
        socket.inet_aton(target_ip),
        0,
        socket.IPPROTO_TCP,
        length,
    )


def build_syn(*, source_ip: str, target_ip: str, source_port: int, target_port: int, sequence: int = 0) -> bytes:
    """Build an IPv4 packet carrying a TCP SYN.

    Args:
        source_ip: This host's address on the route to the target. The reply
            comes back to it, so a wrong one is never answered.
        target_ip: The address being scanned.
        source_port: The port replies will be matched on. It is what
            distinguishes this scan's answers from every other TCP packet the
            raw socket will see.
        target_port: The port being asked about.
        sequence: The initial sequence number.

    Returns:
        The complete packet, ready for a raw socket with ``IP_HDRINCL``.

    Examples:
        >>> packet = build_syn(source_ip="192.168.1.2", target_ip="192.168.1.5",
        ...                    source_port=40000, target_port=80)
        >>> len(packet)
        40
        >>> packet[9] == 6  # protocol TCP
        True

    """

    tcp = _TCP.pack(source_port, target_port, sequence, 0, _DATA_OFFSET, SYN, _WINDOW, 0, 0)
    tcp_checksum = checksum(_pseudo_header(source_ip, target_ip, len(tcp)) + tcp)
    tcp = _TCP.pack(source_port, target_port, sequence, 0, _DATA_OFFSET, SYN, _WINDOW, tcp_checksum, 0)

    total = IPV4_HEADER_SIZE + len(tcp)
    header = _IPV4.pack(
        _VERSION_IHL,
        0,
        total,
        0,
        0,
        _DEFAULT_TTL,
        socket.IPPROTO_TCP,
        0,
        socket.inet_aton(source_ip),
        socket.inet_aton(target_ip),
    )
    # The kernel fills in the IP checksum for a raw socket, but computing it
    # costs nothing and makes the packet valid on its own terms.
    header = _IPV4.pack(
        _VERSION_IHL,
        0,
        total,
        0,
        0,
        _DEFAULT_TTL,
        socket.IPPROTO_TCP,
        checksum(header),
        socket.inet_aton(source_ip),
        socket.inet_aton(target_ip),
    )
    return header + tcp


def parse_tcp_reply(packet: bytes, *, source_port: int, target_port: int) -> PortState | None:
    """Return what a reply says about one port, or None if it is not ours.

    Args:
        packet: A packet as read from a raw TCP socket, including its IPv4
            header.
        source_port: The port the scan sent from.
        target_port: The port the scan asked about.

    Returns:
        ``OPEN`` for a SYN-ACK, ``CLOSED`` for a RST, and ``None`` when the
        packet belongs to another conversation. A raw TCP socket receives
        every TCP packet the host sees, so most of what arrives is unrelated
        and must be discarded rather than interpreted.

    Examples:
        >>> parse_tcp_reply(b"", source_port=40000, target_port=80) is None
        True

    """

    if len(packet) < IPV4_HEADER_SIZE:
        return None
    header_length = (packet[0] & _IHL_MASK) * _WORD
    # Options make the header longer; assuming 20 bytes would read the TCP
    # header from the middle of them.
    if header_length < IPV4_HEADER_SIZE or len(packet) < header_length + TCP_HEADER_SIZE:
        return None

    fields = _TCP.unpack(packet[header_length : header_length + TCP_HEADER_SIZE])
    reply_source, reply_target, _seq, _ack, _offset, flags = fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]

    # The reply's ports are the mirror of the ones sent.
    if reply_source != target_port or reply_target != source_port:
        return None
    if flags & SYN and flags & ACK:
        return PortState.OPEN
    if flags & RST:
        return PortState.CLOSED
    return None
