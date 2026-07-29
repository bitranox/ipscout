"""TCP SYN packet codec. Pure bytes in, pure bytes out, no I/O.

Contents:
    build_syn: An IPv4 + TCP SYN packet aimed at one port.
    read_reply: Which port a reply concerns and what it says.
    parse_tcp_reply: The same, asked about one specific port.
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

__all__ = ["TCP_HEADER_SIZE", "build_syn", "checksum", "parse_tcp_reply", "read_reply"]

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


def read_reply(packet: bytes, *, source_port: int, peer_ip: str | None = None) -> tuple[int, PortState] | None:
    """Return which port a reply concerns and what it says, or None.

    Args:
        packet: A packet as read from a raw TCP socket, including its IPv4
            header.
        source_port: The port the scan sent from.
        peer_ip: The host being scanned. A packet from anywhere else is
            discarded.

    Returns:
        ``(port, state)``, or ``None`` when the packet is not an answer to
        this scan.

    Note:
        The packet already names the port it is about, so a caller with many
        ports outstanding reads it once and looks the port up. Testing each
        outstanding port against each packet instead is quadratic: at 0.26
        microseconds a parse, a full-range scan spends about eighteen minutes
        doing nothing else.

    Examples:
        >>> read_reply(b"", source_port=40000) is None
        True

    """

    ours = _ours_or_none(packet, source_port=source_port, peer_ip=peer_ip)
    if ours is None:
        return None

    reply_source, flags = ours
    if flags & SYN and flags & ACK:
        return reply_source, PortState.OPEN
    if flags & RST:
        return reply_source, PortState.CLOSED
    return None


def _ours_or_none(packet: bytes, *, source_port: int, peer_ip: str | None) -> tuple[int, int] | None:
    """Return a reply's source port and flags, or None if it is not ours.

    A raw TCP socket receives every TCP packet the host sees, so nearly all of
    it belongs to somebody else and must be rejected before anything is read
    out of it.
    """

    if len(packet) < IPV4_HEADER_SIZE:
        return None
    if peer_ip is not None and socket.inet_ntoa(packet[12:16]) != peer_ip:
        return None

    header_length = (packet[0] & _IHL_MASK) * _WORD
    # Options make the header longer; assuming 20 bytes would read the TCP
    # header from the middle of them.
    if header_length < IPV4_HEADER_SIZE or len(packet) < header_length + TCP_HEADER_SIZE:
        return None

    fields = _TCP.unpack(packet[header_length : header_length + TCP_HEADER_SIZE])
    reply_source, reply_target, flags = fields[0], fields[1], fields[5]
    # The reply's destination is the port the scan sent from.
    return (reply_source, flags) if reply_target == source_port else None


def parse_tcp_reply(packet: bytes, *, source_port: int, target_port: int, peer_ip: str | None = None) -> PortState | None:
    """Return what a reply says about one specific port, or None.

    Args:
        packet: A packet as read from a raw TCP socket, including its IPv4
            header.
        source_port: The port the scan sent from.
        target_port: The port being asked about.
        peer_ip: The host being scanned. A packet from anywhere else is
            discarded.

    Returns:
        ``OPEN`` for a SYN-ACK, ``CLOSED`` for a RST, and ``None`` when the
        packet answers a different port or another conversation entirely.

    Note:
        For one port. A caller waiting on many should use :func:`read_reply`,
        which reads the port out of the packet rather than being asked about
        each in turn.

    Examples:
        >>> parse_tcp_reply(b"", source_port=40000, target_port=80) is None
        True

    """

    answer = read_reply(packet, source_port=source_port, peer_ip=peer_ip)
    if answer is None or answer[0] != target_port:
        return None
    return answer[1]
