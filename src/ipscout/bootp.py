"""BOOTP and DHCP reply decoding. Pure bytes in, records out, no I/O.

Contents:
    DhcpReply: One server reply carrying an address for a hardware address.
    offers_from_frames: Every distinct address offered to one hardware address.
    merge_offers: The first-seen ordering and de-duplication rule, on its own.

Which replies count, and why the rule is deliberately inclusive:
    Any ``BOOTREPLY`` carrying a non-zero ``yiaddr`` counts, whatever its DHCP
    message type says. Not offers only, and not acknowledgements only.

    Measured on a real bridge, one hardware address produced ``OFFER, OFFER,
    ACK, OFFER, ACK`` for the same address in a single boot. Duplicates collapse
    to one entry regardless of the filter, so a narrower rule buys **no**
    precision at all - it can only ever return fewer addresses, never more
    accurate ones. That asymmetry is the whole argument: the inclusive rule's
    supposed cost is nil, and the alternative carries pure downside.

    Narrowing to acknowledgements would also drop exactly the address a guest
    is offered, declines after duplicate-address detection, and never binds -
    which is the one a caller most needs to know about, because trying it and
    finding it dead is how it learns to try the next.

    A ``DHCPNAK``, the one reply that must not count, sets ``yiaddr`` to zero
    and is excluded by the same rule that excludes a client's own request.

Note:
    Separated from the socket that carries these for the reason ``arp`` is:
    capturing a frame needs root or ``CAP_NET_RAW``, so the capture cannot run
    in CI at all, while every line of this module can.

"""

from __future__ import annotations

import enum
import socket
import struct
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from .arp import ETH_P_IP, ETH_P_VLAN, ETHERNET, ETHERNET_HEADER_SIZE, MAC_LENGTH, format_mac

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

__all__ = [
    "BOOTP_FIXED_SIZE",
    "DHCP_CLIENT_PORT",
    "DHCP_SERVER_PORT",
    "MAGIC_COOKIE",
    "BootpOperation",
    "DhcpMessageType",
    "DhcpReply",
    "merge_offers",
    "offers_from_frames",
]

#: The BOOTP fixed header, RFC 951 and RFC 2131: operation, hardware type,
#: hardware address length, hops, transaction id, seconds, flags, then the
#: client, your, server and gateway addresses, the client hardware address,
#: and the legacy server-name and boot-file fields.
_BOOTP = struct.Struct("!BBBBIHH4s4s4s4s16s64s128s")
BOOTP_FIXED_SIZE = _BOOTP.size

#: IPv4 without options, and UDP. Both headers are read by offset rather than
#: unpacked whole, so only their sizes are needed here.
_IPV4_MIN_HEADER = 20
_UDP_HEADER_SIZE = 8
_IPV4_VERSION = 4
_IPPROTO_UDP = 17

#: DHCP rides on these two ports. A reply always leaves the server port; it
#: arrives at 68 directly or at 67 through a relay, so the source is what
#: identifies it and the destination is only sanity-checked.
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68

#: The four bytes marking a BOOTP packet as carrying DHCP options (RFC 2132).
MAGIC_COOKIE = b"\x63\x82\x53\x63"
_COOKIE_END = BOOTP_FIXED_SIZE + len(MAGIC_COOKIE)


class BootpOperation(enum.IntEnum):
    """Which way a BOOTP packet is travelling.

    ``IntEnum`` rather than ``StrEnum``: this is one byte of the fixed header
    and is genuinely an integer on the wire, so the members compare equal to
    the bytes without any conversion at the parse.
    """

    REQUEST = 1
    REPLY = 2


#: Ethernet is hardware type 1, with six-byte addresses. Anything else means
#: ``chaddr`` is not a MAC, so comparing it to one would be meaningless.
_HTYPE_ETHERNET = 1


class DhcpMessageType(enum.IntEnum):
    """What a DHCP packet is saying, from option 53 (RFC 2132).

    The whole RFC 2131 set, not only the ones this codec reasons about: a
    capture sees the entire segment, and INFORM in particular turns up
    unbidden from unrelated hosts. Declaring the full set is what keeps such a
    packet a recognised value rather than an unknown one.
    """

    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8


#: Option block codes used while walking it.
_OPT_PAD = 0
_OPT_MESSAGE_TYPE = 53
_OPT_END = 255

#: An address of all zeroes. In ``yiaddr`` it means the packet is not handing
#: out an address: a client request and a DHCPNAK both look like this.
_UNSPECIFIED = bytes(4)


def _ip_payload(frame: bytes) -> bytes | None:
    """Return the IPv4 packet inside a captured frame, or None.

    Accepts a frame with an Ethernet header, a frame carrying one 802.1Q tag,
    and a bare IPv4 packet with no link header at all. The last shape is not
    hypothetical: a datagram packet socket and the Windows promiscuous socket
    both deliver IP-level data, so a capture backend cannot promise a link
    header is present.

    The bare form is detected from the data rather than from ``sys.platform``,
    the argument ``packet.strip_ip_header`` makes. It is tested first and
    guarded harder than a version nibble alone, because byte 0 of an Ethernet
    frame is a destination address that can legitimately begin with 0x4: the
    protocol byte must also say UDP and the two length fields must agree with
    the buffer before a frame is read as headerless.
    """

    if _looks_like_bare_ipv4(frame):
        return frame
    if len(frame) < ETHERNET_HEADER_SIZE:
        return None

    _destination, _source, ethertype = ETHERNET.unpack(frame[:ETHERNET_HEADER_SIZE])
    offset = ETHERNET_HEADER_SIZE
    if ethertype == ETH_P_VLAN:
        # One tag is unwrapped; a second (QinQ) is refused rather than guessed
        # at, so a stacked frame yields nothing instead of a wrong address.
        if len(frame) < ETHERNET_HEADER_SIZE + 4:
            return None
        ethertype = int.from_bytes(frame[offset + 2 : offset + 4], "big")
        offset += 4
    if ethertype != ETH_P_IP:
        return None
    return frame[offset:]


def _looks_like_bare_ipv4(frame: bytes) -> bool:
    """Return whether a buffer is an IPv4 UDP packet with no link header."""

    if len(frame) < _IPV4_MIN_HEADER or (frame[0] >> 4) != _IPV4_VERSION:
        return False
    if frame[9] != _IPPROTO_UDP:
        return False
    header_len = (frame[0] & 0x0F) * 4
    total_len = int.from_bytes(frame[2:4], "big")
    return header_len >= _IPV4_MIN_HEADER and header_len <= len(frame) and header_len <= total_len <= len(frame)


def _udp_payload(packet: bytes) -> tuple[str, bytes] | None:
    """Return the server address and BOOTP body of a DHCP reply, or None.

    The UDP length field is read but not trusted for slicing: a capture taken
    with a small snapshot length reports the full length while holding less,
    so the body is bounded by the buffer and a short one is refused later by
    the fixed-header size check rather than raising here.
    """

    if len(packet) < _IPV4_MIN_HEADER or (packet[0] >> 4) != _IPV4_VERSION:
        return None
    header_len = (packet[0] & 0x0F) * 4
    if header_len < _IPV4_MIN_HEADER or packet[9] != _IPPROTO_UDP:
        return None
    # A non-first fragment carries no UDP header. DHCP is a few hundred bytes
    # and is never legitimately fragmented, so this is somebody else's traffic.
    if int.from_bytes(packet[6:8], "big") & 0x1FFF:
        return None
    if len(packet) < header_len + _UDP_HEADER_SIZE:
        return None

    source_port, destination_port = struct.unpack("!HH", packet[header_len : header_len + 4])
    if source_port != DHCP_SERVER_PORT or destination_port not in (DHCP_SERVER_PORT, DHCP_CLIENT_PORT):
        return None
    return socket.inet_ntoa(packet[12:16]), packet[header_len + _UDP_HEADER_SIZE :]


def _message_type(body: bytes) -> DhcpMessageType | None:
    """Return the DHCP message type in option 53, or None when there is none.

    A reply is not required to carry options at all - a plain BOOTP server
    answers with a real ``yiaddr`` and no magic cookie - so an absent type is
    reported as ``None`` rather than treated as a malformed packet.

    The walk is bounded at every step and stops rather than raising on a
    truncated option, since a capture cut mid-packet is ordinary input here.
    """

    if len(body) < _COOKIE_END or body[BOOTP_FIXED_SIZE:_COOKIE_END] != MAGIC_COOKIE:
        return None

    position = _COOKIE_END
    while position < len(body):
        code = body[position]
        if code == _OPT_END:
            return None
        if code == _OPT_PAD:
            position += 1
            continue
        if position + 2 > len(body):
            return None
        length = body[position + 1]
        if position + 2 + length > len(body):
            return None
        if code == _OPT_MESSAGE_TYPE and length >= 1:
            # An unrecognised type is reported as absent rather than raised:
            # a vendor or future value must not turn a real offer into an
            # exception, and the yiaddr rule decides what counts anyway.
            return _known_message_type(body[position + 2])
        position += 2 + length
    return None


def _known_message_type(value: int) -> DhcpMessageType | None:
    """Return the message type for a byte, or None when it names none."""

    try:
        return DhcpMessageType(value)
    except ValueError:
        return None


class DhcpReply(BaseModel):
    """A server reply handing an address to one hardware address.

    Attributes:
        client_mac: Who the address is for, from ``chaddr``, canonicalised.
        offered_ip: The address being handed out, from ``yiaddr``. Never
            ``0.0.0.0``, since a packet offering nothing is not a reply worth
            reporting.
        server_ip: Which server sent it, taken from the IPv4 source address
            rather than from ``siaddr``, which is frequently left empty.
        transaction_id: The ``xid``, so one exchange can be told from another.
        message_type: The DHCP message type from option 53, or ``None`` for a
            plain BOOTP reply that carries no options.

    Examples:
        >>> DhcpReply.from_frame(b"") is None
        True

    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    client_mac: str
    offered_ip: str
    server_ip: str
    transaction_id: int
    message_type: DhcpMessageType | None = None

    @classmethod
    def from_frame(cls, frame: bytes) -> DhcpReply | None:
        """Return the reply a captured frame carries, or None if it is not one.

        Args:
            frame: Bytes exactly as captured, with an Ethernet header, with an
                802.1Q tag, or as a bare IPv4 packet.

        Returns:
            The parsed reply, or ``None`` for anything that is not a server
            reply handing out an address. A capture sees every frame on the
            segment, so almost everything that arrives is somebody else's and
            has to be discarded rather than parsed. Truncated input is
            discarded the same way and never raises: a capture cut short is
            ordinary, not exceptional.

        Examples:
            A client's own request offers nothing, so it is not a reply:

            >>> DhcpReply.from_frame(bytes(400)) is None
            True

        """

        packet = _ip_payload(frame)
        if packet is None:
            return None
        parsed = _udp_payload(packet)
        if parsed is None:
            return None
        server_ip, body = parsed
        if len(body) < BOOTP_FIXED_SIZE:
            return None

        operation, htype, hlen, _hops, xid, _secs, _flags, _ciaddr, yiaddr, _siaddr, _giaddr, chaddr, _sname, _file = _BOOTP.unpack(body[:BOOTP_FIXED_SIZE])
        # One refusal covering three ways a packet is not an offer: it is
        # travelling the other way, its chaddr is not a MAC so comparing it to
        # one would be meaningless, or it hands out no address at all - which
        # is what both a client request and a DHCPNAK look like.
        if operation != BootpOperation.REPLY or (htype, hlen) != (_HTYPE_ETHERNET, MAC_LENGTH) or yiaddr == _UNSPECIFIED:
            return None

        client_mac = format_mac(chaddr[:MAC_LENGTH])
        if client_mac is None:
            return None
        return cls(
            client_mac=client_mac,
            offered_ip=socket.inet_ntoa(yiaddr),
            server_ip=server_ip,
            transaction_id=xid,
            message_type=_message_type(body),
        )


def merge_offers(existing: Sequence[str], new: Iterable[str]) -> list[str]:
    """Return the union of two address lists in first-seen order.

    Args:
        existing: Addresses already known, in the order they were first seen.
        new: Addresses just observed, in arrival order.

    Returns:
        Every distinct address, keeping the position each was first seen at.

    Note:
        Defined once, here, rather than inside the capture loop, so that the
        one-shot call and the streaming session cannot disagree about what
        "distinct, in order" means.

    Examples:
        >>> merge_offers(["198.51.100.36"], ["198.51.100.36", "198.51.100.51"])
        ['198.51.100.36', '198.51.100.51']

    """

    merged = list(existing)
    seen = set(merged)
    for address in new:
        if address not in seen:
            seen.add(address)
            merged.append(address)
    return merged


def offers_from_frames(frames: Iterable[bytes], *, mac: str, message_types: frozenset[DhcpMessageType] | None = None) -> list[str]:
    """Return every distinct address offered to one hardware address.

    Args:
        frames: Captured frames, in arrival order.
        mac: The hardware address to match, already in the canonical
            lowercase colon-separated form. Callers coming from user input go
            through :func:`ipscout.neighbours.normalise_mac` first, so that
            one canonicalisation serves the whole package.
        message_types: DHCP message types to accept, or ``None`` to accept any
            reply handing out an address. Narrowing is available for a caller
            who has measured its own environment; it is not the default,
            because it can only ever return fewer addresses. A plain BOOTP
            reply, which carries no type at all, matches only ``None``.

    Returns:
        Each distinct address, in the order it was first seen. Empty when
        nothing was offered to that address, which is an answer rather than a
        failure.

    Note:
        **The address a guest most likely bound is the last element, not the
        first.** A pool that hands out an address the guest then declines
        offers the working one afterwards, so both appear and the order is
        chronological rather than by preference.

    Examples:
        >>> offers_from_frames([], mac="02:00:5e:10:00:00")
        []

    """

    found: list[str] = []
    for frame in frames:
        reply = DhcpReply.from_frame(frame)
        if reply is None or reply.client_mac != mac:
            continue
        if message_types is not None and (reply.message_type is None or reply.message_type not in message_types):
            continue
        found = merge_offers(found, [reply.offered_ip])
    return found
