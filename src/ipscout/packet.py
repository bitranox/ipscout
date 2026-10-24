"""Pure ICMP echo encoding and decoding. No sockets, no I/O, no clock.

Everything here is a total function over bytes, which is what makes the
protocol layer testable without a network, without privileges and without a
particular operating system.

Contents:
    EchoPayload: The token-bearing payload carried in every request we send.
    build_echo_request: Assemble a complete ICMP or ICMPv6 echo request.
    EchoRequest: The ``(datagram, token)`` record build_echo_request returns.
    parse_echo_reply: Decode a datagram back into its identifying fields.
    checksum: The RFC 1071 one's-complement sum.

Why replies are matched on a token rather than on the identifier:
    An unprivileged datagram ICMP socket does not let the process choose its
    ICMP identifier. The kernel overwrites that field with a value of its own
    derived from the socket, so the identifier that comes back is not the one
    that was sent. Measured on Linux: an echo sent with identifier ``0xBEEF``
    produced a reply carrying ``0x4C36``.

    Matching on the identifier would therefore silently never match. Instead
    every request embeds a random token in its payload, and a reply counts as
    ours only if the payload token comes back intact. That rule is independent
    of the kernel's rewriting, so the same matching logic is correct on the
    datagram sockets, on raw sockets, and on the Windows API backend.

    The token also solves a second problem: several processes on one host can
    hold ICMP sockets at once and may be handed copies of each other's replies.
    A foreign reply fails the token check and is discarded rather than being
    counted as an answer to a probe we never sent.

"""

from __future__ import annotations

import secrets
import struct
from typing import NamedTuple

from pydantic import BaseModel, ConfigDict

from .models import AddressFamily

__all__ = [
    "DEFAULT_PAYLOAD_SIZE",
    "ECHO_REPLY_V4",
    "ECHO_REPLY_V6",
    "ECHO_REQUEST_V4",
    "ECHO_REQUEST_V6",
    "HEADER_SIZE",
    "IPV4_MIN_HEADER_SIZE",
    "MAGIC",
    "MAX_PAYLOAD_SIZE_IPV4",
    "MAX_PAYLOAD_SIZE_IPV6",
    "TOKEN_SIZE",
    "EchoPayload",
    "EchoRequest",
    "ParsedReply",
    "build_echo_request",
    "checksum",
    "is_echo_reply",
    "is_time_exceeded",
    "parse_echo_reply",
    "strip_ip_header",
]

#: ICMP type numbers. IPv4 and IPv6 disagree on every one of these.
ECHO_REQUEST_V4 = 8
ECHO_REPLY_V4 = 0
ECHO_REQUEST_V6 = 128
ECHO_REPLY_V6 = 129

#: An ICMP echo header is type, code, checksum, identifier, sequence.
_HEADER_STRUCT = struct.Struct("!BBHHH")
HEADER_SIZE = _HEADER_STRUCT.size

#: Marks a payload as ours before the token is even compared. Not security -
#: just a cheap first filter against unrelated traffic.
MAGIC = b"IPSCOUT1"

#: Bytes of randomness identifying one specific request.
TOKEN_SIZE = 8

#: Smallest payload that can still carry magic and token.
MIN_PAYLOAD_SIZE = len(MAGIC) + TOKEN_SIZE

#: Default bytes of ICMP payload per echo, the size the system ping sends.
DEFAULT_PAYLOAD_SIZE = 56

#: The smallest legal IPv4 header, one without options. Used to recognise a
#: header that some platforms prepend to a received ICMP datagram.
IPV4_MIN_HEADER_SIZE = 20

#: The largest datagram an IP length field can describe.
_MAX_IP_LENGTH = 65535

#: The most ICMP payload one echo can carry, per family: what the length field
#: leaves after the headers it counts. IPv4's length counts its own header;
#: IPv6's payload length does not count IPv6's fixed header, so only IPv4 pays
#: it. A larger payload cannot be sent at all, and the failed send would read
#: as a host that never answered.
MAX_PAYLOAD_SIZE_IPV4 = _MAX_IP_LENGTH - IPV4_MIN_HEADER_SIZE - HEADER_SIZE
MAX_PAYLOAD_SIZE_IPV6 = _MAX_IP_LENGTH - HEADER_SIZE


class EchoPayload(BaseModel):
    """The identifying content carried inside an echo request.

    Attributes:
        token: Random bytes unique to one request, echoed back by the peer.
        filler: Padding that brings the payload up to the requested size.

    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    token: bytes
    filler: bytes = b""

    def to_bytes(self) -> bytes:
        """Return the payload as it goes on the wire."""

        return MAGIC + self.token + self.filler

    @classmethod
    def from_bytes(cls, raw: bytes) -> EchoPayload | None:
        """Return the payload parsed from wire bytes, or None if it is foreign.

        Args:
            raw: The bytes following the ICMP header.

        Returns:
            The parsed payload, or ``None`` when the bytes are too short or do
            not start with our magic - meaning the datagram belongs to some
            other process and must be ignored.

        Examples:
            >>> original = EchoPayload(token=b"12345678", filler=b"pad")
            >>> EchoPayload.from_bytes(original.to_bytes()) == original
            True
            >>> EchoPayload.from_bytes(b"not ours at all") is None
            True
            >>> EchoPayload.from_bytes(b"") is None
            True

        """

        if len(raw) < MIN_PAYLOAD_SIZE or not raw.startswith(MAGIC):
            return None
        start = len(MAGIC)
        return cls(token=raw[start : start + TOKEN_SIZE], filler=raw[start + TOKEN_SIZE :])


class ParsedReply(BaseModel):
    """The fields of a decoded echo reply that identify which probe it answers.

    Attributes:
        icmp_type: The ICMP type byte, used to tell a reply from an error.
        code: The ICMP code byte.
        identifier: The identifier field as received. Informational only - the
            kernel rewrites it on unprivileged sockets, so it must never be
            used for matching.
        sequence: The sequence number we chose, which the peer echoes back.
        payload: The decoded payload, or ``None`` if it was not ours.

    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    icmp_type: int
    code: int
    identifier: int
    sequence: int
    payload: EchoPayload | None

    @property
    def token(self) -> bytes | None:
        """Return the echoed token, or None when the reply was not ours."""

        return self.payload.token if self.payload is not None else None


def checksum(data: bytes) -> int:
    """Return the RFC 1071 one's-complement checksum of ``data``.

    Needed for IPv4 only. For ICMPv6 the kernel computes and inserts the
    checksum itself, because the ICMPv6 checksum covers an IPv6 pseudo-header
    containing the source address, which user space does not reliably know.

    Args:
        data: The bytes to sum. An odd length is padded with a zero byte, as
            the RFC requires.

    Returns:
        The 16-bit checksum, ready to place in the header.

    Examples:
        >>> checksum(b"") == 0xFFFF
        True
        >>> value = checksum(b"\\x08\\x00\\x00\\x00\\x00\\x01")
        >>> 0 <= value <= 0xFFFF
        True

        Summing a buffer that already contains its own checksum yields zero,
        which is how a receiver validates one:

        >>> body = b"\\x08\\x00\\x00\\x00\\x12\\x34payload"
        >>> got = checksum(body)
        >>> verified = body[:2] + got.to_bytes(2, "big") + body[4:]
        >>> checksum(verified)
        0

    """

    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    # Fold the carries back in, twice, because the first fold can itself carry.
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


class EchoRequest(NamedTuple):
    """One echo request ready to send, and the token its reply must carry.

    A ``NamedTuple`` rather than a pydantic model on purpose: it was a plain
    ``(datagram, token)`` tuple first, and callers unpack it and index it. A
    NamedTuple keeps those working while letting new code name the field it
    wants - both are ``bytes``, so their order is easy to get backwards and
    nothing would type-check the mistake.

    Attributes:
        datagram: The complete ICMP or ICMPv6 message, header included, as it
            goes on the wire.
        token: The random bytes embedded in the payload. A reply counts as an
            answer to this request only if it carries them back intact.

    Examples:
        >>> request = EchoRequest(b"\\x08\\x00", b"abcdefgh")
        >>> request.token
        b'abcdefgh'
        >>> request == (b"\\x08\\x00", b"abcdefgh")
        True

    """

    datagram: bytes
    token: bytes


def build_echo_request(
    *,
    sequence: int,
    payload_size: int = DEFAULT_PAYLOAD_SIZE,
    family: AddressFamily = AddressFamily.IPV4,
    identifier: int = 0,
    token: bytes | None = None,
) -> EchoRequest:
    """Build one complete ICMP echo request.

    Args:
        sequence: Sequence number for this request. This, together with the
            token, is what identifies the reply.
        payload_size: Total payload length in bytes. Raised to the minimum
            needed to hold magic plus token when a smaller value is asked for.
        family: Which protocol to build for: ``AddressFamily.IPV6`` builds an
            ICMPv6 request, ``AddressFamily.IPV4`` an ICMPv4 one.
        identifier: Value for the identifier field. Cosmetic on unprivileged
            sockets, where the kernel overwrites it.
        token: Explicit token, for tests that need determinism. A fresh random
            token is generated when this is ``None``.

    Returns:
        An :class:`EchoRequest`. The token is returned so the caller can
        register it before the reply can possibly arrive. It is a tuple, so
        ``datagram, token = build_echo_request(...)`` still unpacks it.

    Examples:
        >>> datagram, token = build_echo_request(sequence=1, token=b"abcdefgh")
        >>> datagram[0], len(token)
        (8, 8)
        >>> build_echo_request(sequence=1, token=b"abcdefgh").token
        b'abcdefgh'

        The checksum is left to the kernel for IPv6:

        >>> v6, _ = build_echo_request(sequence=1, family=AddressFamily.IPV6, token=b"abcdefgh")
        >>> v6[0], v6[2:4]
        (128, b'\\x00\\x00')

        A round trip recovers the token:

        >>> parsed = parse_echo_reply(datagram)
        >>> parsed.token == token
        True

    """

    actual_token = token if token is not None else secrets.token_bytes(TOKEN_SIZE)
    filler_len = max(0, payload_size - MIN_PAYLOAD_SIZE)
    payload = EchoPayload(token=actual_token, filler=bytes(filler_len)).to_bytes()

    is_ipv6 = family is AddressFamily.IPV6
    icmp_type = ECHO_REQUEST_V6 if is_ipv6 else ECHO_REQUEST_V4
    # IPv6 checksums are computed by the kernel over a pseudo-header that
    # includes the source address, which is not known here; send zero.
    if is_ipv6:
        return EchoRequest(_HEADER_STRUCT.pack(icmp_type, 0, 0, identifier, sequence) + payload, actual_token)

    blank = _HEADER_STRUCT.pack(icmp_type, 0, 0, identifier, sequence) + payload
    return EchoRequest(_HEADER_STRUCT.pack(icmp_type, 0, checksum(blank), identifier, sequence) + payload, actual_token)


def strip_ip_header(datagram: bytes) -> bytes:
    """Return the datagram with any leading IPv4 header removed.

    Whether a received datagram begins at the IP header or at the ICMP header
    is not consistent across platforms. Linux ping sockets hand over just the
    ICMP message; macOS prepends the full IPv4 header, as raw sockets do on
    every BSD. Parsing the IP header as though it were the ICMP header yields a
    type byte of 0x45, which matches no ICMP type, so every reply would be
    silently discarded and a perfectly healthy host would read as 100% loss.

    The prefix is detected from the data rather than from ``sys.platform``,
    which is both simpler and more robust: ICMPv4 type numbers are all below 16,
    so a first byte whose high nibble is 4 can only be an IPv4 version field and
    never an ICMP type.

    Args:
        datagram: Bytes exactly as received.

    Returns:
        The bytes starting at the ICMP header.

    Examples:
        >>> icmp_only = b"\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x02payload"
        >>> strip_ip_header(icmp_only) == icmp_only
        True

        A 20-byte IPv4 header (version 4, IHL 5) is recognised and removed:

        >>> with_header = b"\\x45" + b"\\x00" * 19 + icmp_only
        >>> strip_ip_header(with_header) == icmp_only
        True

        A header claiming more length than the datagram holds is left alone
        rather than truncating everything away:

        >>> strip_ip_header(b"\\x4f" + b"\\x00" * 5)
        b'O\\x00\\x00\\x00\\x00\\x00'

    """

    if len(datagram) < IPV4_MIN_HEADER_SIZE or (datagram[0] >> 4) != AddressFamily.IPV4.ip_version:
        return datagram
    header_len = (datagram[0] & 0x0F) * 4
    if header_len < IPV4_MIN_HEADER_SIZE or header_len >= len(datagram):
        return datagram
    return datagram[header_len:]


def parse_echo_reply(datagram: bytes) -> ParsedReply | None:
    """Decode a received datagram into its identifying fields.

    Args:
        datagram: Bytes as received. A leading IPv4 header is removed first
            when one is present, since macOS delivers it and Linux does not.

    Returns:
        The parsed reply, or ``None`` when the datagram is too short to hold
        an ICMP header at all.

    Note:
        This does not decide whether the reply answers a particular probe. It
        reports what arrived; matching on ``sequence`` and ``token`` is the
        caller's job, because only the caller knows what is outstanding.

    Examples:
        >>> datagram, token = build_echo_request(sequence=9, token=b"ABCDEFGH")
        >>> reply = parse_echo_reply(datagram)
        >>> reply.sequence, reply.token == token
        (9, True)

        Too short to be an ICMP header at all:

        >>> parse_echo_reply(b"\\x00\\x00") is None
        True

        A well-formed header carrying somebody else's payload parses, but
        yields no token, so it can never be matched:

        >>> import struct
        >>> foreign = struct.pack("!BBHHH", 0, 0, 0, 1, 2) + b"someone elses data"
        >>> parse_echo_reply(foreign).token is None
        True

    """

    body = strip_ip_header(datagram)
    if len(body) < HEADER_SIZE:
        return None
    icmp_type, code, _sum, identifier, sequence = _HEADER_STRUCT.unpack(body[:HEADER_SIZE])
    return ParsedReply(
        icmp_type=icmp_type,
        code=code,
        identifier=identifier,
        sequence=sequence,
        payload=EchoPayload.from_bytes(body[HEADER_SIZE:]),
    )


def is_echo_reply(parsed: ParsedReply, *, family: AddressFamily) -> bool:
    """Return whether a parsed datagram is an echo reply for this family.

    Args:
        parsed: A decoded datagram.
        family: Which family's type numbers to expect.

    Returns:
        True when the type byte marks an echo reply.

    Examples:
        >>> datagram, _ = build_echo_request(sequence=1, token=b"abcdefgh")
        >>> request = parse_echo_reply(datagram)
        >>> is_echo_reply(request, family=AddressFamily.IPV4)   # an echo REQUEST, not a reply
        False

    """

    expected = ECHO_REPLY_V6 if family is AddressFamily.IPV6 else ECHO_REPLY_V4
    return parsed.icmp_type == expected


#: ICMP Time Exceeded: type 11 on IPv4, type 3 on IPv6. A router that
#: discards a probe for running out of hops sends one of these, and its source
#: address is the router itself.
TIME_EXCEEDED_V4 = 11
TIME_EXCEEDED_V6 = 3


def is_time_exceeded(datagram: bytes, *, family: AddressFamily) -> bool:
    """Return whether a datagram is an ICMP Time Exceeded message.

    Args:
        datagram: The bytes received, with or without a leading IP header.
        family: Which protocol's type numbering applies. The two disagree:
            11 on IPv4 is Time Exceeded, while 3 on IPv6 is - and 3 on IPv4
            means Destination Unreachable instead, so reading it with the
            wrong family inverts the meaning.

    Returns:
        Whether this is a router reporting that a probe ran out of hops.

    Examples:
        >>> is_time_exceeded(bytes([11, 0]) + bytes(6), family=AddressFamily.IPV4)
        True
        >>> is_time_exceeded(bytes([3, 0]) + bytes(6), family=AddressFamily.IPV4)
        False
        >>> is_time_exceeded(bytes([3, 0]) + bytes(6), family=AddressFamily.IPV6)
        True
        >>> is_time_exceeded(b"", family=AddressFamily.IPV4)
        False

    """

    body = strip_ip_header(datagram)
    if not body:
        return False
    expected = TIME_EXCEEDED_V6 if family is AddressFamily.IPV6 else TIME_EXCEEDED_V4
    return body[0] == expected
