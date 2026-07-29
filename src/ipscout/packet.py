"""Pure ICMP echo encoding and decoding. No sockets, no I/O, no clock.

Everything here is a total function over bytes, which is what makes the
protocol layer testable without a network, without privileges and without a
particular operating system.

Contents:
    EchoPayload: The token-bearing payload carried in every request we send.
    build_echo_request: Assemble a complete ICMP or ICMPv6 echo request.
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
from dataclasses import dataclass

__all__ = [
    "ECHO_REPLY_V4",
    "ECHO_REPLY_V6",
    "ECHO_REQUEST_V4",
    "ECHO_REQUEST_V6",
    "HEADER_SIZE",
    "MAGIC",
    "TOKEN_SIZE",
    "EchoPayload",
    "ParsedReply",
    "build_echo_request",
    "checksum",
    "is_echo_reply",
    "parse_echo_reply",
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


@dataclass(frozen=True)
class EchoPayload:
    """The identifying content carried inside an echo request.

    Attributes:
        token: Random bytes unique to one request, echoed back by the peer.
        filler: Padding that brings the payload up to the requested size.

    """

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


@dataclass(frozen=True)
class ParsedReply:
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


def build_echo_request(
    *,
    sequence: int,
    payload_size: int = 56,
    is_ipv6: bool = False,
    identifier: int = 0,
    token: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Build one complete ICMP echo request.

    Args:
        sequence: Sequence number for this request. This, together with the
            token, is what identifies the reply.
        payload_size: Total payload length in bytes. Raised to the minimum
            needed to hold magic plus token when a smaller value is asked for.
        is_ipv6: Build an ICMPv6 request rather than an ICMPv4 one.
        identifier: Value for the identifier field. Cosmetic on unprivileged
            sockets, where the kernel overwrites it.
        token: Explicit token, for tests that need determinism. A fresh random
            token is generated when this is ``None``.

    Returns:
        A ``(datagram, token)`` pair. The token is returned so the caller can
        register it before the reply can possibly arrive.

    Examples:
        >>> datagram, token = build_echo_request(sequence=1, token=b"abcdefgh")
        >>> datagram[0], len(token)
        (8, 8)

        The checksum is left to the kernel for IPv6:

        >>> v6, _ = build_echo_request(sequence=1, is_ipv6=True, token=b"abcdefgh")
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

    icmp_type = ECHO_REQUEST_V6 if is_ipv6 else ECHO_REQUEST_V4
    # IPv6 checksums are computed by the kernel over a pseudo-header that
    # includes the source address, which is not known here; send zero.
    if is_ipv6:
        return _HEADER_STRUCT.pack(icmp_type, 0, 0, identifier, sequence) + payload, actual_token

    blank = _HEADER_STRUCT.pack(icmp_type, 0, 0, identifier, sequence) + payload
    return _HEADER_STRUCT.pack(icmp_type, 0, checksum(blank), identifier, sequence) + payload, actual_token


def parse_echo_reply(datagram: bytes) -> ParsedReply | None:
    """Decode a received datagram into its identifying fields.

    Args:
        datagram: Bytes as received. On an unprivileged datagram socket this
            starts at the ICMP header, with no IP header prepended.

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

    if len(datagram) < HEADER_SIZE:
        return None
    icmp_type, code, _sum, identifier, sequence = _HEADER_STRUCT.unpack(datagram[:HEADER_SIZE])
    return ParsedReply(
        icmp_type=icmp_type,
        code=code,
        identifier=identifier,
        sequence=sequence,
        payload=EchoPayload.from_bytes(datagram[HEADER_SIZE:]),
    )


def is_echo_reply(parsed: ParsedReply, *, is_ipv6: bool) -> bool:
    """Return whether a parsed datagram is an echo reply for this family.

    Args:
        parsed: A decoded datagram.
        is_ipv6: Which family's type numbers to expect.

    Returns:
        True when the type byte marks an echo reply.

    Examples:
        >>> datagram, _ = build_echo_request(sequence=1, token=b"abcdefgh")
        >>> request = parse_echo_reply(datagram)
        >>> is_echo_reply(request, is_ipv6=False)   # an echo REQUEST, not a reply
        False

    """

    expected = ECHO_REPLY_V6 if is_ipv6 else ECHO_REPLY_V4
    return parsed.icmp_type == expected
