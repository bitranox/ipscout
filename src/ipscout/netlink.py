"""Netlink plumbing shared by the Linux route and neighbour backends.

Contents:
    open_socket: A NETLINK_ROUTE socket, or None where there is none.
    build_message: Wrap a request body in an ``nlmsghdr``.
    iter_messages: Walk the messages in one received chunk.
    iter_attributes: Walk the ``rtattr`` list trailing a message body.
    build_attribute: Encode one ``rtattr``, padded for the next one.
    parse_ack: Read the kernel's verdict on a request out of its reply.
    aligned: The 4-byte rounding netlink uses throughout.

Note:
    A netlink socket is an ordinary datagram socket and the queries need no
    privileges; a request that CHANGES kernel state (a static neighbour entry)
    needs ``CAP_NET_ADMIN``, and the kernel answers it with an acknowledgement
    carrying the errno. The walkers and encoders are pure functions over bytes,
    which is what lets the wire formats above them be tested without a kernel.

"""

from __future__ import annotations

import socket
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__ = [
    "NLMSG_DONE",
    "NLMSG_ERROR",
    "NLM_F_ACK",
    "NLM_F_CREATE",
    "NLM_F_DUMP",
    "NLM_F_REPLACE",
    "NLM_F_REQUEST",
    "aligned",
    "build_attribute",
    "build_message",
    "iter_attributes",
    "iter_messages",
    "open_socket",
    "parse_ack",
]

#: NETLINK_ROUTE: routes, addresses, neighbours and links.
NETLINK_ROUTE = 0

NLM_F_REQUEST = 0x01
#: Ask for an acknowledgement even on success. Without it a request that
#: worked is answered with silence, which cannot be told from a lost reply.
NLM_F_ACK = 0x04
#: NLM_F_ROOT | NLM_F_MATCH: ask for the whole table rather than one entry.
NLM_F_DUMP = 0x300
#: Modifiers of a NEW request: replace an existing object, create a missing one.
NLM_F_REPLACE = 0x100
NLM_F_CREATE = 0x400

NLMSG_ERROR = 0x02
NLMSG_DONE = 0x03

#: struct nlmsghdr: length, type, flags, sequence, port id.
NLMSGHDR = struct.Struct("=IHHII")

#: struct rtattr: length, type.
RTATTR = struct.Struct("=HH")

#: struct nlmsgerr starts with a signed errno: zero acknowledges success, a
#: negative value is the refusal.
NLMSGERR_CODE = struct.Struct("=i")


def aligned(length: int) -> int:
    """Return a length rounded up to netlink's 4-byte alignment."""

    return (length + 3) & ~3


def open_socket() -> socket.socket | None:
    """Return a NETLINK_ROUTE socket, or None where there is none to open.

    ``AF_NETLINK`` is Linux-only, so it is looked up by name rather than
    accessed as an attribute: a direct ``socket.AF_NETLINK`` fails type
    checking on the macOS and Windows runs even though it is guarded at
    runtime, and silencing that per platform would hide real errors with it.
    """

    af_netlink = getattr(socket, "AF_NETLINK", None)
    if not isinstance(af_netlink, int):  # pragma: no cover - non-Linux
        return None
    try:
        return socket.socket(af_netlink, socket.SOCK_RAW, NETLINK_ROUTE)
    except OSError:  # pragma: no cover - Linux without netlink
        return None


def build_message(message_type: int, flags: int, body: bytes, sequence: int = 1) -> bytes:
    """Wrap a request body in an ``nlmsghdr``.

    Args:
        message_type: The ``RTM_*`` request.
        flags: ``NLM_F_*`` bits.
        body: The type-specific request structure.
        sequence: Sequence number echoed back on the reply.

    Returns:
        The complete message, ready to send.

    Examples:
        >>> message = build_message(26, NLM_F_REQUEST, b"\\x00" * 12)
        >>> len(message) == NLMSGHDR.size + 12
        True

    """

    return NLMSGHDR.pack(NLMSGHDR.size + len(body), message_type, flags, sequence, 0) + body


def iter_messages(data: bytes) -> Iterator[tuple[int, bytes]]:
    """Walk the netlink messages in one received chunk.

    Args:
        data: Bytes as read from the socket. A dump arrives as several
            messages packed into one datagram.

    Yields:
        ``(message_type, payload)`` for each well-formed message. Stops at the
        first malformed header rather than guessing where the next one begins.

    Examples:
        >>> chunk = build_message(24, 0, b"body-padded!")
        >>> [(kind, len(payload)) for kind, payload in iter_messages(chunk)]
        [(24, 12)]

    """

    position = 0
    while position + NLMSGHDR.size <= len(data):
        length, message_type, _flags, _sequence, _pid = NLMSGHDR.unpack(data[position : position + NLMSGHDR.size])
        if length < NLMSGHDR.size or position + length > len(data):
            return
        yield message_type, data[position + NLMSGHDR.size : position + length]
        position += aligned(length)


def iter_attributes(payload: bytes, offset: int) -> Iterator[tuple[int, bytes]]:
    """Walk the ``rtattr`` list that follows a message's fixed header.

    Args:
        payload: One message body.
        offset: Size of the fixed structure the attributes follow.

    Yields:
        ``(attribute_type, value)`` for each attribute. A length that would
        run past the end ends the walk, so a truncated or hostile message
        cannot read beyond the buffer.

    Examples:
        >>> body = b"\\x00" * 4 + RTATTR.pack(RTATTR.size + 4, 1) + b"abcd"
        >>> list(iter_attributes(body, 4))
        [(1, b'abcd')]

    """

    position = offset
    while position + RTATTR.size <= len(payload):
        length, attribute = RTATTR.unpack(payload[position : position + RTATTR.size])
        if length < RTATTR.size or position + length > len(payload):
            return
        yield attribute, payload[position + RTATTR.size : position + length]
        position += aligned(length)


def build_attribute(attribute_type: int, value: bytes) -> bytes:
    """Encode one ``rtattr`` and pad it so the next one starts aligned.

    Args:
        attribute_type: The attribute number (``NDA_*``, ``RTA_*``).
        value: The attribute payload.

    Returns:
        The header, the value and the zero padding up to 4 bytes. The length
        field counts header and value only, as the kernel's ``RTA_LENGTH``
        does; the padding is implied by the alignment rule.

    Examples:
        >>> build_attribute(2, bytes.fromhex("020000000001")).hex()
        '0a0002000200000000010000'

    """

    length = RTATTR.size + len(value)
    return RTATTR.pack(length, attribute_type) + value + bytes(aligned(length) - length)


def parse_ack(data: bytes) -> int | None:
    """Return the errno the kernel answered a request with.

    Args:
        data: Bytes as read from the socket after sending a request that asked
            for ``NLM_F_ACK``.

    Returns:
        ``0`` when the kernel acknowledged success, the positive errno when it
        refused, or ``None`` when the chunk carries no acknowledgement at all.

    Examples:
        >>> parse_ack(build_message(NLMSG_ERROR, 0, NLMSGERR_CODE.pack(0)))
        0
        >>> parse_ack(build_message(NLMSG_ERROR, 0, NLMSGERR_CODE.pack(-1)))
        1
        >>> parse_ack(b"") is None
        True

    """

    for message_type, payload in iter_messages(data):
        if message_type == NLMSG_ERROR and len(payload) >= NLMSGERR_CODE.size:
            (code,) = NLMSGERR_CODE.unpack(payload[: NLMSGERR_CODE.size])
            return -int(code)
    return None
