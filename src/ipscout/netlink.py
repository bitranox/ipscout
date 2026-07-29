"""Netlink plumbing shared by the Linux route and neighbour backends.

Contents:
    open_socket: A NETLINK_ROUTE socket, or None where there is none.
    build_message: Wrap a request body in an ``nlmsghdr``.
    iter_messages: Walk the messages in one received chunk.
    iter_attributes: Walk the ``rtattr`` list trailing a message body.
    aligned: The 4-byte rounding netlink uses throughout.

Note:
    A netlink socket is an ordinary datagram socket and these queries need no
    privileges. The walkers are pure functions over bytes, which is what lets
    the wire formats above them be tested without a kernel.

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
    "NLM_F_DUMP",
    "NLM_F_REQUEST",
    "aligned",
    "build_message",
    "iter_attributes",
    "iter_messages",
    "open_socket",
]

#: NETLINK_ROUTE: routes, addresses, neighbours and links.
NETLINK_ROUTE = 0

NLM_F_REQUEST = 0x01
#: NLM_F_ROOT | NLM_F_MATCH: ask for the whole table rather than one entry.
NLM_F_DUMP = 0x300

NLMSG_ERROR = 0x02
NLMSG_DONE = 0x03

#: struct nlmsghdr: length, type, flags, sequence, port id.
NLMSGHDR = struct.Struct("=IHHII")

#: struct rtattr: length, type.
RTATTR = struct.Struct("=HH")


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
