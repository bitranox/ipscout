"""Neighbour-cache reads on Linux, via a netlink ``RTM_GETNEIGH`` dump.

Contents:
    list_neighbours: Every entry the kernel currently holds.
    parse_neighbour_dump: Pure decoder for one dump chunk.

Note:
    Netlink covers IPv4 and IPv6 in one dump, so this does not read
    ``/proc/net/arp`` at all: that file is IPv4-only, and using it would mean
    two mechanisms where one answers the whole question. The read is passive -
    it reports what the kernel already learned and sends nothing - and needs no
    privileges.

"""

from __future__ import annotations

import contextlib
import socket
import struct

from .models import AddressFamily, Neighbour, NeighbourState
from .netlink import (
    NLM_F_DUMP,
    NLM_F_REQUEST,
    NLMSG_DONE,
    NLMSG_ERROR,
    build_message,
    iter_attributes,
    iter_messages,
    open_socket,
)

__all__ = ["list_neighbours", "parse_neighbour_dump"]

_RTM_NEWNEIGH = 28
_RTM_GETNEIGH = 30

#: struct ndmsg: family, pad, pad, ifindex, state, flags, type.
_NDMSG = struct.Struct("=BBHiHBB")

#: Neighbour attributes this module reads.
_NDA_DST = 1
_NDA_LLADDR = 2

#: NUD_* entry states, as the kernel reports them.
_NUD_INCOMPLETE = 0x01
_NUD_REACHABLE = 0x02
_NUD_STALE = 0x04
_NUD_FAILED = 0x20
_NUD_PERMANENT = 0x80

_STATE_NAMES = {
    _NUD_INCOMPLETE: NeighbourState.INCOMPLETE,
    _NUD_REACHABLE: NeighbourState.REACHABLE,
    _NUD_STALE: NeighbourState.STALE,
    _NUD_FAILED: NeighbourState.FAILED,
    _NUD_PERMANENT: NeighbourState.PERMANENT,
}

#: A cache larger than this would be pathological; the bound stops a truncated
#: or hostile stream from looping forever.
_MAX_DUMP_CHUNKS = 256

#: An Ethernet hardware address is six bytes.
_MAC_LENGTH = 6


def format_mac(raw: bytes) -> str | None:
    """Return the canonical ``aa:bb:cc:dd:ee:ff`` form of a link address.

    Args:
        raw: The hardware address as the kernel reported it.

    Returns:
        The lowercase colon-separated form, or ``None`` when the length is not
        an Ethernet address. Loopback and tunnel interfaces report zero-length
        or oversized link addresses, and inventing a MAC for them would be
        worse than saying nothing.

    Examples:
        >>> format_mac(bytes.fromhex("aabbccddeeff"))
        'aa:bb:cc:dd:ee:ff'
        >>> format_mac(b"") is None
        True

    """

    if len(raw) != _MAC_LENGTH:
        return None
    return ":".join(f"{octet:02x}" for octet in raw)


def _state_of(state: int) -> NeighbourState:
    """Map the kernel's NUD bitmask to the reported state."""

    for bit, name in _STATE_NAMES.items():
        if state & bit:
            return name
    return NeighbourState.OTHER


def parse_neighbour_dump(data: bytes) -> tuple[list[Neighbour], bool]:
    """Decode one netlink dump chunk into neighbour entries.

    Args:
        data: Bytes as read from the netlink socket.

    Returns:
        The entries found, and whether the kernel signalled the end of the
        dump. Entries with no usable hardware address are dropped: an
        unanswered query is not a neighbour this host knows.

    Examples:
        >>> parse_neighbour_dump(b"")
        ([], False)

    """

    found: list[Neighbour] = []
    for message_type, payload in iter_messages(data):
        if message_type in (NLMSG_DONE, NLMSG_ERROR):
            return found, True
        if message_type != _RTM_NEWNEIGH or len(payload) < _NDMSG.size:
            continue

        family, _pad1, _pad2, ifindex, state, _flags, _kind = _NDMSG.unpack(payload[: _NDMSG.size])
        if state & (_NUD_INCOMPLETE | _NUD_FAILED):
            continue
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue

        ip: str | None = None
        mac: str | None = None
        for attribute, value in iter_attributes(payload, _NDMSG.size):
            if attribute == _NDA_DST:
                with contextlib.suppress(OSError, ValueError):
                    ip = socket.inet_ntop(family, value)
            elif attribute == _NDA_LLADDR:
                mac = format_mac(value)

        if ip is None or mac is None:
            continue

        interface: str | None = None
        if ifindex > 0:
            with contextlib.suppress(OSError, ValueError):
                interface = socket.if_indextoname(ifindex)

        found.append(
            Neighbour(
                ip=ip,
                mac=mac,
                interface=interface,
                state=_state_of(state),
                family=AddressFamily.IPV6 if family == socket.AF_INET6 else AddressFamily.IPV4,
            )
        )
    return found, False


def list_neighbours() -> tuple[Neighbour, ...]:
    """Return every neighbour-cache entry this host currently holds.

    Returns:
        One record per entry, both address families, in the order the kernel
        reported them.

    Examples:
        >>> entries = list_neighbours()
        >>> all(entry.mac for entry in entries)
        True

    """

    sock = open_socket()
    if sock is None:  # pragma: no cover - non-Linux, or netlink unavailable
        return ()

    found: list[Neighbour] = []
    try:
        sock.settimeout(2.0)
        # AF_UNSPEC asks for every family in one dump.
        sock.send(build_message(_RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP, _NDMSG.pack(socket.AF_UNSPEC, 0, 0, 0, 0, 0, 0)))
        for _ in range(_MAX_DUMP_CHUNKS):
            entries, done = parse_neighbour_dump(sock.recv(65535))
            found.extend(entries)
            if done:
                break
    except OSError:
        return tuple(found)
    finally:
        with contextlib.suppress(OSError):
            sock.close()
    return tuple(found)
