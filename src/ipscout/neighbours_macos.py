"""Neighbour-cache reads on macOS and the BSDs, via a ``sysctl`` route dump.

Contents:
    list_neighbours: Every entry the kernel currently holds.
    parse_neighbour_dump: Pure decoder for one dump.

Note:
    The read is passive - it reports what the kernel already learned and sends
    nothing - and needs no privileges. The decoder is separated from the
    ``sysctl`` call so the wire format can be tested on Linux, where none of
    this can execute.

"""

from __future__ import annotations

import contextlib
import ipaddress
import socket

from .bsdroute import (
    CTL_NET,
    NET_RT_FLAGS,
    PF_ROUTE,
    RT_MSGHDR,
    RTA_DST,
    RTA_GATEWAY,
    RTF_LLINFO,
    address_of,
    link_address_of,
    roundup,
    split_sockaddrs,
    sysctl,
)
from .models import AddressFamily, Neighbour, NeighbourState

__all__ = ["list_neighbours", "parse_neighbour_dump"]


def parse_neighbour_dump(data: bytes, family: AddressFamily) -> list[Neighbour]:
    """Decode one ``NET_RT_FLAGS`` dump into neighbour entries.

    Args:
        data: The bytes the sysctl returned.
        family: Which family this dump was requested for, carried onto each
            record.

    Returns:
        One record per entry that names both an address and a learned
        hardware address. Multicast and unspecified entries are dropped:
        their link address is derived from the group rather than learned from
        a host, so reporting them as neighbours would be noise.

    Examples:
        >>> parse_neighbour_dump(b"", AddressFamily.IPV4)
        []

    """

    found: list[Neighbour] = []
    position = 0
    while position + RT_MSGHDR.size <= len(data):
        message_length = int.from_bytes(data[position : position + 2], "little")
        if message_length < RT_MSGHDR.size or position + message_length > len(data):
            break

        header = RT_MSGHDR.unpack(data[position : position + RT_MSGHDR.size])
        index, _flags, addrs = header[3], header[4], header[5]
        sockaddrs = split_sockaddrs(data[position + RT_MSGHDR.size : position + message_length], addrs)

        # The destination is the neighbour's IP; the gateway slot holds the
        # sockaddr_dl carrying its hardware address.
        ip = address_of(sockaddrs[RTA_DST]) if RTA_DST in sockaddrs else None
        mac = link_address_of(sockaddrs[RTA_GATEWAY]) if RTA_GATEWAY in sockaddrs else None
        position += roundup(message_length)

        if ip is None or mac is None:
            continue
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:  # pragma: no cover - the kernel does not emit these
            continue
        if address.is_multicast or address.is_unspecified:
            continue

        interface: str | None = None
        if index:
            with contextlib.suppress(OSError, ValueError):
                interface = socket.if_indextoname(index)

        # The dump reports no per-entry state, so every entry it lists is
        # simply one the kernel holds. Claiming REACHABLE would assert a
        # freshness this interface never provides.
        found.append(Neighbour(ip=ip, mac=mac, interface=interface, state=NeighbourState.OTHER, family=family))
    return found


def list_neighbours() -> tuple[Neighbour, ...]:  # pragma: no cover - macOS only
    """Return every neighbour-cache entry this host currently holds.

    Returns:
        One record per entry, both address families. Each family is a separate
        dump here, unlike the single netlink query Linux uses.

    """

    found: list[Neighbour] = []
    for family, af in ((AddressFamily.IPV4, socket.AF_INET), (AddressFamily.IPV6, socket.AF_INET6)):
        data = sysctl([CTL_NET, PF_ROUTE, 0, af, NET_RT_FLAGS, RTF_LLINFO])
        if data:
            found.extend(parse_neighbour_dump(data, family))
    return tuple(found)
