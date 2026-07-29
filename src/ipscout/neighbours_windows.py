"""Neighbour-cache reads on Windows, via ``GetIpNetTable2`` in ``iphlpapi.dll``.

Contents:
    list_neighbours: Every entry the stack currently holds.

Note:
    The read is passive - it reports what the stack already learned and sends
    nothing - and needs no elevation. ``GetIpNetTable2`` covers IPv4 and IPv6
    in one call, so there is no second mechanism for the second family.

"""

from __future__ import annotations

import contextlib
import ctypes
import ipaddress
import socket
from typing import Any

from .errors import IPScoutUnsupportedError
from .models import AddressFamily, Neighbour, NeighbourState
from .winapi import (
    MIB_IPNET_ROW2,
    MIB_IPNET_TABLE2,
    WIN_AF_INET6,
    WIN_AF_UNSPEC,
    iphlpapi,
    sockaddr_inet_to_string,
)

__all__ = ["format_mac", "list_neighbours", "resolve_active", "state_of"]

#: NO_ERROR, the only success value GetIpNetTable2 returns.
_NO_ERROR = 0

#: An Ethernet hardware address is six bytes; the row's buffer is larger.
_MAC_LENGTH = 6

#: NL_NEIGHBOR_STATE, in declaration order.
_NL_NUD_UNREACHABLE = 0
_NL_NUD_INCOMPLETE = 1
_NL_NUD_PROBE = 2
_NL_NUD_DELAY = 3
_NL_NUD_STALE = 4
_NL_NUD_REACHABLE = 5
_NL_NUD_PERMANENT = 6

_STATES = {
    _NL_NUD_UNREACHABLE: NeighbourState.FAILED,
    _NL_NUD_INCOMPLETE: NeighbourState.INCOMPLETE,
    _NL_NUD_PROBE: NeighbourState.OTHER,
    _NL_NUD_DELAY: NeighbourState.OTHER,
    _NL_NUD_STALE: NeighbourState.STALE,
    _NL_NUD_REACHABLE: NeighbourState.REACHABLE,
    _NL_NUD_PERMANENT: NeighbourState.PERMANENT,
}

#: States carrying no usable hardware address.
_UNUSABLE = frozenset({NeighbourState.FAILED, NeighbourState.INCOMPLETE})


def state_of(value: int) -> NeighbourState:
    """Map a ``NL_NEIGHBOR_STATE`` to the reported state.

    Args:
        value: The state as the stack reported it.

    Returns:
        The public state. Windows numbers these differently from Linux's NUD
        bitmask - they are an enumeration here, not flags - so the mapping is
        explicit rather than shared.

    Examples:
        >>> state_of(5) is NeighbourState.REACHABLE
        True
        >>> state_of(99) is NeighbourState.OTHER
        True

    """

    return _STATES.get(value, NeighbourState.OTHER)


def format_mac(raw: bytes, length: int) -> str | None:
    """Return the canonical form of a link address from a row's buffer.

    Args:
        raw: The fixed-size address buffer the row carries.
        length: How many of its bytes are meaningful.

    Returns:
        The lowercase colon-separated form, or ``None`` when the entry holds
        no learned Ethernet address.

    Examples:
        >>> format_mac(bytes.fromhex("aabbccddeeff") + bytes(26), 6)
        'aa:bb:cc:dd:ee:ff'
        >>> format_mac(bytes(32), 6) is None
        True

    """

    if length != _MAC_LENGTH:
        return None
    address = raw[:_MAC_LENGTH]
    if not any(address):
        return None
    return ":".join(f"{octet:02x}" for octet in address)


def list_neighbours() -> tuple[Neighbour, ...]:  # pragma: no cover - Windows only
    """Return every neighbour-cache entry this host currently holds.

    Returns:
        One record per entry, both address families. Multicast and unspecified
        rows are dropped: their address is derived rather than learned, so
        reporting them as neighbours would be noise in any scan.

    """

    try:
        library: Any = iphlpapi()
    except IPScoutUnsupportedError:
        return ()

    table = ctypes.POINTER(MIB_IPNET_TABLE2)()
    if library.GetIpNetTable2(WIN_AF_UNSPEC, ctypes.byref(table)) != _NO_ERROR:
        return ()

    found: list[Neighbour] = []
    try:
        count = int(table.contents.NumEntries)
        rows = ctypes.cast(table.contents.Table, ctypes.POINTER(MIB_IPNET_ROW2))
        for index in range(count):
            row: MIB_IPNET_ROW2 = rows[index]
            state = state_of(int(row.State))
            if state in _UNUSABLE:
                continue

            ip = sockaddr_inet_to_string(row.Address)
            mac = format_mac(bytes(row.PhysicalAddress), int(row.PhysicalAddressLength))
            if ip is None or mac is None:
                continue
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if address.is_multicast or address.is_unspecified:
                continue

            interface: str | None = None
            if int(row.InterfaceIndex):
                with contextlib.suppress(OSError, ValueError):
                    interface = socket.if_indextoname(int(row.InterfaceIndex))

            found.append(
                Neighbour(
                    ip=ip,
                    mac=mac,
                    interface=interface,
                    state=state,
                    family=AddressFamily.IPV6 if int(row.Address.si_family) == WIN_AF_INET6 else AddressFamily.IPV4,
                )
            )
        return tuple(found)
    finally:
        library.FreeMibTable(table)


def resolve_active(ip: str) -> str | None:  # pragma: no cover - Windows only
    """Actively resolve one address, sending a real ARP request.

    Args:
        ip: The IPv4 address to resolve.

    Returns:
        The hardware address, or ``None`` when nothing answered.

    Raises:
        IPScoutUnsupportedError: The address is IPv6. Windows resolves those
            through ResolveIpNetEntry2, which does require elevation, so it is
            not offered here rather than being offered and always failing.

    Note:
        ``SendARP`` needs no elevation, which makes Windows the one platform
        where active resolution fits this library's premise. It resolves a host
        that has never been contacted, without a ping first.

    """

    if ":" in ip:
        msg = "active IPv6 resolution needs elevation on Windows; sweep with arp_scan() instead"
        raise IPScoutUnsupportedError(msg)

    try:
        library: Any = iphlpapi()
    except IPScoutUnsupportedError:
        return None

    try:
        packed = socket.inet_aton(ip)
    except OSError:
        return None

    buffer = (ctypes.c_uint8 * 8)()
    length = ctypes.c_uint32(8)
    destination = ctypes.c_uint32.from_buffer_copy(packed).value
    if library.SendARP(destination, 0, ctypes.byref(buffer), ctypes.byref(length)) != _NO_ERROR:
        return None
    return format_mac(bytes(buffer), int(length.value))
