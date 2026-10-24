"""Neighbour-cache reads and writes on Windows, via ``iphlpapi.dll``.

Contents:
    list_neighbours: Every entry the stack currently holds (``GetIpNetTable2``).
    set_static_neighbour / remove_static_neighbour: Write a permanent IPv4
        entry (``CreateIpNetEntry2``) or delete one (``DeleteIpNetEntry2``).
    ipv4_neighbour_row: Pure builder of the ``MIB_IPNET_ROW2`` both take.
    raise_for_status / removed_from_status: The Win32 error code, mapped to an
        outcome.

Note:
    The read is passive - it reports what the stack already learned and sends
    nothing - and needs no elevation. ``GetIpNetTable2`` covers IPv4 and IPv6
    in one call, so there is no second mechanism for the second family.
    Writing needs Administrator.

"""

from __future__ import annotations

import contextlib
import ctypes
import ipaddress
import socket

from .errors import IPScoutError, IPScoutPermissionError, IPScoutUnsupportedError
from .models import AddressFamily, Neighbour, NeighbourChange, NeighbourState
from .winapi import (
    MIB_IPNET_ROW2,
    MIB_IPNET_TABLE2,
    WIN_AF_UNSPEC,
    family_from_win,
    iphlpapi,
    sockaddr_inet_to_string,
    win_family,
)

__all__ = [
    "format_mac",
    "ipv4_neighbour_row",
    "list_neighbours",
    "raise_for_status",
    "remove_static_neighbour",
    "removed_from_status",
    "resolve_active",
    "set_static_neighbour",
    "state_of",
]

#: NO_ERROR, the only success value these calls return.
_NO_ERROR = 0

#: ERROR_ACCESS_DENIED: the elevation refusal, worth telling apart from a
#: neighbour that simply did not answer.
_ERROR_ACCESS_DENIED = 5

#: ERROR_NOT_FOUND: a delete found no such entry, which is an answer.
_ERROR_NOT_FOUND = 1168

#: ERROR_OBJECT_ALREADY_EXISTS: a create met an entry for that address.
_ERROR_OBJECT_ALREADY_EXISTS = 5010

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
        library = iphlpapi()
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
            family = family_from_win(int(row.Address.si_family))
            mac = format_mac(bytes(row.PhysicalAddress), int(row.PhysicalAddressLength))
            if ip is None or family is None or mac is None:
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
                    family=family,
                )
            )
        return tuple(found)
    finally:
        library.FreeMibTable(table)


def _resolve_ipv6(library: ctypes.CDLL, ip: str) -> str | None:  # pragma: no cover - Windows only
    """Resolve an IPv6 neighbour through ResolveIpNetEntry2.

    Unlike SendARP this needs elevation, so a refusal here is reported as a
    permission problem naming the unprivileged alternative rather than being
    swallowed.
    """

    row = MIB_IPNET_ROW2()
    row.Address.si_family = win_family(AddressFamily.IPV6)
    try:
        row.Address.Ipv6.sin6_addr[:] = socket.inet_pton(AddressFamily.IPV6.socket_family, ip)
    except OSError:
        return None

    status = library.ResolveIpNetEntry2(ctypes.byref(row), None)
    if status == _ERROR_ACCESS_DENIED:
        msg = (
            "active IPv6 resolution uses ResolveIpNetEntry2, which needs Administrator on Windows "
            "(SendARP, used for IPv4, does not). Run elevated, or use arp_scan(), which resolves "
            "the same addresses unprivileged"
        )
        raise IPScoutPermissionError(msg)
    if status != _NO_ERROR:
        return None
    return format_mac(bytes(row.PhysicalAddress), int(row.PhysicalAddressLength))


def resolve_active(ip: str) -> str | None:  # pragma: no cover - Windows only
    """Actively resolve one address, sending a real ARP request.

    Args:
        ip: The IPv4 address to resolve.

    Returns:
        The hardware address, or ``None`` when nothing answered.

    Raises:
        IPScoutPermissionError: IPv6 resolution was refused for want of
            elevation. ``ResolveIpNetEntry2`` requires it; ``SendARP`` does
            not, so IPv4 works either way.

    Note:
        IPv4 goes through ``SendARP``, which needs no elevation and makes
        Windows the one platform where active resolution fits this library's
        premise unelevated. IPv6 goes through ``ResolveIpNetEntry2``, which
        does need it and says so rather than being withheld.

    """

    try:
        library = iphlpapi()
    except IPScoutUnsupportedError:
        return None

    if ":" in ip:
        return _resolve_ipv6(library, ip)

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


# --------------------------------------------------------------------------
# Writing a static entry
# --------------------------------------------------------------------------


def ipv4_neighbour_row(ip: str, mac: bytes, interface_index: int) -> MIB_IPNET_ROW2:
    """Build the ``MIB_IPNET_ROW2`` for a permanent IPv4 neighbour entry.

    Args:
        ip: The IPv4 address the entry maps.
        mac: The six-byte hardware address.
        interface_index: The interface the entry belongs to. The stack keys
            the table by address and interface, as ``netsh interface ipv4 add
            neighbors`` does with its interface argument.

    Returns:
        A zeroed row with the address (``AF_INET`` is 2 on Windows too), the
        interface index, the hardware address and its length, and the state
        ``NlnsPermanent``. The LUID stays zero: the index identifies the
        interface, and the API takes either.

    Examples:
        >>> row = ipv4_neighbour_row("192.0.2.7", bytes.fromhex("020000000007"), 4)
        >>> bytes(row)[:8].hex(), int(row.State)
        ('02000000c0000207', 6)

    """

    row = MIB_IPNET_ROW2()
    row.Address.Ipv4.sin_family = win_family(AddressFamily.IPV4)
    row.Address.Ipv4.sin_addr[:] = socket.inet_aton(ip)
    row.InterfaceIndex = interface_index
    row.PhysicalAddress[: len(mac)] = mac
    row.PhysicalAddressLength = len(mac)
    row.State = _NL_NUD_PERMANENT
    return row


def raise_for_status(status: int, *, action: NeighbourChange) -> None:
    """Raise unless an ``*IpNetEntry2`` call succeeded.

    Args:
        status: The Win32 error code the call returned.
        action: What was asked, named in the message.

    Raises:
        IPScoutPermissionError: ``ERROR_ACCESS_DENIED``: changing the neighbour
            table needs Administrator.
        IPScoutError: Any other failure.

    Examples:
        >>> raise_for_status(0, action=NeighbourChange.ADD)
        >>> raise_for_status(5, action=NeighbourChange.ADD)
        Traceback (most recent call last):
        ...
        ipscout.errors.IPScoutPermissionError: ...Administrator...

    """

    if status == _NO_ERROR:
        return
    if status == _ERROR_ACCESS_DENIED:
        msg = "changing the neighbour table needs Administrator on Windows (ERROR_ACCESS_DENIED). Run elevated"
        raise IPScoutPermissionError(msg)
    msg = f"Windows refused to {action.value} the neighbour entry: Win32 error {status}"
    raise IPScoutError(msg)


def removed_from_status(status: int) -> bool:
    """Return whether a delete removed an entry, raising on a real failure.

    Args:
        status: The Win32 error code ``DeleteIpNetEntry2`` returned.

    Returns:
        ``True`` when the entry went, ``False`` when there was none
        (``ERROR_NOT_FOUND``).

    Examples:
        >>> removed_from_status(0), removed_from_status(1168)
        (True, False)

    """

    if status == _ERROR_NOT_FOUND:
        return False
    raise_for_status(status, action=NeighbourChange.REMOVE)
    return True


def set_static_neighbour(ip: str, mac: bytes, ifindex: int) -> None:  # pragma: no cover - Windows only
    """Add or replace a permanent IPv4 neighbour entry.

    Args:
        ip: The IPv4 address the entry maps.
        mac: The six-byte hardware address.
        ifindex: The interface the entry belongs to.

    Raises:
        IPScoutPermissionError: The process is not elevated.
        IPScoutError: The stack refused for another reason.

    Note:
        ``CreateIpNetEntry2`` refuses an address that already has an entry on
        that interface, so on ``ERROR_OBJECT_ALREADY_EXISTS`` the existing one
        is deleted and the create is repeated once.

    """

    library = iphlpapi()
    status = library.CreateIpNetEntry2(ctypes.byref(ipv4_neighbour_row(ip, mac, ifindex)))
    if status == _ERROR_OBJECT_ALREADY_EXISTS:
        removed_from_status(library.DeleteIpNetEntry2(ctypes.byref(ipv4_neighbour_row(ip, mac, ifindex))))
        status = library.CreateIpNetEntry2(ctypes.byref(ipv4_neighbour_row(ip, mac, ifindex)))
    raise_for_status(int(status), action=NeighbourChange.ADD)


def remove_static_neighbour(ip: str, ifindex: int) -> bool:  # pragma: no cover - Windows only
    """Delete one IPv4 neighbour entry.

    Args:
        ip: The address whose entry goes.
        ifindex: The interface it is on.

    Returns:
        Whether an entry was removed.

    Raises:
        IPScoutPermissionError: The process is not elevated.
        IPScoutError: The stack refused for another reason.

    """

    row = ipv4_neighbour_row(ip, bytes(0), ifindex)
    return removed_from_status(int(iphlpapi().DeleteIpNetEntry2(ctypes.byref(row))))
