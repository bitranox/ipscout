"""Neighbour-cache reads and writes on Windows, via ``iphlpapi.dll``.

Contents:
    list_neighbours: Every entry the stack currently holds (``GetIpNetTable2``).
    set_static_neighbour / remove_static_neighbour: Write a permanent IPv4
        entry (``CreateIpNetEntry2``) or delete one (``DeleteIpNetEntry2``).
    ipv4_neighbour_row: Pure builder of the ``MIB_IPNET_ROW2`` both take.
    raise_for_status / removed_from_status: The Win32 error code, mapped to an
        outcome.
    request_address: The packed address an active resolution asks about.

Note:
    The read is passive - it reports what the stack already learned and sends
    nothing - and needs no elevation. ``GetIpNetTable2`` covers IPv4 and IPv6
    in one call, so there is no second mechanism for the second family.
    Writing needs Administrator.

"""

from __future__ import annotations

import ctypes

from .arp import MAC_LENGTH, format_mac
from .errors import ARP_SCAN_ALTERNATIVE, IPScoutError, IPScoutPermissionError, IPScoutUnsupportedError
from .models import AddressFamily, Neighbour, NeighbourChange, NeighbourState, names_a_neighbour, require_address
from .resolve import MAX_INTERFACE_INDEX, interface_name, split_zone
from .winapi import (
    MAX_ADAPTER_ADDRESS_LENGTH,
    MIB_IPNET_ROW2,
    MIB_IPNET_TABLE2,
    NO_ERROR,
    WIN_AF_UNSPEC,
    address_text,
    iphlpapi,
    sockaddr_inet,
    sockaddr_inet_address,
    string_to_ipv4,
)

__all__ = [
    "declared_mac",
    "ipv4_neighbour_row",
    "list_neighbours",
    "raise_for_status",
    "refuse_unless_unanswered",
    "remove_static_neighbour",
    "removed_from_status",
    "request_address",
    "resolve_active",
    "set_static_neighbour",
    "state_of",
]

#: ERROR_ACCESS_DENIED: the elevation refusal, worth telling apart from a
#: neighbour that simply did not answer.
_ERROR_ACCESS_DENIED = 5

#: ERROR_NOT_FOUND: a delete found no such entry, which is an answer.
_ERROR_NOT_FOUND = 1168

#: ERROR_BAD_NET_NAME: the one status that means "asked, nobody answered".
#: Measured 2026-10-26 on a Windows test VM: SendARP gives it for an on-link address
#: nobody holds and for an off-subnet one, and ResolveIpNetEntry2 for an
#: unanswered link-local address. Every other failure (ERROR_NETWORK_UNREACHABLE
#: with no route, an invalid parameter) means the request could not be asked.
_ERROR_BAD_NET_NAME = 67


def refuse_unless_unanswered(status: int, *, call: str, ip: str) -> None:
    """Return quietly for "nobody answered"; raise for a request that could not be asked.

    Args:
        status: The failure status the call returned (not ``NO_ERROR``).
        call: The Windows function that returned it, named in the refusal.
        ip: The address that was asked about.

    Raises:
        IPScoutUnsupportedError: ``status`` is any failure other than no reply,
            so the caller is told it could not ask rather than that the
            address is free.
    """

    if status != _ERROR_BAD_NET_NAME:
        msg = f"could not ask for {ip}: {call} failed with Windows error {status}"
        raise IPScoutUnsupportedError(msg)


#: ERROR_OBJECT_ALREADY_EXISTS: a create met an entry for that address.
_ERROR_OBJECT_ALREADY_EXISTS = 5010

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


def declared_mac(raw: bytes, length: int) -> str | None:
    """Return the Ethernet address in a fixed-size buffer, read to its declared length.

    Args:
        raw: The address buffer a row or ``SendARP`` filled; larger than any
            Ethernet address (32 bytes in a row, 8 for ``SendARP``).
        length: How many of its bytes the API says are meaningful.

    Returns:
        The lowercase colon-separated form, or ``None`` when the entry holds
        no learned Ethernet address: a length other than six, or all zeros.

    Examples:
        >>> declared_mac(bytes.fromhex("aabbccddeeff") + bytes(26), 6)
        'aa:bb:cc:dd:ee:ff'
        >>> declared_mac(bytes(32), 6) is None
        True

    """

    # Reading the whole buffer would append its unused tail; arp.format_mac
    # then refuses anything not exactly six bytes long.
    return format_mac(raw[:length])


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
    if library.GetIpNetTable2(WIN_AF_UNSPEC, ctypes.byref(table)) != NO_ERROR:
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

            address = sockaddr_inet_address(row.Address)
            mac = declared_mac(bytes(row.PhysicalAddress), int(row.PhysicalAddressLength))
            if address is None or mac is None or not names_a_neighbour(address):
                continue

            found.append(
                Neighbour(
                    ip=address_text(address),
                    mac=mac,
                    interface=interface_name(int(row.InterfaceIndex)),
                    state=state,
                    family=AddressFamily.of_version(address.version),
                )
            )
        return tuple(found)
    finally:
        library.FreeMibTable(table)


def request_address(ip: str, family: AddressFamily) -> bytes:
    """Return the packed address an active resolution asks about, or refuse it.

    Args:
        ip: The bare address literal to resolve.
        family: The family it must belong to.

    Returns:
        The address in network byte order.

    Raises:
        ValueError: ``ip`` is not an address literal of ``family``, or it
            carries a zone. Refused before anything is sent, so a request that
            could not be made is never reported as "nobody answered".

    Examples:
        >>> request_address("192.0.2.1", AddressFamily.IPV4).hex()
        'c0000201'
        >>> request_address("fe80::1%7", AddressFamily.IPV6)
        Traceback (most recent call last):
        ...
        ValueError: 'fe80::1%7' carries a zone, which active resolution on Windows cannot honour: pass the bare address

    """

    # A zone is refused rather than dropped: neither SendARP nor the
    # ResolveIpNetEntry2 row is given an interface here, so a dropped zone
    # would let the request leave by another link than the one it names. The
    # public resolve_active strips the zone before it calls this backend.
    if split_zone(ip).zone is not None:
        msg = f"{ip!r} carries a zone, which active resolution on Windows cannot honour: pass the bare address"
        raise ValueError(msg)
    return require_address(ip, family).packed


def _resolve_ipv6(library: ctypes.CDLL, packed: bytes, ip: str) -> str | None:  # pragma: no cover - Windows only
    """Resolve an IPv6 neighbour through ResolveIpNetEntry2.

    Unlike SendARP this needs elevation, so a refusal here is reported as a
    permission problem naming the unprivileged alternative rather than being
    swallowed. ``packed`` is ``ip`` as :func:`request_address` returned it;
    ``ip`` is kept for the messages.
    """

    row = MIB_IPNET_ROW2()
    row.Address = sockaddr_inet(packed, AddressFamily.IPV6)

    status = library.ResolveIpNetEntry2(ctypes.byref(row), None)
    if status == _ERROR_ACCESS_DENIED:
        msg = (
            "active IPv6 resolution uses ResolveIpNetEntry2, which needs Administrator on Windows "
            f"(SendARP, used for IPv4, does not). Run elevated, or {ARP_SCAN_ALTERNATIVE}"
        )
        raise IPScoutPermissionError(msg)
    if status != NO_ERROR:
        refuse_unless_unanswered(int(status), call="ResolveIpNetEntry2", ip=ip)
        return None
    return declared_mac(bytes(row.PhysicalAddress), int(row.PhysicalAddressLength))


def resolve_active(ip: str, family: AddressFamily) -> str | None:  # pragma: no cover - Windows only
    """Actively resolve one address, sending a real ARP request.

    Args:
        ip: The address to resolve.
        family: The family of ``ip``, as the caller already decided it; it
            picks ``SendARP`` or ``ResolveIpNetEntry2``.

    Returns:
        The hardware address, or ``None`` when nothing answered.

    Raises:
        ValueError: ``ip`` is not an address literal of ``family``, or it
            carries a zone: the request could not be made, so it is never
            reported as "nobody answered".
        IPScoutPermissionError: IPv6 resolution was refused for want of
            elevation. ``ResolveIpNetEntry2`` requires it; ``SendARP`` does
            not, so IPv4 works either way.
        IPScoutUnsupportedError: ``iphlpapi.dll`` could not be loaded, or the
            call failed for any reason other than no reply (no route to the
            address, among others): the request could not be asked.

    Note:
        IPv4 goes through ``SendARP``, which needs no elevation and makes
        Windows the one platform where active resolution fits this library's
        premise unelevated. IPv6 goes through ``ResolveIpNetEntry2``, which
        does need it and says so rather than being withheld.

    """

    # Checked before the library loads, so a malformed argument is refused the
    # same way on every platform.
    packed = request_address(ip, family)
    library = iphlpapi()

    if family is AddressFamily.IPV6:
        return _resolve_ipv6(library, packed, ip)

    destination = string_to_ipv4(ip)
    buffer = (ctypes.c_uint8 * MAX_ADAPTER_ADDRESS_LENGTH)()
    length = ctypes.c_uint32(MAX_ADAPTER_ADDRESS_LENGTH)
    status = library.SendARP(destination, 0, ctypes.byref(buffer), ctypes.byref(length))
    if status != NO_ERROR:
        refuse_unless_unanswered(int(status), call="SendARP", ip=ip)
        return None
    return declared_mac(bytes(buffer), int(length.value))


# --------------------------------------------------------------------------
# Writing a static entry
# --------------------------------------------------------------------------


def ipv4_neighbour_row(ip: str, mac: bytes, interface_index: int) -> MIB_IPNET_ROW2:
    """Build the ``MIB_IPNET_ROW2`` for a permanent IPv4 neighbour entry.

    Args:
        ip: The IPv4 address the entry maps, in dotted-quad form.
        mac: The six-byte hardware address, or no bytes at all for a delete,
            which the stack keys on address and interface alone.
        interface_index: The interface the entry belongs to. The stack keys
            the table by address and interface, as ``netsh interface ipv4 add
            neighbors`` does with its interface argument.

    Returns:
        A zeroed row with the address (``AF_INET`` is 2 on Windows too), the
        interface index, the hardware address and its length, and the state
        ``NlnsPermanent``. The LUID stays zero: the index identifies the
        interface, and the API takes either.

    Raises:
        ValueError: ``ip`` is not a dotted-quad IPv4 address, ``mac`` is
            neither six bytes nor empty, or ``interface_index`` is not one the
            row's ULONG field can hold (1 to 4294967295). Checked here because
            the row would otherwise store a truncated or wrapped value without
            complaint and hand the stack an entry nobody asked for.

    Examples:
        >>> row = ipv4_neighbour_row("192.0.2.7", bytes.fromhex("020000000007"), 4)
        >>> bytes(row)[:8].hex(), int(row.State)
        ('02000000c0000207', 6)
        >>> ipv4_neighbour_row("192.0.2.7", bytes(7), 4)
        Traceback (most recent call last):
        ...
        ValueError: a neighbour entry's hardware address is 6 bytes (or none, to delete), not 7

    """

    if len(mac) not in (0, MAC_LENGTH):
        msg = f"a neighbour entry's hardware address is {MAC_LENGTH} bytes (or none, to delete), not {len(mac)}"
        raise ValueError(msg)
    if not 1 <= interface_index <= MAX_INTERFACE_INDEX:
        msg = f"interface index out of range 1-{MAX_INTERFACE_INDEX}: {interface_index}"
        raise ValueError(msg)
    try:
        packed = require_address(ip, AddressFamily.IPV4).packed
    except ValueError as exc:
        # Reworded rather than passed on: the row takes nothing but a full
        # dotted quad, and the refusal says which form that is.
        msg = f"{ip!r} is not a dotted-quad IPv4 address"
        raise ValueError(msg) from exc

    row = MIB_IPNET_ROW2()
    row.Address = sockaddr_inet(packed, AddressFamily.IPV4)
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

    if status == NO_ERROR:
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
