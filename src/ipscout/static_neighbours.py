"""Writing the neighbour cache: a static IPv4 entry, and taking it out again.

Contents:
    set_neighbour: Map an IPv4 address to a hardware address, permanently.
    remove_neighbour: Delete such an entry.
    ipv4_station_address / station_mac: Refuse what no single device can own.
    interface_index / subnet_interface_index: Decide which interface the
        entry belongs to.

What this is for:
    A device answers whatever IP the sender's neighbour cache maps to its
    hardware address, so a static entry lets this host talk to a device at an
    address the device has not got yet - the "ARP trick" print servers and
    other embedded devices are configured with. ``set_neighbour`` writes the
    mapping, the caller sends to the address (ping, TFTP), and
    ``remove_neighbour`` takes the mapping out again.

Note:
    Unlike every read in this package, a write needs privilege: root or
    ``CAP_NET_ADMIN`` on Linux, root on macOS, Administrator on Windows. A
    refusal raises :class:`~ipscout.errors.IPScoutPermissionError` naming the
    remedy. IPv4 only: IPv6 neighbour entries are refused by name.

    Each platform writes natively, nothing shells out to ``ip``, ``arp`` or
    ``netsh``: netlink ``RTM_NEWNEIGH``/``RTM_DELNEIGH`` on Linux,
    ``CreateIpNetEntry2``/``DeleteIpNetEntry2`` on Windows, and a routing
    socket ``RTM_ADD``/``RTM_DELETE`` on macOS. **The macOS path has not been
    run on real hardware**: its message encoding is pinned byte for byte by
    tests, but no CI runner is root on macOS.

"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import socket
import sys
from typing import TYPE_CHECKING

from . import neighbours_linux, neighbours_macos, neighbours_windows
from .errors import IPScoutError, IPScoutUnsupportedError
from .interfaces import local_interfaces
from .models import AddressFamily, Neighbour
from .neighbours import neighbours, normalise_mac

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .models import Interface

__all__ = ["interface_index", "ipv4_station_address", "remove_neighbour", "set_neighbour", "station_mac", "subnet_interface_index"]

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"

#: An interface given as its number: digits only, and no more than an index
#: can hold. ``str.isdigit`` would accept a superscript two (U+00B2), which ``int`` then refuses.
_INDEX_PATTERN = re.compile(r"[0-9]{1,10}")

#: The I/G bit of the first octet: set for every group address, broadcast
#: included. A neighbour entry maps an address to ONE station.
_GROUP_BIT = 0x01


def ipv4_station_address(ip: str) -> str:
    """Return ``ip`` as a canonical IPv4 address an entry can be written for.

    Args:
        ip: The address the caller wants mapped.

    Returns:
        The address in its canonical text form.

    Raises:
        ValueError: Not an address, or one that cannot name a single station
            (multicast, the limited broadcast, the unspecified address).
        IPScoutUnsupportedError: An IPv6 address; only IPv4 entries are
            written.

    Examples:
        >>> ipv4_station_address("192.0.2.7")
        '192.0.2.7'
        >>> ipv4_station_address("224.0.0.1")
        Traceback (most recent call last):
        ...
        ValueError: 224.0.0.1 does not name a single station, so it cannot have a neighbour entry

    """

    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        msg = f"{ip!r} is not an IP address"
        raise ValueError(msg) from exc
    if isinstance(address, ipaddress.IPv6Address):
        msg = f"{ip} is an IPv6 address; static neighbour entries are written for IPv4 only"
        raise IPScoutUnsupportedError(msg)
    if address.is_multicast or address.is_unspecified or address == ipaddress.IPv4Address("255.255.255.255"):
        msg = f"{ip} does not name a single station, so it cannot have a neighbour entry"
        raise ValueError(msg)
    return str(address)


def station_mac(mac: str) -> str:
    """Return ``mac`` normalised, refusing anything that is not one station's address.

    Args:
        mac: A hardware address in any form :func:`~ipscout.neighbours.normalise_mac` reads.

    Returns:
        The lowercase colon-separated form.

    Raises:
        ValueError: Not a hardware address, or the all-zero, broadcast or a
            multicast address (the I/G bit set), none of which a device owns.

    Examples:
        >>> station_mac("00-00-5E-00-53-07")
        '00:00:5e:00:53:07'
        >>> station_mac("01:00:5e:00:00:01")
        Traceback (most recent call last):
        ...
        ValueError: 01:00:5e:00:00:01 is a broadcast or multicast hardware address, which no single device owns

    """

    normalised = normalise_mac(mac)
    if normalised is None:
        msg = f"{mac!r} is not a hardware address"
        raise ValueError(msg)
    raw = bytes.fromhex(normalised.replace(":", ""))
    if not any(raw):
        msg = f"{mac} is the all-zero hardware address, which names no device"
        raise ValueError(msg)
    if raw[0] & _GROUP_BIT:
        msg = f"{mac} is a broadcast or multicast hardware address, which no single device owns"
        raise ValueError(msg)
    return normalised


def interface_index(name: str, interfaces: Sequence[Interface]) -> int:
    """Return the index of an interface named in any spelling this host accepts.

    Args:
        name: The interface's index as digits, or its name.
        interfaces: This host's interfaces, as ``local_interfaces()`` reports
            them.

    Returns:
        The interface index. Windows has two disjoint interface namespaces -
        the friendly name ``local_interfaces()`` reports and the one
        ``if_nametoindex`` and ``neighbours()`` speak - so both are tried,
        after a bare number, which is portable everywhere.

    Raises:
        ValueError: No interface on this host goes by that name or number.

    Examples:
        >>> from ipscout.models import Interface
        >>> interface_index("Ethernet 4", [Interface(name="Ethernet 4", index=7)])
        7

    """

    if _INDEX_PATTERN.fullmatch(name):
        try:
            socket.if_indextoname(int(name))
        except (OSError, OverflowError, ValueError) as exc:
            msg = f"no interface with index {name} on this host"
            raise ValueError(msg) from exc
        return int(name)
    for candidate in interfaces:
        if candidate.name == name and candidate.index:
            return candidate.index
    try:
        return socket.if_nametoindex(name)
    except OSError as exc:
        msg = f"no interface named {name!r} on this host"
        raise ValueError(msg) from exc


def subnet_interface_index(ip: str, interfaces: Sequence[Interface]) -> int:
    """Return the index of the one interface whose IPv4 subnet holds ``ip``.

    Args:
        ip: A canonical IPv4 address.
        interfaces: This host's interfaces, as ``local_interfaces()`` reports
            them.

    Returns:
        The index of the interface. Only interfaces with an index and a
        hardware address count: loopback and tunnels have no link layer, so a
        neighbour entry on them would map to nothing.

    Raises:
        IPScoutUnsupportedError: No interface's subnet holds ``ip``, or more
            than one does. Either way the caller has to say which link they
            mean, and guessing would write the entry onto the wrong one.

    Examples:
        >>> from ipscout.models import Interface, InterfaceAddress
        >>> lan = Interface(name="eth0", index=2, mac="00:00:5e:00:53:01",
        ...                 ipv4=(InterfaceAddress(address="192.0.2.1", prefix_len=24),))
        >>> subnet_interface_index("192.0.2.7", [lan])
        2

    """

    address = ipaddress.IPv4Address(ip)
    matches = [
        (candidate.name, index)
        for candidate in interfaces
        if (index := candidate.index)
        and candidate.mac
        and any(address in ipaddress.ip_network(f"{entry.address}/{entry.prefix_len}", strict=False) for entry in candidate.ipv4)
    ]
    if not matches:
        msg = f"no interface on this host has a subnet holding {ip}; name one with interface= (--interface on the command line)"
        raise IPScoutUnsupportedError(msg)
    if len(matches) > 1:
        names = ", ".join(name for name, _ in matches)
        msg = f"{ip} lies in the subnet of several interfaces ({names}); name one with interface= (--interface on the command line)"
        raise IPScoutUnsupportedError(msg)
    return matches[0][1]


def _index_of(name: str | None) -> int | None:
    """Return the index of an interface name as the cache reports it, if known."""

    if name is None:
        return None
    with contextlib.suppress(OSError):
        return socket.if_nametoindex(name)
    return None


def _confirmed(ip: str, mac: str, index: int, entries: Sequence[Neighbour]) -> Neighbour | None:
    """Return the cache entry proving ``ip -> mac`` was written on ``index``."""

    return next((entry for entry in entries if entry.ip == ip and entry.mac == mac and _index_of(entry.interface) == index), None)


def _write(ip: str, mac: bytes, index: int) -> None:
    """Hand the entry to this platform's backend."""

    if IS_WINDOWS:  # pragma: no cover - exercised on Windows only
        neighbours_windows.set_static_neighbour(ip, mac, index)
    elif IS_MACOS:  # pragma: no cover - exercised on macOS only
        neighbours_macos.set_static_neighbour(ip, mac, index)
    else:
        neighbours_linux.set_static_neighbour(ip, mac, index)


def _delete(ip: str, index: int) -> bool:
    """Ask this platform's backend to delete the entry, and whether it did."""

    if IS_WINDOWS:  # pragma: no cover - exercised on Windows only
        return neighbours_windows.remove_static_neighbour(ip, index)
    if IS_MACOS:  # pragma: no cover - exercised on macOS only
        return neighbours_macos.remove_static_neighbour(ip, index)
    return neighbours_linux.remove_static_neighbour(ip, index)


def set_neighbour(ip: str, mac: str, *, interface: str | None = None) -> Neighbour:
    """Add or replace a permanent (static) IPv4 neighbour entry.

    Args:
        ip: The IPv4 address to map.
        mac: The hardware address it maps to, in any common written form.
        interface: The interface the entry belongs to: its index as digits
            (portable everywhere), or its name - on Windows either the
            friendly name ``local_interfaces()`` reports or the one
            ``neighbours()`` reports. ``None`` picks the one interface whose
            IPv4 subnet holds ``ip``.

    Returns:
        The entry as read back from the neighbour cache, which is the proof
        the kernel holds it - not merely that the call returned.

    Raises:
        ValueError: ``ip`` or ``mac`` is malformed, or cannot name a single
            station (multicast, broadcast, unspecified, all-zero), or no
            interface goes by ``interface``.
        IPScoutUnsupportedError: ``ip`` is IPv6, or ``interface`` was not
            given and no single interface's subnet holds ``ip``.
        IPScoutPermissionError: The process may not change the neighbour
            table. The message names the remedy: root or ``CAP_NET_ADMIN`` on
            Linux, root on macOS, Administrator on Windows.
        IPScoutError: The kernel refused for another reason, or accepted the
            entry and then did not list it.

    Note:
        An existing entry for the address on that interface, learned or
        static, is replaced. Remove the entry with :func:`remove_neighbour`
        when done: a static entry outlives this process and overrides what the
        network would answer, until reboot.

    Examples:
        Typical use is the pair, with the removal in a ``finally`` (not run
        here: it needs privilege and changes this host's neighbour table)::

            entry = set_neighbour("192.0.2.7", "00:00:5e:00:53:07", interface="eth0")
            try:
                ...  # talk to 192.0.2.7; the device owning that MAC answers
            finally:
                remove_neighbour("192.0.2.7", interface="eth0")

        An address no single device can own is refused before anything is
        written:

        >>> set_neighbour("192.0.2.7", "ff:ff:ff:ff:ff:ff")
        Traceback (most recent call last):
        ...
        ValueError: ff:ff:ff:ff:ff:ff is a broadcast or multicast hardware address, which no single device owns

    """

    target = ipv4_station_address(ip)
    station = station_mac(mac)
    interfaces = local_interfaces()
    index = interface_index(interface, interfaces) if interface is not None else subnet_interface_index(target, interfaces)

    _write(target, bytes.fromhex(station.replace(":", "")), index)

    entry = _confirmed(target, station, index, neighbours(family=AddressFamily.IPV4))
    if entry is None:
        msg = f"the kernel accepted {target} -> {station} on interface index {index}, but the neighbour cache does not list it"
        raise IPScoutError(msg)
    return entry


def remove_neighbour(ip: str, *, interface: str | None = None) -> bool:
    """Delete an IPv4 neighbour entry, static or learned.

    Args:
        ip: The IPv4 address whose entry goes.
        interface: The interface to delete it from, spelled as for
            :func:`set_neighbour`. ``None`` deletes the entry for ``ip`` on
            every interface the neighbour cache lists it on.

    Returns:
        ``True`` when an entry was removed, ``False`` when there was none.

    Raises:
        ValueError: ``ip`` is malformed, or no interface goes by ``interface``.
        IPScoutUnsupportedError: ``ip`` is IPv6.
        IPScoutPermissionError: The process may not change the neighbour
            table; the message names the remedy.
        IPScoutError: The kernel refused for another reason.

    Note:
        With ``interface=None`` the cache is read first, which needs no
        privilege, so an address it does not list answers ``False`` without
        asking the kernel to delete anything. Naming an interface always asks,
        and so needs the privilege even when there turns out to be nothing to
        remove.

    Examples:
        >>> remove_neighbour("192.0.2.254")
        False

    """

    target = ipv4_station_address(ip)
    if interface is not None:
        return _delete(target, interface_index(interface, local_interfaces()))

    listed = (_index_of(entry.interface) for entry in neighbours(family=AddressFamily.IPV4) if entry.ip == target)
    removed = False
    for index in dict.fromkeys(item for item in listed if item is not None):
        removed = _delete(target, index) or removed
    return removed
