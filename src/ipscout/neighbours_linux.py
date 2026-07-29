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
import ipaddress
import socket
import struct
import time

from .arp import (
    ETH_P_ARP,
    build_arp_request,
    build_neighbour_solicitation,
    parse_arp_reply,
    parse_neighbour_advertisement,
    solicited_node_multicast,
)
from .errors import IPScoutPermissionError, IPScoutUnsupportedError
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

__all__ = ["format_mac", "list_neighbours", "parse_neighbour_dump", "resolve_active_ipv4", "resolve_active_ipv6"]

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
        The lowercase colon-separated form, or ``None`` when this is not a
        learned Ethernet address. Loopback and tunnel interfaces report
        zero-length or oversized link addresses, and point-to-point interfaces
        report all zeros, which means no address was learned rather than an
        address of zero. Inventing a MAC for any of them would be worse than
        saying nothing.

    Examples:
        >>> format_mac(bytes.fromhex("aabbccddeeff"))
        'aa:bb:cc:dd:ee:ff'
        >>> format_mac(b"") is None
        True
        >>> format_mac(bytes(6)) is None
        True

    """

    if len(raw) != _MAC_LENGTH or not any(raw):
        return None
    return ":".join(f"{octet:02x}" for octet in raw)


def _state_of(state: int) -> NeighbourState:
    """Map the kernel's NUD bitmask to the reported state."""

    for bit, name in _STATE_NAMES.items():
        if state & bit:
            return name
    return NeighbourState.OTHER


def _is_not_a_neighbour(ip: str) -> bool:
    """Return whether an address cannot name a neighbour worth reporting.

    Multicast entries carry a MAC derived from the group address rather than
    learned from a host, and the unspecified address names nobody. Both appear
    in a raw dump and both would be noise in a scan that answers "which host
    has this hardware address".
    """

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:  # pragma: no cover - the kernel does not emit these
        return True
    return address.is_multicast or address.is_unspecified


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

        if ip is None or mac is None or _is_not_a_neighbour(ip):
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


def _permission_error(exc: OSError, what: str) -> IPScoutPermissionError:
    """Return the error explaining which privilege the caller is missing."""

    return IPScoutPermissionError(
        f"active {what} needs a raw socket, so root or CAP_NET_RAW: {exc}. "
        f"Grant it with 'setcap cap_net_raw+ep $(readlink -f $(which python3))', run as root, "
        f"or use arp_scan(), which resolves the same addresses unprivileged"
    )


def resolve_active_ipv4(target_ip: str, *, interface: str, source_ip: str, source_mac: str, timeout: float = 2.0) -> str | None:
    """Send a real ARP request and return what answers.

    Args:
        target_ip: The address to resolve.
        interface: The interface to send on.
        source_ip: This host's address on the target's subnet.
        source_mac: This host's hardware address on that interface.
        timeout: Seconds to wait for a reply.

    Returns:
        The hardware address, or ``None`` when nothing answered in time.

    Raises:
        IPScoutPermissionError: The process may not open a link-layer socket.

    Note:
        Uses ``AF_PACKET``, which requires root or ``CAP_NET_RAW``. It never
        falls back to the cache: a caller who asked to resolve actively gets a
        fresh answer or an error, not a stale entry dressed up as one.

    """

    af_packet = getattr(socket, "AF_PACKET", None)
    if not isinstance(af_packet, int):  # pragma: no cover - non-Linux
        msg = "AF_PACKET is a Linux facility and this process is not on Linux"
        raise IPScoutUnsupportedError(msg)

    try:
        sock = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    except PermissionError as exc:
        raise _permission_error(exc, "ARP") from exc
    except OSError as exc:  # pragma: no cover - no interface to bind
        raise _permission_error(exc, "ARP") from exc

    try:
        sock.bind((interface, ETH_P_ARP))
        sock.settimeout(timeout)
        sock.send(build_arp_request(sender_mac=source_mac, sender_ip=source_ip, target_ip=target_ip))

        # A link-layer socket sees every frame on the segment, so most of what
        # arrives belongs to somebody else and is discarded.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                found = parse_arp_reply(sock.recv(2048), target_ip)
            except TimeoutError:
                return None
            if found is not None:
                return found
        return None
    except PermissionError as exc:  # pragma: no cover - bind may also be denied
        raise _permission_error(exc, "ARP") from exc
    except OSError:
        return None
    finally:
        with contextlib.suppress(OSError):
            sock.close()


def resolve_active_ipv6(target_ip: str, *, interface: str, source_mac: str, timeout: float = 2.0) -> str | None:
    """Send an ICMPv6 neighbour solicitation and return what answers.

    Args:
        target_ip: The address to resolve.
        interface: The interface to send on, which scopes a link-local target.
        source_mac: This host's hardware address, carried as an option.
        timeout: Seconds to wait for a reply.

    Returns:
        The hardware address, or ``None`` when nothing answered in time.

    Raises:
        IPScoutPermissionError: The process may not open a raw ICMPv6 socket.

    Note:
        Neighbour discovery does not broadcast: the solicitation goes to the
        solicited-node multicast group derived from the target, so only hosts
        whose address ends the same way have to look at it.

    """

    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    except PermissionError as exc:
        raise _permission_error(exc, "neighbour discovery") from exc
    except OSError as exc:  # pragma: no cover - no IPv6 stack
        raise _permission_error(exc, "neighbour discovery") from exc

    try:
        index = socket.if_nametoindex(interface)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
        sock.settimeout(timeout)
        group = solicited_node_multicast(target_ip)
        sock.sendto(build_neighbour_solicitation(sender_mac=source_mac, target_ip=target_ip), (group, 0, 0, index))

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                found = parse_neighbour_advertisement(sock.recv(2048), target_ip)
            except TimeoutError:
                return None
            if found is not None:
                return found
        return None
    except PermissionError as exc:  # pragma: no cover - send may also be denied
        raise _permission_error(exc, "neighbour discovery") from exc
    except OSError:
        return None
    finally:
        with contextlib.suppress(OSError):
            sock.close()
