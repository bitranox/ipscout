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
import os
import select
import socket
import time

from .arp import (
    build_arp_request,
    build_neighbour_solicitation,
    parse_arp_reply,
    parse_neighbour_advertisement,
    solicited_node_multicast,
)
from .bpf import iter_bpf_frames, open_bpf_device
from .bsdroute import (
    CTL_NET,
    NET_RT_FLAGS,
    PF_ROUTE,
    RT_MSGHDR,
    RTF_LLINFO,
    address_of,
    link_address_of,
    roundup,
    split_sockaddrs,
    sysctl,
)
from .errors import IPScoutPermissionError
from .models import AddressFamily, Neighbour, NeighbourState

__all__ = ["iter_bpf_frames", "list_neighbours", "parse_neighbour_dump", "resolve_active_ipv4", "resolve_active_ipv6"]


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
        ip = address_of(sockaddrs.destination) if sockaddrs.destination else None
        mac = link_address_of(sockaddrs.gateway) if sockaddrs.gateway else None
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


# --------------------------------------------------------------------------
# Active resolution, over BPF
# --------------------------------------------------------------------------
def _open_bpf(interface: str) -> tuple[int, int]:  # pragma: no cover - macOS only
    """Open a free BPF device bound to one interface, and its buffer size.

    Thin wrapper over :func:`ipscout.bpf.open_bpf_device`: the plumbing is
    shared with the DHCP capture, only the remediation message differs.
    """

    try:
        return open_bpf_device(interface, complete_headers=True)
    except OSError as exc:
        raise _permission_error(exc) from exc


def _permission_error(exc: OSError) -> IPScoutPermissionError:
    """Return the error explaining which privilege the caller is missing."""

    return IPScoutPermissionError(
        f"active ARP on macOS needs a BPF device, and /dev/bpf* is root-only: {exc}. "
        f"Run as root, or use arp_scan(), which resolves the same addresses unprivileged"
    )


def resolve_active_ipv4(
    target_ip: str, *, interface: str, source_ip: str, source_mac: str, timeout: float = 2.0
) -> str | None:  # pragma: no cover - macOS only
    """Send a real ARP request over BPF and return what answers.

    Args:
        target_ip: The address to resolve.
        interface: The interface to send on.
        source_ip: This host's address on the target's subnet.
        source_mac: This host's hardware address on that interface.
        timeout: Seconds to wait for a reply.

    Returns:
        The hardware address, or ``None`` when nothing answered in time.

    Raises:
        IPScoutPermissionError: ``/dev/bpf*`` could not be opened, which on a
            stock macOS means the process is not root.

    Note:
        macOS has no ``AF_PACKET``; BPF is the equivalent, and it is
        root-only. It never falls back to the cache: a caller who asked to
        resolve actively gets a fresh answer or an error.

    """

    descriptor, buffer_length = _open_bpf(interface)
    try:
        os.write(descriptor, build_arp_request(sender_mac=source_mac, sender_ip=source_ip, target_ip=target_ip))

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            readable, _writable, _failed = select.select([descriptor], [], [], max(0.01, deadline - time.monotonic()))
            if not readable:
                return None
            for frame in iter_bpf_frames(os.read(descriptor, buffer_length)):
                found = parse_arp_reply(frame, target_ip)
                if found is not None:
                    return found
        return None
    except OSError:
        return None
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)


def resolve_active_ipv6(target_ip: str, *, interface: str, source_mac: str, timeout: float = 2.0) -> str | None:  # pragma: no cover - macOS only
    """Send an ICMPv6 neighbour solicitation and return what answers.

    Args:
        target_ip: The address to resolve.
        interface: The interface to send on.
        source_mac: This host's hardware address, carried as an option.
        timeout: Seconds to wait for a reply.

    Returns:
        The hardware address, or ``None`` when nothing answered in time.

    Raises:
        IPScoutPermissionError: A raw ICMPv6 socket could not be opened.

    """

    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    except OSError as exc:
        raise IPScoutPermissionError(
            f"active neighbour discovery needs a raw ICMPv6 socket, which is root-only here: {exc}. "
            f"Run as root, or use arp_scan(), which resolves the same addresses unprivileged"
        ) from exc

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
    except OSError:
        return None
    finally:
        with contextlib.suppress(OSError):
            sock.close()
