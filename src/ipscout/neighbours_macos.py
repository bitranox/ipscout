"""Neighbour-cache reads and writes on macOS and the BSDs.

Contents:
    list_neighbours: Every entry the kernel currently holds, via a ``sysctl``
        route dump.
    parse_neighbour_dump: Pure decoder for one dump.
    set_static_neighbour / remove_static_neighbour: Write a permanent IPv4
        entry or delete one, with ``RTM_ADD`` / ``RTM_DELETE`` on a routing
        socket, exactly as ``arp -s`` and ``arp -d`` do.
    build_add_message / build_delete_message: Pure encoders for those two.
    raise_for_route_errno / removed_from_route_errno: The kernel's errno,
        mapped to an outcome.

Note:
    The read is passive - it reports what the kernel already learned and sends
    nothing - and needs no privileges. Writing needs root. The decoder and the
    encoders are separated from the system calls so the wire format can be
    tested on Linux, where none of this can execute.

    **The write path has not been run on macOS hardware.** No CI runner here
    is root on macOS, so the message encoding is pinned byte for byte against
    the BSD headers (``net/route.h``, ``net/if_dl.h``) and ``arp.c`` while the
    ``write`` to the routing socket itself is untested.

"""

from __future__ import annotations

import contextlib
import errno
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
    RTA_DST,
    RTA_GATEWAY,
    RTF_HOST,
    RTF_LLINFO,
    RTF_STATIC,
    RTM_ADD,
    RTM_DELETE,
    RTM_VERSION,
    RTV_EXPIRE,
    address_of,
    link_address_of,
    pack_sockaddr_dl,
    pack_sockaddr_in,
    roundup,
    split_sockaddrs,
    sysctl,
)
from .errors import IPScoutError, IPScoutPermissionError
from .models import AddressFamily, Neighbour, NeighbourState

__all__ = [
    "build_add_message",
    "build_delete_message",
    "iter_bpf_frames",
    "list_neighbours",
    "parse_neighbour_dump",
    "raise_for_route_errno",
    "remove_static_neighbour",
    "removed_from_route_errno",
    "resolve_active_ipv4",
    "resolve_active_ipv6",
    "set_static_neighbour",
]


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


# --------------------------------------------------------------------------
# Writing a static entry, over a routing socket
# --------------------------------------------------------------------------

#: The flags ``arp -s`` sends for a permanent entry, plus RTF_LLINFO, which the
#: kernel would set on the new entry anyway and which says what it is.
_STATIC_FLAGS = RTF_HOST | RTF_STATIC | RTF_LLINFO

#: rt_metrics, all zero: with RTV_EXPIRE in rtm_inits that is an expiry of
#: "never".
_NO_METRICS = bytes(56)


def build_add_message(ip: str, mac: bytes, ifindex: int, *, pid: int, seq: int) -> bytes:
    """Encode the ``RTM_ADD`` that writes a permanent IPv4 neighbour entry.

    Args:
        ip: The IPv4 address the entry maps.
        mac: The six-byte hardware address.
        ifindex: The interface, carried in the gateway's ``sdl_index``; the
            kernel takes the entry's interface from it.
        pid: The sending process, as the header records it.
        seq: The sequence number, as the header records it.

    Returns:
        ``rt_msghdr`` (type ``RTM_ADD``, flags ``RTF_HOST | RTF_STATIC |
        RTF_LLINFO``, addrs ``RTA_DST | RTA_GATEWAY``, inits ``RTV_EXPIRE``
        with a zero expiry) followed by a ``sockaddr_in`` destination and a
        ``sockaddr_dl`` gateway carrying the hardware address - the message
        ``arp -s IP MAC`` writes.

    Examples:
        >>> len(build_add_message("192.0.2.7", bytes(6), 4, pid=1, seq=1))
        128

    """

    addresses = pack_sockaddr_in(socket.inet_aton(ip)) + pack_sockaddr_dl(ifindex, mac)
    return _header(RTM_ADD, RTA_DST | RTA_GATEWAY, len(addresses), pid=pid, seq=seq) + addresses


def build_delete_message(ip: str, *, pid: int, seq: int) -> bytes:
    """Encode the ``RTM_DELETE`` that removes one IPv4 neighbour entry.

    Args:
        ip: The address whose entry goes. The kernel deletes the host entry
            keyed on it, which is why the caller must first confirm that the
            entry is a neighbour and not some other host route.
        pid: The sending process, as the header records it.
        seq: The sequence number, as the header records it.

    Returns:
        ``rt_msghdr`` (type ``RTM_DELETE``, addrs ``RTA_DST``) followed by the
        ``sockaddr_in`` destination.

    Examples:
        >>> len(build_delete_message("192.0.2.7", pid=1, seq=1))
        108

    """

    address = pack_sockaddr_in(socket.inet_aton(ip))
    return _header(RTM_DELETE, RTA_DST, len(address), pid=pid, seq=seq) + address


def _header(message_type: int, addrs: int, payload_length: int, *, pid: int, seq: int) -> bytes:
    """Return the ``rt_msghdr`` both writes start with."""

    return RT_MSGHDR.pack(
        RT_MSGHDR.size + payload_length,
        RTM_VERSION,
        message_type,
        0,
        _STATIC_FLAGS,
        addrs,
        pid,
        seq,
        0,
        0,
        RTV_EXPIRE,
        _NO_METRICS,
    )


def raise_for_route_errno(error: int, *, action: str) -> None:
    """Raise unless a routing-socket write succeeded.

    Args:
        error: ``0`` for success, otherwise the errno the write failed with.
        action: What was asked, for the message (``"add"``, ``"remove"``).

    Raises:
        IPScoutPermissionError: ``EPERM`` or ``EACCES``: only root may change
            the routing table on macOS.
        IPScoutError: Any other refusal. ``EEXIST`` means something already
            occupies that address - an unresolved entry, or a host route that
            is not a neighbour - and is not overwritten blind.

    Examples:
        >>> raise_for_route_errno(0, action="add")
        >>> raise_for_route_errno(errno.EPERM, action="add")
        Traceback (most recent call last):
        ...
        ipscout.errors.IPScoutPermissionError: ...root...

    """

    if error == 0:
        return
    if error in (errno.EPERM, errno.EACCES):
        msg = f"changing the neighbour table needs root on macOS: {os.strerror(error)}. Run as root"
        raise IPScoutPermissionError(msg)
    msg = f"the kernel refused to {action} the neighbour entry: {os.strerror(error)} (errno {error})"
    raise IPScoutError(msg)


def removed_from_route_errno(error: int) -> bool:
    """Return whether a delete removed an entry, raising on a real refusal.

    Args:
        error: ``0`` for success, otherwise the errno the write failed with.

    Returns:
        ``True`` when the entry went, ``False`` when there was none
        (``ESRCH``, the routing socket's "no such route").

    Examples:
        >>> removed_from_route_errno(0), removed_from_route_errno(errno.ESRCH)
        (True, False)

    """

    if error == errno.ESRCH:
        return False
    raise_for_route_errno(error, action="remove")
    return True


def _route_write(message: bytes) -> int:  # pragma: no cover - macOS only
    """Write one message to a routing socket and return the errno, 0 on success.

    The kernel reports a refused change as the write's own error, so there is
    no reply to read for the verdict.
    """

    af_route = getattr(socket, "AF_ROUTE", PF_ROUTE)
    try:
        sock = socket.socket(af_route, socket.SOCK_RAW, 0)
    except OSError as exc:
        return exc.errno or errno.EIO
    try:
        sock.send(message)
    except OSError as exc:
        return exc.errno or errno.EIO
    finally:
        with contextlib.suppress(OSError):
            sock.close()
    return 0


def _is_listed(ip: str, ifindex: int | None = None) -> bool:  # pragma: no cover - macOS only
    """Return whether the neighbour dump holds an entry for ``ip``, on ``ifindex`` when given."""

    name: str | None = None
    if ifindex is not None:
        with contextlib.suppress(OSError, ValueError):
            name = socket.if_indextoname(ifindex)
    return any(entry.ip == ip and (ifindex is None or entry.interface == name) for entry in list_neighbours())


def set_static_neighbour(ip: str, mac: bytes, ifindex: int) -> None:  # pragma: no cover - macOS only
    """Add or replace a permanent IPv4 neighbour entry.

    Args:
        ip: The IPv4 address the entry maps.
        mac: The six-byte hardware address.
        ifindex: The interface the entry belongs to.

    Raises:
        IPScoutPermissionError: The process is not root.
        IPScoutError: The kernel refused for another reason.

    Note:
        ``RTM_ADD`` refuses an address that already has an entry, so an
        existing neighbour entry is deleted first - what ``arp -S`` does. Only
        one the neighbour dump lists is deleted: a host route that is not a
        neighbour is left alone, and the add then fails with ``EEXIST``.

    """

    pid = os.getpid()
    # Any interface: the routing socket keys the entry by address alone, so an
    # entry on another link blocks the add just the same.
    if _is_listed(ip):
        removed_from_route_errno(_route_write(build_delete_message(ip, pid=pid, seq=1)))
    raise_for_route_errno(_route_write(build_add_message(ip, mac, ifindex, pid=pid, seq=2)), action="add")


def remove_static_neighbour(ip: str, ifindex: int) -> bool:  # pragma: no cover - macOS only
    """Delete one IPv4 neighbour entry.

    Args:
        ip: The address whose entry goes.
        ifindex: The interface it is on. The message itself deletes by
            address; the index decides whether there is an entry to delete.

    Returns:
        Whether an entry was removed. ``False`` without writing anything when
        the neighbour dump holds no entry for ``ip`` on that interface, so a
        host route that is not a neighbour can never be deleted through here.

    Raises:
        IPScoutPermissionError: The process is not root.
        IPScoutError: The kernel refused for another reason.

    """

    if not _is_listed(ip, ifindex):
        return False
    return removed_from_route_errno(_route_write(build_delete_message(ip, pid=os.getpid(), seq=1)))
