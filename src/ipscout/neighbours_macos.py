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
    FRAME_RECEIVE_SIZE,
    build_arp_request,
    build_neighbour_solicitation,
    parse_arp_reply,
    parse_neighbour_advertisement,
    solicited_node_multicast,
)
from .bpf import BpfDevice, iter_bpf_frames, open_bpf_device
from .bsdroute import (
    CTL_NET,
    NET_RT_FLAGS,
    NO_METRICS,
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
    open_route_socket,
    pack_sockaddr_dl,
    pack_sockaddr_in,
    roundup,
    split_sockaddrs,
    sysctl,
)
from .errors import IPScoutError, IPScoutPermissionError, could_not_ask
from .models import DEFAULT_TIMEOUT, AddressFamily, Neighbour, NeighbourChange, NeighbourState

__all__ = [
    "build_add_message",
    "build_delete_message",
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
        # The loop guard leaves a whole header in range, so the length is read
        # as part of it: one struct, one byte order, for every field.
        (
            message_length,
            _version,
            _message_type,
            index,
            _flags,
            addrs,
            _pid,
            _seq,
            _errno,
            _use,
            _inits,
            _metrics,
        ) = RT_MSGHDR.unpack_from(data, position)
        if message_length < RT_MSGHDR.size or position + message_length > len(data):
            break

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
        # A Neighbour refuses a family that disagrees with its address, so an
        # entry of the other family in this dump is skipped rather than allowed
        # to fail the whole listing.
        if address.is_multicast or address.is_unspecified or address.version != family.ip_version:
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
    for family in AddressFamily:
        data = sysctl([CTL_NET, PF_ROUTE, 0, family.socket_family, NET_RT_FLAGS, RTF_LLINFO])
        if data:
            found.extend(parse_neighbour_dump(data, family))
    return tuple(found)


# --------------------------------------------------------------------------
# Active resolution, over BPF
# --------------------------------------------------------------------------
#: The way out offered whenever active resolution is refused for want of root.
_UNPRIVILEGED_ADVICE = "Run as root, or use arp_scan(), which resolves the same addresses unprivileged"


def _open_bpf(interface: str) -> BpfDevice:  # pragma: no cover - macOS only
    """Open a free BPF device bound to one interface, and its buffer size.

    Thin wrapper over :func:`ipscout.bpf.open_bpf_device`: the plumbing is
    shared with the DHCP capture, only the remediation message differs.

    Returns:
        The claimed device, its descriptor and read size, exactly as
        :func:`ipscout.bpf.open_bpf_device` returns it.
    """

    try:
        return open_bpf_device(interface, complete_headers=True)
    except OSError as exc:
        raise _permission_error(exc) from exc


def _permission_error(exc: OSError) -> IPScoutPermissionError:
    """Return the error explaining which privilege the caller is missing."""

    return IPScoutPermissionError(f"active ARP on macOS needs a BPF device, and /dev/bpf* is root-only: {exc}. {_UNPRIVILEGED_ADVICE}")


def resolve_active_ipv4(
    target_ip: str, *, interface: str, source_ip: str, source_mac: str, timeout: float = DEFAULT_TIMEOUT
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
        IPScoutUnsupportedError: The request could not be sent or the reply
            could not be read (the interface went away, the stack refused the
            send). That is "could not ask", never a ``None`` answer.

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
    except OSError as exc:
        raise could_not_ask(target_ip, interface, exc) from exc
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)


def resolve_active_ipv6(target_ip: str, *, interface: str, source_mac: str, timeout: float = DEFAULT_TIMEOUT) -> str | None:  # pragma: no cover - macOS only
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
        IPScoutUnsupportedError: The request could not be sent or the reply
            could not be read (the interface went away, the stack refused the
            send). That is "could not ask", never a ``None`` answer.

    """

    try:
        sock = socket.socket(AddressFamily.IPV6.socket_family, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    except OSError as exc:
        raise IPScoutPermissionError(f"active neighbour discovery needs a raw ICMPv6 socket, which is root-only here: {exc}. {_UNPRIVILEGED_ADVICE}") from exc

    try:
        index = socket.if_nametoindex(interface)
        sock.setsockopt(AddressFamily.IPV6.ip_option_level, socket.IPV6_MULTICAST_IF, index)
        sock.settimeout(timeout)
        group = solicited_node_multicast(target_ip)
        try:
            sock.sendto(build_neighbour_solicitation(sender_mac=source_mac, target_ip=target_ip), (group, 0, 0, index))
        except PermissionError as exc:
            raise IPScoutPermissionError(f"active neighbour discovery was refused: {exc}. {_UNPRIVILEGED_ADVICE}") from exc

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                found = parse_neighbour_advertisement(sock.recv(FRAME_RECEIVE_SIZE), target_ip)
            except TimeoutError:
                return None
            if found is not None:
                return found
        return None
    except OSError as exc:
        raise could_not_ask(target_ip, interface, exc) from exc
    finally:
        with contextlib.suppress(OSError):
            sock.close()


# --------------------------------------------------------------------------
# Writing a static entry, over a routing socket
# --------------------------------------------------------------------------

#: The flags ``arp -s`` sends for a permanent entry, plus RTF_LLINFO, which the
#: kernel would set on the new entry anyway and which says what it is.
_STATIC_FLAGS = RTF_HOST | RTF_STATIC | RTF_LLINFO


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
        NO_METRICS,
    )


def raise_for_route_errno(error: int, *, action: NeighbourChange) -> None:
    """Raise unless a routing-socket write succeeded.

    Args:
        error: ``0`` for success, otherwise the errno the write failed with.
        action: What was asked, named in the message.

    Raises:
        IPScoutPermissionError: ``EPERM`` or ``EACCES``: only root may change
            the routing table on macOS.
        IPScoutError: Any other refusal. ``EEXIST`` means something already
            occupies that address - an unresolved entry, or a host route that
            is not a neighbour - and is not overwritten blind.

    Examples:
        >>> raise_for_route_errno(0, action=NeighbourChange.ADD)
        >>> raise_for_route_errno(errno.EPERM, action=NeighbourChange.ADD)
        Traceback (most recent call last):
        ...
        ipscout.errors.IPScoutPermissionError: ...root...

    """

    if error == 0:
        return
    if error in (errno.EPERM, errno.EACCES):
        msg = f"changing the neighbour table needs root on macOS: {os.strerror(error)}. Run as root"
        raise IPScoutPermissionError(msg)
    msg = f"the kernel refused to {action.value} the neighbour entry: {os.strerror(error)} (errno {error})"
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
    raise_for_route_errno(error, action=NeighbourChange.REMOVE)
    return True


def _route_write(message: bytes) -> int:  # pragma: no cover - macOS only
    """Write one message to a routing socket and return the errno, 0 on success.

    The kernel reports a refused change as the write's own error, so there is
    no reply to read for the verdict.
    """

    try:
        sock = open_route_socket()
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
    raise_for_route_errno(_route_write(build_add_message(ip, mac, ifindex, pid=pid, seq=2)), action=NeighbourChange.ADD)


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
