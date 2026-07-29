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
import struct
import time
from typing import Protocol, cast

from .arp import (
    build_arp_request,
    build_neighbour_solicitation,
    parse_arp_reply,
    parse_neighbour_advertisement,
    solicited_node_multicast,
)
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

#: BPF ioctls, built rather than hardcoded so the encoding is visible. The
#: direction bits and the embedded argument size are part of the number, so a
#: wrong size is a wrong ioctl rather than a wrong argument.
_IOC_WRITE = 0x80000000
_IOC_READ = 0x40000000
_IOCPARM_MASK = 0x1FFF
_BPF_GROUP = ord("B")

#: sizeof(struct ifreq) on macOS: a 16-byte name plus a 16-byte union.
_IFREQ_SIZE = 32
_UINT_SIZE = 4

#: struct bpf_hdr: a 32-bit timeval, captured and original lengths, then the
#: header length that says where the frame actually starts.
_BPF_HDR = struct.Struct("=iiIIH")

#: How many /dev/bpf devices to try before giving up. They are a fixed pool
#: and each is exclusive, so a busy one is normal rather than an error.
_MAX_BPF_DEVICES = 64


class _Fcntl(Protocol):
    """The one ``fcntl`` call this module makes, in the one form used.

    ``fcntl`` is a Unix module, so on the Windows type-check its attributes
    are unknown even though the import sits on a macOS-only path. Casting the
    module onto this Protocol gives the call sites complete types on every
    platform without turning a rule off, which would blind this file to real
    errors as well.
    """

    def ioctl(self, fd: int, request: int, arg: bytes, /) -> bytes: ...


def _fcntl() -> _Fcntl:
    """Return the ``fcntl`` module, typed, importing it on first use."""

    import fcntl  # noqa: PLC0415 - Unix-only, and only on the active path

    return cast("_Fcntl", fcntl)


def _iow(number: int, size: int) -> int:
    """Return the ioctl number for a write-direction request."""

    return _IOC_WRITE | ((size & _IOCPARM_MASK) << 16) | (_BPF_GROUP << 8) | number


def _ior(number: int, size: int) -> int:
    """Return the ioctl number for a read-direction request."""

    return _IOC_READ | ((size & _IOCPARM_MASK) << 16) | (_BPF_GROUP << 8) | number


BIOCGBLEN = _ior(102, _UINT_SIZE)
BIOCSETIF = _iow(108, _IFREQ_SIZE)
BIOCIMMEDIATE = _iow(112, _UINT_SIZE)
BIOCSHDRCMPLT = _iow(117, _UINT_SIZE)


def iter_bpf_frames(buffer: bytes) -> list[bytes]:
    """Split a BPF read into the frames it holds.

    Args:
        buffer: One read from a BPF device.

    Returns:
        Each captured frame, without its BPF header. A single read returns
        several frames packed together, each preceded by a header whose
        ``bh_hdrlen`` gives the offset to the frame and whose length is
        rounded up for alignment - so neither offset can be assumed.

    Examples:
        >>> iter_bpf_frames(b"")
        []

    """

    frames: list[bytes] = []
    position = 0
    while position + _BPF_HDR.size <= len(buffer):
        _sec, _usec, caplen, _datalen, hdrlen = _BPF_HDR.unpack(buffer[position : position + _BPF_HDR.size])
        if hdrlen < _BPF_HDR.size or caplen == 0:
            break
        start = position + hdrlen
        end = start + caplen
        if end > len(buffer):
            break
        frames.append(buffer[start:end])
        # BPF_WORDALIGN: each record starts on a 4-byte boundary.
        position += (hdrlen + caplen + 3) & ~3
    return frames


def _open_bpf(interface: str) -> tuple[int, int]:  # pragma: no cover - macOS only
    """Open a free BPF device bound to one interface, and its buffer size."""

    fcntl = _fcntl()
    last: OSError | None = None
    for number in range(_MAX_BPF_DEVICES):
        try:
            descriptor = os.open(f"/dev/bpf{number}", os.O_RDWR)
        except PermissionError as exc:
            raise _permission_error(exc) from exc
        except OSError as exc:
            # EBUSY simply means another process holds that one.
            last = exc
            continue

        try:
            name = interface.encode()[:15].ljust(_IFREQ_SIZE, b"\x00")
            fcntl.ioctl(descriptor, BIOCSETIF, name)
            fcntl.ioctl(descriptor, BIOCIMMEDIATE, struct.pack("=I", 1))
            # Say that the frames written are complete, so the kernel does not
            # fill in a source address of its own choosing.
            fcntl.ioctl(descriptor, BIOCSHDRCMPLT, struct.pack("=I", 1))
            length = struct.unpack("=I", fcntl.ioctl(descriptor, BIOCGBLEN, struct.pack("=I", 0)))[0]
        except OSError as exc:
            os.close(descriptor)
            raise _permission_error(exc) from exc
        return descriptor, int(length)

    raise _permission_error(last or OSError("no BPF device could be opened"))


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
