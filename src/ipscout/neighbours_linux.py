"""Neighbour-cache reads and writes on Linux, over netlink.

Contents:
    list_neighbours: Every entry the kernel currently holds (``RTM_GETNEIGH``).
    parse_neighbour_dump: Pure decoder for one dump chunk.
    NeighbourDumpChunk: What that decoder returns - the entries and whether
        the dump ended.
    set_static_neighbour / remove_static_neighbour: Write a permanent IPv4
        entry (``RTM_NEWNEIGH``) or delete one (``RTM_DELNEIGH``).
    build_set_request / build_remove_request: Pure encoders for those two.
    raise_for_ack / removed_from_ack: The kernel's errno, mapped to an outcome.

Note:
    Netlink covers IPv4 and IPv6 in one dump, so this does not read
    ``/proc/net/arp`` at all: that file is IPv4-only, and using it would mean
    two mechanisms where one answers the whole question. The read is passive -
    it reports what the kernel already learned and sends nothing - and needs no
    privileges.

"""

from __future__ import annotations

import contextlib
import enum
import errno
import os
import socket
import struct
from typing import NamedTuple

from .arp import (
    ETH_P_ARP,
    await_answer,
    build_arp_request,
    format_mac,
    parse_arp_reply,
    parse_neighbour_advertisement,
    send_neighbour_solicitation,
)
from .errors import (
    ARP_SCAN_ALTERNATIVE,
    PERMISSION_ERRNOS,
    IPScoutError,
    IPScoutPermissionError,
    IPScoutUnsupportedError,
    could_not_ask,
    kernel_refused_neighbour_change,
    setcap_command,
)
from .models import DEFAULT_TIMEOUT, AddressFamily, Neighbour, NeighbourChange, NeighbourState, names_a_neighbour, parse_address
from .netlink import (
    NLM_F_ACK,
    NLM_F_CREATE,
    NLM_F_DUMP,
    NLM_F_REPLACE,
    NLM_F_REQUEST,
    NLMSG_DONE,
    NLMSG_ERROR,
    RECEIVE_SIZE,
    build_attribute,
    build_message,
    iter_attributes,
    iter_messages,
    open_socket,
    parse_ack,
)
from .resolve import interface_name
from .unixio import packet_family

__all__ = [
    "NeighbourDumpChunk",
    "build_remove_request",
    "build_set_request",
    "list_neighbours",
    "parse_neighbour_dump",
    "raise_for_ack",
    "remove_static_neighbour",
    "removed_from_ack",
    "resolve_active_ipv4",
    "resolve_active_ipv6",
    "set_static_neighbour",
]

_RTM_NEWNEIGH = 28
_RTM_DELNEIGH = 29
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


def _state_of(state: int) -> NeighbourState:
    """Map the kernel's NUD bitmask to the reported state."""

    for bit, name in _STATE_NAMES.items():
        if state & bit:
            return name
    return NeighbourState.OTHER


class _EntryAddresses(NamedTuple):
    """The destination address and link address one neighbour entry carries.

    A ``NamedTuple`` so the pair cannot be read back in the wrong order: both
    fields are optional strings, so a swapped unpack would type-check.

    Attributes:
        ip: The textual destination address, or ``None`` when the entry lacks
            one or it does not decode.
        mac: The formatted hardware address, or ``None`` when the entry lacks
            a learned Ethernet address.

    Examples:
        >>> _EntryAddresses("192.0.2.5", None) == ("192.0.2.5", None)
        True

    """

    ip: str | None
    mac: str | None


def _read_address_attributes(payload: bytes, family: int) -> _EntryAddresses:
    """Return the destination address and link address an entry carries.

    Args:
        payload: One ``RTM_NEWNEIGH`` message payload, ndmsg header included.
        family: The entry's address family, which decides how to render the
            destination.

    Returns:
        The textual destination address and the formatted MAC, each ``None``
        when the entry lacks it or it does not decode. A later attribute of the
        same kind overwrites an earlier one only when it decodes.

    """

    ip: str | None = None
    mac: str | None = None
    for attribute, value in iter_attributes(payload, _NDMSG.size):
        if attribute == _NDA_DST:
            with contextlib.suppress(OSError, ValueError):
                ip = socket.inet_ntop(family, value)
        elif attribute == _NDA_LLADDR:
            # Loopback and tunnels report a zero-length or oversized link
            # address and point-to-point links all zeros: none is a learned
            # Ethernet address, and format_mac answers None for each.
            mac = format_mac(value)
    return _EntryAddresses(ip=ip, mac=mac)


def _neighbour_from_payload(payload: bytes) -> Neighbour | None:
    """Decode one ``RTM_NEWNEIGH`` payload into a neighbour, if it names one.

    Args:
        payload: The message payload, at least one ndmsg header long.

    Returns:
        The entry, or ``None`` when it is unresolved or failed, of a family
        other than IPv4/IPv6, lacks a usable address or MAC, or names a
        multicast or unspecified address.

    """

    raw_family, _pad1, _pad2, ifindex, state, _flags, _kind = _NDMSG.unpack(payload[: _NDMSG.size])
    if state & (_NUD_INCOMPLETE | _NUD_FAILED):
        return None
    family = AddressFamily.of_socket_family(raw_family)
    if family is None:
        return None

    addresses = _read_address_attributes(payload, raw_family)
    ip, mac = addresses.ip, addresses.mac
    # Multicast entries carry a MAC derived from the group rather than learned
    # from a host, and the unspecified address names nobody: both would be
    # noise in a scan that answers "which host has this hardware address".
    if ip is None or mac is None or not names_a_neighbour(parse_address(ip)):
        return None

    return Neighbour(ip=ip, mac=mac, interface=interface_name(ifindex), state=_state_of(state), family=family)


class NeighbourDumpChunk(NamedTuple):
    """What one netlink dump chunk decodes to.

    A ``NamedTuple`` rather than a pydantic model on purpose: it was a plain
    ``(entries, done)`` tuple first, and callers unpack it and compare it with
    tuples. A NamedTuple keeps every one of those working while letting new
    code name the fields instead of remembering their order.

    Attributes:
        entries: The neighbours this chunk carried, in the order the kernel
            reported them. Entries with no usable hardware address are already
            dropped.
        done: Whether the kernel signalled the end of the dump in this chunk,
            so the reader stops asking for more.

    Examples:
        >>> chunk = NeighbourDumpChunk([], True)
        >>> chunk.entries, chunk.done
        ([], True)
        >>> chunk == ([], True)
        True

    """

    entries: list[Neighbour]
    done: bool


def parse_neighbour_dump(data: bytes) -> NeighbourDumpChunk:
    """Decode one netlink dump chunk into neighbour entries.

    Args:
        data: Bytes as read from the netlink socket.

    Returns:
        The entries found, and whether the kernel signalled the end of the
        dump. Entries with no usable hardware address are dropped: an
        unanswered query is not a neighbour this host knows.

    Examples:
        >>> parse_neighbour_dump(b"")
        NeighbourDumpChunk(entries=[], done=False)

    """

    found: list[Neighbour] = []
    for message_type, payload in iter_messages(data):
        if message_type in (NLMSG_DONE, NLMSG_ERROR):
            return NeighbourDumpChunk(entries=found, done=True)
        if message_type != _RTM_NEWNEIGH or len(payload) < _NDMSG.size:
            continue
        neighbour = _neighbour_from_payload(payload)
        if neighbour is not None:
            found.append(neighbour)
    return NeighbourDumpChunk(entries=found, done=False)


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
        sock.settimeout(DEFAULT_TIMEOUT)
        # AF_UNSPEC asks for every family in one dump.
        sock.send(build_message(_RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP, _NDMSG.pack(socket.AF_UNSPEC, 0, 0, 0, 0, 0, 0)))
        for _ in range(_MAX_DUMP_CHUNKS):
            chunk = parse_neighbour_dump(sock.recv(RECEIVE_SIZE))
            found.extend(chunk.entries)
            if chunk.done:
                break
    except OSError:
        return tuple(found)
    finally:
        with contextlib.suppress(OSError):
            sock.close()
    return tuple(found)


class _Solicitation(str, enum.Enum):
    """The active query a raw socket was opened for, as the error names it.

    Render a member with ``.value``, never by formatting the member itself: on
    3.11 and later an f-string of a ``str`` enum member gives
    ``_Solicitation.ARP``, not ``ARP``, so the message would change with the
    interpreter.

    Examples:
        >>> f"active {_Solicitation.NEIGHBOUR_DISCOVERY.value} needs a raw socket"
        'active neighbour discovery needs a raw socket'

    """

    ARP = "ARP"
    NEIGHBOUR_DISCOVERY = "neighbour discovery"


def _permission_error(exc: OSError, what: _Solicitation) -> IPScoutPermissionError:
    """Return the error explaining which privilege the caller is missing.

    Args:
        exc: The refusal the socket call raised, quoted in the message.
        what: The query the socket was for.

    Returns:
        The error to raise, naming the capability and how to grant it.

    """

    return IPScoutPermissionError(
        f"active {what.value} needs a raw socket, so root or CAP_NET_RAW: {exc}. "
        f"Grant it with '{setcap_command('cap_net_raw')}', run as root, "
        f"or {ARP_SCAN_ALTERNATIVE}"
    )


def resolve_active_ipv4(target_ip: str, *, interface: str, source_ip: str, source_mac: str, timeout: float = DEFAULT_TIMEOUT) -> str | None:
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
        IPScoutUnsupportedError: The request could not be sent or the reply
            could not be read (the interface went away, the stack refused the
            send). That is "could not ask", never a ``None`` answer.

    Note:
        Uses ``AF_PACKET``, which requires root or ``CAP_NET_RAW``. It never
        falls back to the cache: a caller who asked to resolve actively gets a
        fresh answer or an error, not a stale entry dressed up as one.

    """

    af_packet = packet_family()

    try:
        sock = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    except PermissionError as exc:
        raise _permission_error(exc, _Solicitation.ARP) from exc
    except OSError as exc:  # pragma: no cover - no interface to bind
        raise _permission_error(exc, _Solicitation.ARP) from exc

    try:
        sock.bind((interface, ETH_P_ARP))
        sock.settimeout(timeout)
        sock.send(build_arp_request(sender_mac=source_mac, sender_ip=source_ip, target_ip=target_ip))
        # A link-layer socket sees every frame on the segment, so most of what
        # arrives belongs to somebody else and is discarded by the parser.
        return await_answer(sock, timeout=timeout, parse=lambda frame: parse_arp_reply(frame, target_ip))
    except PermissionError as exc:  # pragma: no cover - bind may also be denied
        raise _permission_error(exc, _Solicitation.ARP) from exc
    except OSError as exc:
        raise could_not_ask(target_ip, interface, exc) from exc
    finally:
        with contextlib.suppress(OSError):
            sock.close()


def resolve_active_ipv6(target_ip: str, *, interface: str, source_mac: str, timeout: float = DEFAULT_TIMEOUT) -> str | None:
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
        IPScoutUnsupportedError: The request could not be sent or the reply
            could not be read (the interface went away, the stack refused the
            send). That is "could not ask", never a ``None`` answer.

    Note:
        Neighbour discovery does not broadcast: the solicitation goes to the
        solicited-node multicast group derived from the target, so only hosts
        whose address ends the same way have to look at it.

    """

    try:
        sock = socket.socket(AddressFamily.IPV6.socket_family, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    except PermissionError as exc:
        raise _permission_error(exc, _Solicitation.NEIGHBOUR_DISCOVERY) from exc
    except OSError as exc:  # pragma: no cover - no IPv6 stack
        raise _permission_error(exc, _Solicitation.NEIGHBOUR_DISCOVERY) from exc

    try:
        send_neighbour_solicitation(sock, interface=interface, target_ip=target_ip, source_mac=source_mac, timeout=timeout)
        return await_answer(sock, timeout=timeout, parse=lambda frame: parse_neighbour_advertisement(frame, target_ip))
    except PermissionError as exc:  # pragma: no cover - send may also be denied
        raise _permission_error(exc, _Solicitation.NEIGHBOUR_DISCOVERY) from exc
    except OSError as exc:
        raise could_not_ask(target_ip, interface, exc) from exc
    finally:
        with contextlib.suppress(OSError):
            sock.close()


# --------------------------------------------------------------------------
# Writing a static entry
# --------------------------------------------------------------------------

#: Reads allowed while waiting for the acknowledgement. Nothing else is sent
#: on this private socket, so the first reply is the answer; the bound only
#: stops a misbehaving stream from looping.
_MAX_ACK_READS = 8


def build_set_request(ip: str, mac: bytes, ifindex: int, sequence: int = 1) -> bytes:
    """Encode the ``RTM_NEWNEIGH`` that adds or replaces a permanent IPv4 entry.

    Args:
        ip: The IPv4 address the entry maps.
        mac: The six-byte hardware address it maps to.
        ifindex: The interface the entry belongs to. The kernel keys the table
            by address AND interface, so there is no entry without one.
        sequence: Sequence number echoed back on the acknowledgement.

    Returns:
        The message ``ip neigh replace IP lladdr MAC nud permanent dev IF``
        sends: an ``ndmsg`` in state ``NUD_PERMANENT``, then ``NDA_DST`` and
        ``NDA_LLADDR``, with ``NLM_F_CREATE | NLM_F_REPLACE`` so an existing
        entry (learned or static) is overwritten rather than refused.

    Examples:
        >>> len(build_set_request("192.0.2.7", bytes.fromhex("020000000007"), 2))
        48

    """

    body = (
        _NDMSG.pack(socket.AF_INET, 0, 0, ifindex, _NUD_PERMANENT, 0, 0) + build_attribute(_NDA_DST, socket.inet_aton(ip)) + build_attribute(_NDA_LLADDR, mac)
    )
    return build_message(_RTM_NEWNEIGH, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, body, sequence)


def build_remove_request(ip: str, ifindex: int, sequence: int = 1) -> bytes:
    """Encode the ``RTM_DELNEIGH`` that deletes one IPv4 entry.

    Args:
        ip: The IPv4 address whose entry goes.
        ifindex: The interface it is on. The kernel refuses a delete without
            one (``EINVAL``), since the same address may be on several links.
        sequence: Sequence number echoed back on the acknowledgement.

    Returns:
        An ``ndmsg`` plus ``NDA_DST``, asking for an acknowledgement.

    Examples:
        >>> len(build_remove_request("192.0.2.7", 2))
        36

    """

    body = _NDMSG.pack(socket.AF_INET, 0, 0, ifindex, 0, 0, 0) + build_attribute(_NDA_DST, socket.inet_aton(ip))
    return build_message(_RTM_DELNEIGH, NLM_F_REQUEST | NLM_F_ACK, body, sequence)


def raise_for_ack(error: int | None, *, action: NeighbourChange) -> None:
    """Raise unless the kernel acknowledged a neighbour-table change.

    Args:
        error: What :func:`~ipscout.netlink.parse_ack` read: ``0`` for success,
            a positive errno for a refusal, ``None`` for no answer at all.
        action: What was asked, named in the message.

    Raises:
        IPScoutPermissionError: ``EPERM`` or ``EACCES``. Writing the table
            needs ``CAP_NET_ADMIN``, which reading it does not.
        IPScoutError: Any other refusal, or no acknowledgement.

    Examples:
        >>> raise_for_ack(0, action=NeighbourChange.ADD)
        >>> raise_for_ack(errno.EPERM, action=NeighbourChange.ADD)
        Traceback (most recent call last):
        ...
        ipscout.errors.IPScoutPermissionError: ...CAP_NET_ADMIN...

    """

    if error == 0:
        return
    if error is None:
        msg = f"the kernel did not acknowledge the request to {action.value} the neighbour entry"
        raise IPScoutError(msg)
    if error in PERMISSION_ERRNOS:
        msg = (
            f"changing the neighbour table needs root or CAP_NET_ADMIN: {os.strerror(error)}. Run as root, or grant it with '{setcap_command('cap_net_admin')}'"
        )
        raise IPScoutPermissionError(msg)
    raise kernel_refused_neighbour_change(action.value, error)


def removed_from_ack(error: int | None) -> bool:
    """Return whether a delete removed an entry, raising on a real refusal.

    Args:
        error: The acknowledged errno, as for :func:`raise_for_ack`.

    Returns:
        ``True`` when the kernel deleted an entry, ``False`` when it had none
        (``ENOENT``) - an ordinary answer, not an error.

    Raises:
        IPScoutPermissionError: The process lacks ``CAP_NET_ADMIN``.
        IPScoutError: Any other refusal, or no acknowledgement.

    Examples:
        >>> removed_from_ack(0), removed_from_ack(errno.ENOENT)
        (True, False)

    """

    if error == errno.ENOENT:
        return False
    raise_for_ack(error, action=NeighbourChange.REMOVE)
    return True


def _exchange(message: bytes) -> int | None:
    """Send one request on a private netlink socket and return its errno."""

    sock = open_socket()
    if sock is None:  # pragma: no cover - non-Linux, or netlink unavailable
        msg = "no netlink socket on this host, so the neighbour table cannot be changed"
        raise IPScoutUnsupportedError(msg)
    try:
        sock.settimeout(DEFAULT_TIMEOUT)
        sock.send(message)
        for _ in range(_MAX_ACK_READS):
            error = parse_ack(sock.recv(RECEIVE_SIZE))
            if error is not None:
                return error
        return None  # pragma: no cover - the kernel always acknowledges
    except OSError:  # pragma: no cover - a timeout, which the kernel does not cause
        return None
    finally:
        with contextlib.suppress(OSError):
            sock.close()


def set_static_neighbour(ip: str, mac: bytes, ifindex: int) -> None:
    """Add or replace a permanent IPv4 neighbour entry.

    Args:
        ip: The IPv4 address the entry maps.
        mac: The six-byte hardware address.
        ifindex: The interface the entry belongs to.

    Raises:
        IPScoutPermissionError: The process lacks ``CAP_NET_ADMIN``.
        IPScoutError: The kernel refused for another reason.

    """

    raise_for_ack(_exchange(build_set_request(ip, mac, ifindex)), action=NeighbourChange.ADD)


def remove_static_neighbour(ip: str, ifindex: int) -> bool:
    """Delete one IPv4 neighbour entry.

    Args:
        ip: The address whose entry goes.
        ifindex: The interface it is on.

    Returns:
        Whether an entry was removed.

    Raises:
        IPScoutPermissionError: The process lacks ``CAP_NET_ADMIN``.
        IPScoutError: The kernel refused for another reason.

    """

    return removed_from_ack(_exchange(build_remove_request(ip, ifindex)))
