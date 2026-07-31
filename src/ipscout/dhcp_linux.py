"""Link-layer capture of IPv4 traffic on Linux, through ``AF_PACKET``.

Contents:
    open_capture: A capture of one interface, satisfying ``PacketCapture``.
    capture_available: Whether a capture could be opened at all.
    PACKET_MREQ: The kernel structure asking for promiscuous mode.

Why promiscuous mode is on by default, and what it costs to turn off:
    On a bridge, a frame addressed to a guest's own hardware address is
    forwarded to that guest's port. It never travels up the bridge device's
    receive path, so a packet socket bound there does not see it.

    Whether DHCP replies are unicast is decided by the client: one that sets
    the broadcast flag gets broadcast answers, and one that does not gets
    unicast ones. Windows sets it. Linux clients generally do not, because
    they read replies from a raw socket and can accept a unicast frame before
    they hold an address. Measured on a real bridge: every reply to a booting
    Linux guest was unicast, and its broadcast flag was clear on all eight of
    its packets.

    So without promiscuous mode this backend would see only the broadcast
    requests, every one of which carries no address at all and is correctly
    discarded, and it would report a machine that booted perfectly as one that
    never appeared - the exact failure the feature exists to prevent.

Note:
    Promiscuous mode is asked for with ``PACKET_ADD_MEMBERSHIP`` rather than by
    setting ``IFF_PROMISC`` through an ioctl. The kernel reference-counts the
    membership and drops it when the socket closes, including when the process
    dies without tidying up. The ioctl form leaves the interface promiscuous
    forever if teardown is ever missed, which is a host-wide side effect to
    leave behind.

"""

from __future__ import annotations

import contextlib
import socket
import struct

from .arp import ETH_P_IP
from .errors import IPScoutPermissionError, IPScoutUnsupportedError

__all__ = ["PACKET_MREQ", "PacketSocketCapture", "capture_available", "open_capture"]

#: ``struct packet_mreq``: interface index, request type, address length, and
#: a fixed eight-byte address field used only by address-based requests.
PACKET_MREQ = struct.Struct("=iHH8s")

#: ``setsockopt`` level and options for a packet socket, from ``linux/if_packet.h``.
#: Named here rather than taken from ``socket`` because they are absent from
#: that module on every platform that is not Linux, and this module has to stay
#: importable everywhere so its layout can be asserted from anywhere.
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1

#: Large enough for any Ethernet frame, so nothing is ever read in halves.
_RECEIVE_SIZE = 2048

#: Asked for, not required. The kernel doubles it for bookkeeping and clamps it
#: to net.core.rmem_max, so the value that sticks is frequently smaller. It is
#: a cushion against a burst arriving between two reads, never a correctness
#: dependency, so failing to set it is not a failure to capture.
_RECEIVE_BUFFER = 1 << 20


def _af_packet() -> int:
    """Return the ``AF_PACKET`` constant, or say why this host has none."""

    af_packet = getattr(socket, "AF_PACKET", None)
    if not isinstance(af_packet, int):  # pragma: no cover - non-Linux
        msg = "AF_PACKET is a Linux facility and this process is not on Linux"
        raise IPScoutUnsupportedError(msg)
    return af_packet


def _permission_error(exc: OSError) -> IPScoutPermissionError:
    """Return the error naming the privilege a capture needs, and the remedy."""

    return IPScoutPermissionError(
        f"capturing DHCP needs a link-layer socket, so root or CAP_NET_RAW: {exc}. "
        f"Grant it with 'setcap cap_net_raw+ep $(readlink -f $(which python3))' or run as root. "
        f"There is no unprivileged way to watch somebody else's traffic; subnet_info() reads this "
        f"host's own lease without any privilege, but it only describes this host"
    )


def capture_available() -> bool:
    """Return whether a capture socket can be opened right now.

    Returns:
        Whether the privilege is present. Opens and immediately closes a
        socket, which is the only honest way to ask: the answer depends on
        capabilities this process may hold without being root.

    Examples:
        >>> isinstance(capture_available(), bool)
        True

    """

    af_packet = getattr(socket, "AF_PACKET", None)
    if not isinstance(af_packet, int):  # pragma: no cover - non-Linux
        return False
    try:
        sock = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    except OSError:
        return False
    sock.close()
    return True


class PacketSocketCapture:
    """A capture of the IPv4 traffic on one interface.

    Bound to ``ETH_P_IP`` rather than to every ethertype, so the kernel copies
    only IPv4 frames across. On a bridge carrying real traffic that is the
    difference between discarding a bridge's whole ARP, IPv6 and spanning-tree
    load in Python and never being handed it. DHCPv4 is IPv4-only, so nothing
    that could matter is filtered out.
    """

    def __init__(self, sock: socket.socket, *, interface: str) -> None:
        self._socket = sock
        self._interface = interface
        self._closed = False

    @property
    def interface(self) -> str:
        """The interface being captured."""

        return self._interface

    def receive(self, *, timeout: float) -> bytes | None:
        """Return the next frame, or None when none arrived in ``timeout``."""

        self._socket.settimeout(max(0.001, timeout))
        try:
            return self._socket.recv(_RECEIVE_SIZE)
        except TimeoutError:
            return None
        except OSError:
            if self._closed:
                # Closed underneath a blocked read during teardown. That is a
                # stop, not a failure, and must not surface as one.
                return None
            raise

    def close(self) -> None:
        """Release the socket, dropping the promiscuous membership with it."""

        self._closed = True
        with contextlib.suppress(OSError):
            self._socket.close()

    def __enter__(self) -> PacketSocketCapture:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        del exc_type, exc, tb
        self.close()


def open_capture(interface: str, *, promiscuous: bool = True) -> PacketSocketCapture:
    """Open a capture of the IPv4 traffic on one interface.

    Args:
        interface: The interface to watch, for example a bridge like ``br0``.
        promiscuous: Whether to ask for promiscuous mode. Leaving it on is
            almost always right; see this module's docstring for what turning
            it off stops you seeing. It raises the interface's promiscuity
            count for as long as the capture is open, which is visible to
            anything else looking at the host.

    Returns:
        The capture, ready to read.

    Raises:
        IPScoutPermissionError: The process may not open a link-layer socket.
        IPScoutUnsupportedError: There is no such interface, or this is not
            Linux.

    """

    af_packet = _af_packet()
    try:
        sock = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    except OSError as exc:
        raise _permission_error(exc) from exc

    try:
        sock.bind((interface, ETH_P_IP))
    except PermissionError as exc:  # pragma: no cover - binding may also be denied
        sock.close()
        raise _permission_error(exc) from exc
    except OSError as exc:
        sock.close()
        msg = f"cannot capture on {interface!r}: {exc}. Name an interface that exists; local_interfaces() lists them"
        raise IPScoutUnsupportedError(msg) from exc

    # Best effort, never fatal: the kernel clamps this and a smaller buffer
    # still captures, it just tolerates a shorter burst between reads.
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RECEIVE_BUFFER)

    if promiscuous:
        try:
            _join_promiscuous(sock, interface)
        except OSError as exc:
            sock.close()
            raise _permission_error(exc) from exc

    return PacketSocketCapture(sock, interface=interface)


def _join_promiscuous(sock: socket.socket, interface: str) -> None:
    """Put one interface into promiscuous mode for this socket's lifetime."""

    request = PACKET_MREQ.pack(socket.if_nametoindex(interface), PACKET_MR_PROMISC, 0, bytes(8))
    sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, request)
