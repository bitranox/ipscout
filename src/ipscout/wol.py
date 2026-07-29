"""Wake-on-LAN: the magic packet, and sending it.

Contents:
    build_magic_packet: The packet a sleeping NIC listens for.
    wake_on_lan: Send it to a broadcast address.

Note:
    Unprivileged everywhere. The packet is ordinary UDP; what makes it special
    is only its contents, which a sleeping NIC's firmware matches on without
    the host being awake to receive it.

    It is fire-and-forget by design. Nothing acknowledges a magic packet, so
    this cannot report whether the target woke - only whether the packet was
    sent. Poll with ``is_reachable`` if you need to know.

"""

from __future__ import annotations

import socket

from .errors import IPScoutError
from .neighbours import normalise_mac

__all__ = ["DEFAULT_PORT", "build_magic_packet", "wake_on_lan"]

#: The conventional ports. Nothing listens on them in the usual sense - the
#: NIC matches the payload regardless - so any of them works.
DEFAULT_PORT = 9

#: The packet is six 0xFF bytes followed by the address repeated sixteen times.
_SYNC_LENGTH = 6
_REPEATS = 16

#: 6 sync bytes plus 16 six-byte addresses.
MAGIC_PACKET_SIZE = 102


def build_magic_packet(mac: str) -> bytes:
    """Return the magic packet for one hardware address.

    Args:
        mac: The target's address, in any common written form.

    Returns:
        The 102-byte payload: six ``0xFF`` bytes, then the address sixteen
        times over.

    Raises:
        ValueError: The input is not a hardware address.

    Examples:
        >>> packet = build_magic_packet("aa:bb:cc:dd:ee:ff")
        >>> len(packet), packet[:6].hex()
        (102, 'ffffffffffff')
        >>> packet[6:12].hex()
        'aabbccddeeff'

    """

    canonical = normalise_mac(mac)
    if canonical is None:
        msg = f"not a hardware address: {mac!r}"
        raise ValueError(msg)
    raw = bytes.fromhex(canonical.replace(":", ""))
    return b"\xff" * _SYNC_LENGTH + raw * _REPEATS


def wake_on_lan(mac: str, *, broadcast: str = "255.255.255.255", port: int = DEFAULT_PORT) -> None:
    """Send a magic packet, asking a sleeping host to wake.

    Args:
        mac: The target's hardware address, in any common written form.
        broadcast: Where to send it. The limited broadcast address reaches the
            local segment; a subnet's own broadcast address is often the
            better choice, since some switches drop the limited form.
        port: UDP port. Conventionally 9 or 7, and it makes no difference:
            the NIC matches the payload, not the port.

    Raises:
        ValueError: The input is not a hardware address.
        IPScoutError: The packet could not be sent - an unroutable broadcast
            address, or no route to it.

    Note:
        Returns nothing, because nothing comes back. A magic packet is
        unacknowledged, so a successful send says only that the packet left
        this host. Whether the target woke is a separate question, answered by
        polling ``is_reachable``.

    Examples:
        >>> wake_on_lan("aa:bb:cc:dd:ee:ff", broadcast="127.0.0.1")

    """

    packet = build_magic_packet(mac)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(packet, (broadcast, port))
    except OSError as exc:
        # Every other public callable reports failure through this hierarchy;
        # leaking a bare OSError from one of them would make the contract
        # "catch IPScoutError" untrue for exactly one function.
        msg = f"could not send the magic packet to {broadcast}:{port}: {exc}"
        raise IPScoutError(msg) from exc
