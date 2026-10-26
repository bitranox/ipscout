"""Wake-on-LAN: the magic packet, and sending it.

Contents:
    build_magic_packet: The packet a sleeping NIC listens for.
    wake_on_lan: Send it to a broadcast address.
    WakeSettings: The arguments of one send, checked together.

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
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, ValidationError

from .arp import MAC_LENGTH, packed_mac, require_mac
from .errors import IPScoutError, refused_arguments
from .models import DISCARD_PORT, AddressFamily, Port, require_address

__all__ = ["DEFAULT_BROADCAST", "DEFAULT_PORT", "MAGIC_PACKET_SIZE", "WakeSettings", "build_magic_packet", "wake_on_lan"]

#: The conventional port, the discard service's (7, echo, is the other one
#: in use). Nothing listens on it in the usual sense - the NIC matches the
#: payload regardless - so any port works.
DEFAULT_PORT = DISCARD_PORT

#: The limited broadcast address: it reaches the local segment without
#: knowing its subnet, which is why it is the default.
DEFAULT_BROADCAST = "255.255.255.255"

#: The packet is six 0xFF bytes followed by the address repeated sixteen times.
_SYNC_LENGTH = 6
_REPEATS = 16

#: The whole packet: the sync bytes, then the hardware address repeated.
MAGIC_PACKET_SIZE = _SYNC_LENGTH + MAC_LENGTH * _REPEATS


def _broadcast_address(text: str) -> str:
    """Return the IPv4 address a magic packet goes to, or raise saying why ``text`` is not one.

    An empty string or ``0.0.0.0`` is refused rather than handed to the
    socket: both mean INADDR_ANY there, so the packet would go to this host
    and still be reported as sent. A name is refused too, because only an
    address says which segment the broadcast is meant for.

    Returns:
        The address in its canonical text form, the form a socket is handed.

    Examples:
        >>> _broadcast_address("192.0.2.255")
        '192.0.2.255'
        >>> _broadcast_address("0.0.0.0")
        Traceback (most recent call last):
        ...
        ValueError: broadcast must be an IPv4 address other than 0.0.0.0: '0.0.0.0' is this host

    """

    lead = "broadcast must be an IPv4 address other than 0.0.0.0"
    try:
        address = require_address(text, AddressFamily.IPV4)
    except ValueError as exc:
        msg = f"{lead}: {exc}"
        raise ValueError(msg) from exc
    if address.is_unspecified:
        msg = f"{lead}: {text!r} is this host"
        raise ValueError(msg)
    return str(address)


class WakeSettings(BaseModel):
    """The arguments of one wake-on-LAN send, checked together before anything is sent.

    Strict, so ``True`` and ``9.0`` are not ports: a bool would otherwise pass
    as port 1 and be sent there. Each field's rule is the library's own for
    that kind of value, so the refusal reads the same here as elsewhere.

    Examples:
        >>> WakeSettings(mac="AA-BB-CC-DD-EE-FF").mac
        'aa:bb:cc:dd:ee:ff'
        >>> WakeSettings(mac="aa:bb:cc:dd:ee:ff", port=0)
        Traceback (most recent call last):
        ...
        pydantic_core._pydantic_core.ValidationError: ...

    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    #: The target's hardware address, stored in canonical form.
    mac: Annotated[str, AfterValidator(require_mac)]
    #: The IPv4 destination, never ``0.0.0.0``, stored in canonical form.
    broadcast: Annotated[str, AfterValidator(_broadcast_address)] = DEFAULT_BROADCAST
    #: The UDP port, under the library's one port rule.
    port: Port = DEFAULT_PORT


def _settings(*, mac: str, broadcast: str, port: int) -> WakeSettings:
    """Return the checked settings, or raise one ``ValueError`` naming every bad argument."""

    try:
        return WakeSettings(mac=mac, broadcast=broadcast, port=port)
    except ValidationError as refused:
        raise refused_arguments("wake-on-LAN", refused) from refused


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

    return b"\xff" * _SYNC_LENGTH + packed_mac(mac) * _REPEATS


def wake_on_lan(mac: str, *, broadcast: str = DEFAULT_BROADCAST, port: int = DEFAULT_PORT) -> None:
    """Send a magic packet, asking a sleeping host to wake.

    Args:
        mac: The target's hardware address, in any common written form.
        broadcast: Where to send it, as an IPv4 address. The limited
            broadcast address reaches the local segment; a subnet's own
            broadcast address is often the better choice, since some switches
            drop the limited form.
        port: UDP port. Conventionally 9 or 7, and it makes no difference:
            the NIC matches the payload, not the port.

    Raises:
        ValueError: The input is not a hardware address, the port is not an
            integer in ``MIN_PORT``-``MAX_PORT``, or ``broadcast`` is not an
            IPv4 address or is ``0.0.0.0``. Checked together before anything
            is sent, and every bad argument is named in the one message.
        IPScoutError: The packet could not be sent, for instance for want of a
            route to the broadcast address.

    Note:
        Returns nothing, because nothing comes back. A magic packet is
        unacknowledged, so a successful send says only that the packet left
        this host. Whether the target woke is a separate question, answered by
        polling ``is_reachable``.

    Examples:
        >>> wake_on_lan("aa:bb:cc:dd:ee:ff", broadcast="127.0.0.1")

    """

    settings = _settings(mac=mac, broadcast=broadcast, port=port)
    packet = build_magic_packet(settings.mac)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(packet, (settings.broadcast, settings.port))
    except OSError as exc:
        # Every other public callable reports failure through this hierarchy;
        # leaking a bare OSError from one of them would make the contract
        # "catch IPScoutError" untrue for exactly one function.
        msg = f"could not send the magic packet to {broadcast}:{port}: {exc}"
        raise IPScoutError(msg) from exc
