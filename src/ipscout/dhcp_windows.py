"""Promiscuous IPv4 capture on Windows, through ``SIO_RCVALL``.

Contents:
    open_capture: A capture of one interface, satisfying ``PacketCapture``.
    capture_available: Whether a capture could be opened at all.
    SIO_RCVALL: The ioctl that turns a raw socket promiscuous.

No driver, and what that costs:
    Windows has no ``AF_PACKET``, and a raw socket cannot see Ethernet frames
    at any privilege level. What it does have is ``SIO_RCVALL``, a socket
    ioctl that puts a raw IPv4 socket into promiscuous receive. That needs
    Administrator but no installed driver, which is why this backend exists
    rather than a dependency on Npcap.

    **The promise here is weaker than on Linux, and the difference matters.**
    A packet socket bound to a Linux bridge sees the traffic the bridge
    forwards, including frames addressed to a guest. ``SIO_RCVALL`` sees what
    reaches THIS host's interface. On a Hyper-V virtual switch that excludes
    other guests' traffic unless the port is configured to mirror it, so
    watching a VM boot from its Hyper-V host does not work out of the box the
    way watching one boot from its Linux bridge host does.

    Say that plainly rather than letting the shared function name imply the
    two are equivalent: this backend is right for DHCP traffic this host's own
    segment carries, and the Linux one is right for a bridge.

Note:
    A raw socket delivers the IPv4 header and everything after it, with no
    link-layer header at all. ``bootp`` already accepts that shape, detecting
    it from the data rather than from ``sys.platform``, so nothing here has to
    fabricate an Ethernet header to keep the codec happy.

"""

from __future__ import annotations

import contextlib
import ipaddress
import socket
from typing import TYPE_CHECKING, cast

from .errors import IPScoutPermissionError, IPScoutUnsupportedError

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["RCVALL_OFF", "RCVALL_ON", "SIO_RCVALL", "RawSocketCapture", "capture_available", "open_capture"]

#: ``SIO_RCVALL`` from mstcpip.h, which is ``_WSAIOW(IOC_VENDOR, 1)``. Spelled
#: as the resolved constant because the macro's inputs are not exposed by the
#: socket module, and pinned by a test so a mistyped digit cannot pass review.
SIO_RCVALL = 0x98000001

#: Its arguments. ``RCVALL_ON`` takes every IPv4 packet the interface sees;
#: ``RCVALL_SOCKETLEVELONLY`` is deliberately unused, since it does not do what
#: its name suggests and is not supported on all stacks.
RCVALL_OFF = 0
RCVALL_ON = 1

#: An IPv4 packet cannot exceed this, so nothing is ever read in halves.
_RECEIVE_SIZE = 65535

#: Asked for, not required, and clamped by the stack. A cushion against a
#: burst arriving between two reads, never a correctness dependency.
_RECEIVE_BUFFER = 1 << 20


def _ioctl_of(sock: socket.socket) -> Callable[[int, int], object] | None:
    """Return the socket's ``ioctl``, or None where the platform has none.

    A typed facade rather than a suppression: ``socket.ioctl`` exists only on
    Windows, so its absence is a real answer this module has to give on the
    platforms that run its tests.
    """

    return cast("Callable[[int, int], object] | None", getattr(sock, "ioctl", None))


def _permission_error(exc: OSError) -> IPScoutPermissionError:
    """Return the error naming the privilege a capture needs, and the remedy."""

    return IPScoutPermissionError(
        f"capturing DHCP on Windows needs a raw socket in promiscuous mode, so Administrator: {exc}. "
        f"Run the process elevated. There is no unprivileged way to watch somebody else's traffic; "
        f"subnet_info() reads this host's own lease without any privilege, but it only describes this host"
    )


def capture_available() -> bool:
    """Return whether a promiscuous capture can be opened right now.

    Returns:
        Whether this process holds the privilege. Opens a raw socket and
        immediately closes it, which is the only honest way to ask: the answer
        depends on the process token rather than on the platform.

    Note:
        Deliberately does NOT run the ``SIO_RCVALL`` ioctl. That needs a bound
        interface address, and picking one here would make a capability
        question do interface discovery and possibly answer "no" because this
        host has no usable address rather than because it lacks the right.

    Examples:
        >>> isinstance(capture_available(), bool)
        True

    """

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except OSError:
        return False
    available = _ioctl_of(sock) is not None
    sock.close()
    return available


def _address_for(interface: str) -> str:
    """Return the IPv4 address to bind, from an address or an adapter name.

    ``SIO_RCVALL`` binds to an address rather than to a device, but the public
    argument is called ``interface`` on every platform. Accepting both keeps
    one spelling working across Linux and Windows for the common case of a
    caller that knows its adapter by name.
    """

    with contextlib.suppress(ValueError):
        if ipaddress.ip_address(interface).version == 4:  # noqa: PLR2004 - IPv4, and DHCPv4 is IPv4 only
            return interface

    from .interfaces_windows import list_interfaces  # noqa: PLC0415 - Windows-only import

    candidates = [found for found in list_interfaces() if found.name == interface and found.ipv4]
    if not candidates:
        known = ", ".join(sorted(found.name for found in list_interfaces() if found.ipv4)) or "none with an IPv4 address"
        msg = f"no interface named {interface!r} with an IPv4 address to bind; SIO_RCVALL binds to an address, not a device. Available: {known}"
        raise IPScoutUnsupportedError(msg)
    return candidates[0].ipv4[0].address


class RawSocketCapture:
    """A promiscuous capture of the IPv4 traffic reaching one address.

    Delivers whole IPv4 packets, header included, with no link-layer header.
    """

    def __init__(self, sock: socket.socket, *, address: str, promiscuous: bool) -> None:
        self._socket = sock
        self._address = address
        self._promiscuous = promiscuous
        self._closed = False

    @property
    def address(self) -> str:
        """The local address this capture is bound to."""

        return self._address

    def receive(self, *, timeout: float) -> bytes | None:
        """Return the next packet, or None when none arrived in ``timeout``."""

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
        """Turn promiscuous mode off, then release the socket."""

        self._closed = True
        # Closing the socket ends the capture on its own, but asking for it
        # explicitly means the interface is not left promiscuous for however
        # long the stack takes to notice the handle went away.
        if self._promiscuous:
            ioctl = _ioctl_of(self._socket)
            if ioctl is not None:
                with contextlib.suppress(OSError):
                    ioctl(SIO_RCVALL, RCVALL_OFF)
        with contextlib.suppress(OSError):
            self._socket.close()

    def __enter__(self) -> RawSocketCapture:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        del exc_type, exc, tb
        self.close()


def open_capture(interface: str, *, promiscuous: bool = True) -> RawSocketCapture:
    """Open a promiscuous capture of the IPv4 traffic reaching one interface.

    Args:
        interface: An adapter name, or the IPv4 address to bind directly.
            ``SIO_RCVALL`` works on an address, so a name is resolved to the
            first IPv4 address that adapter holds.
        promiscuous: Whether to ask for ``SIO_RCVALL``. Turning it off leaves
            an ordinary raw socket that sees only traffic addressed to this
            host, which for DHCP means broadcast replies alone.

    Returns:
        The capture, ready to read.

    Raises:
        IPScoutPermissionError: The process is not elevated.
        IPScoutUnsupportedError: This platform has no ``socket.ioctl``, or no
            such interface holds an IPv4 address.

    """

    address = _address_for(interface)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except OSError as exc:
        raise _permission_error(exc) from exc

    ioctl = _ioctl_of(sock)
    if ioctl is None:  # pragma: no cover - non-Windows
        sock.close()
        msg = "SIO_RCVALL needs socket.ioctl, which exists only on Windows"
        raise IPScoutUnsupportedError(msg)

    try:
        # Bind first: SIO_RCVALL is refused on an unbound socket, and binding
        # to a specific address is what selects the interface to watch.
        sock.bind((address, 0))
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RECEIVE_BUFFER)
        if promiscuous:
            ioctl(SIO_RCVALL, RCVALL_ON)
    except PermissionError as exc:
        sock.close()
        raise _permission_error(exc) from exc
    except OSError as exc:
        sock.close()
        msg = f"cannot capture on {address!r}: {exc}. Name an interface that exists and holds an IPv4 address; local_interfaces() lists them"
        raise IPScoutUnsupportedError(msg) from exc

    return RawSocketCapture(sock, address=address, promiscuous=promiscuous)
