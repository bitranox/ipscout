"""Link-layer capture of one interface on macOS, through the BSD packet filter.

Contents:
    open_capture: A capture of one interface, satisfying ``PacketCapture``.
    capture_available: Whether a capture could be opened at all.

macOS has no ``AF_PACKET``. What it has is ``/dev/bpf``, the same facility
``tcpdump`` uses, which this package already opens to resolve neighbours
actively. A device is claimed, bound to an interface, and read; the plumbing
lives in ``bpf`` because two backends now need it.

Note:
    **A BPF read returns SEVERAL frames at once**, packed with per-record
    headers and 4-byte alignment, while a capture hands back one frame at a
    time. The extras are held here and handed out on later calls rather than
    dropped - dropping them would silently lose exactly the reply being waited
    for, since a DHCP exchange arrives in a burst.

    **A bridge is refused; watch the guest's member port.** A BPF device bound
    to a macOS bridge sees only frames delivered to this host, never what the
    bridge forwards between its members - unlike a Linux packet socket on a
    bridge. Measured with a real macOS DHCP client behind a bridge: the bridge
    showed nothing without an address of its own, and with one only
    broadcasts, never a reply unicast to the guest, while the guest's member
    port showed the whole exchange. See ``bridge_refusal``.

    **Promiscuous mode is asked for by default**, for the reason it is on
    Linux: a reply is often unicast to the guest's own hardware address, which
    is not the address of the interface watched, and a Linux client does not
    set the broadcast flag that would make it visible otherwise.
    ``BIOCPROMISC`` takes no argument, so passing one makes the kernel refuse
    it.

    **Only an Ethernet link type is accepted.** A BPF device reports its
    framing through ``BIOCGDLT``; loopback uses ``DLT_NULL``, which prefixes a
    four-byte protocol family rather than an Ethernet header. A codec written
    for Ethernet would read the wrong bytes rather than none, so a foreign
    link type is refused instead of quietly returning nothing.

Verification status:
    The encoding and the record splitting are asserted from any platform, and
    the ioctl numbers are pinned against the values in ``<net/bpf.h>``. The
    unprivileged CI lanes cannot open a BPF device (measured: ``/dev/bpf0``
    refused with EACCES on macos-latest). As root on a macOS 26 runner VM:
    ``tests/test_dhcp_macos_live.py`` captures offers written onto a ``feth``
    pair, and ``tests/test_dhcp_macos_bridge_live.py`` watches a real macOS
    DHCP client's handshake from its member port of a bridge, through to the
    client binding the offered address. Not yet run on physical hardware.

"""

from __future__ import annotations

import contextlib
import os
import re
import select
import struct
import sys
from collections import deque

from .bpf import BIOCGDLT, DLT_EN10MB, MAX_BPF_DEVICES, iter_bpf_frames, open_bpf_device
from .deadline import blocking_wait
from .errors import IPScoutPermissionError, IPScoutUnsupportedError
from .unixio import fcntl_module

__all__ = ["BpfCapture", "bridge_refusal", "capture_available", "open_capture"]

#: How macOS names a bridge interface (``ifconfig bridge create`` answers ``bridge0``).
_BRIDGE_NAME = re.compile(r"bridge[0-9]+")


def _require_bpf() -> None:
    """Refuse before touching a device where the platform has no BPF at all.

    The mirror of ``unixio.packet_family``: a backend guards its own platform
    facility with this package's error rather than letting a foreign one
    escape. Without it the first call reaches ``fcntl``, which does not exist
    off Unix, and a ``ModuleNotFoundError`` leaves the package's promise that
    every failure is an ``IPScoutError`` untrue for exactly this path.
    """

    if not sys.platform.startswith(("darwin", "freebsd", "openbsd", "netbsd")):  # pragma: no cover - non-BSD
        msg = f"the BPF devices are a BSD facility and this process is on {sys.platform!r}"
        raise IPScoutUnsupportedError(msg)


def bridge_refusal(interface: str) -> str | None:
    """Return why a capture on this interface would miss a guest's handshake, or None.

    A BPF device bound to a macOS bridge sees only frames delivered to this
    host, never what the bridge forwards between its members. Measured with a
    real macOS DHCP client behind a bridge of ``feth`` members: without a
    bridge address the bridge showed nothing, with one only broadcasts, and a
    reply unicast to the guest never; both member ports showed the whole
    exchange. Returning an empty list there would read as "the machine never
    asked", so the capture refuses instead. macOS names every bridge
    ``bridge<N>``, which is what is matched.

    Args:
        interface: The interface a caller asked to watch.

    Returns:
        The refusal message for a bridge, or None for anything else.

    Examples:
        >>> bridge_refusal("en0") is None
        True
        >>> "member port" in bridge_refusal("bridge100")
        True

    """

    if _BRIDGE_NAME.fullmatch(interface) is None:
        return None
    return (
        f"{interface!r} is a bridge, and macOS shows a capture on a bridge only the frames delivered to this "
        f"host - never the replies the bridge forwards to a guest - so it would report a machine that did ask "
        f"for an address as one that never did. Watch the guest's own member port instead: "
        f"'ifconfig {interface}' lists the members"
    )


def _permission_error(exc: OSError) -> IPScoutPermissionError:
    """Return the error naming the privilege a capture needs, and the remedy."""

    return IPScoutPermissionError(
        f"capturing DHCP on macOS needs read access to a BPF device, so root: {exc}. "
        f"Run the process with sudo, or grant the BPF devices to your group - some setups ship a "
        f"'Wireshark' helper that does exactly that. There is no unprivileged way to watch somebody "
        f"else's traffic; subnet_info() reads this host's own lease without any privilege, but it "
        f"only describes this host"
    )


def capture_available() -> bool:
    """Return whether a BPF device can be opened right now.

    Returns:
        Whether the privilege is present. Opens and immediately closes a
        device, which is the only honest way to ask: access to ``/dev/bpf*``
        is a filesystem permission that varies per machine, not something the
        platform name settles. Devices are tried the way a capture claims
        one: a busy or missing device moves on to the next, while a refused
        one (EACCES, EPERM) answers False at once, because every device in
        the pool carries the same permission.

    Examples:
        >>> isinstance(capture_available(), bool)
        True

    """

    # The same fixed pool, in the same order, that open_bpf_device walks when it
    # claims one, so the answer here is the one a real capture would get. A busy
    # device belongs to another process and says nothing about this one's privilege.
    for number in range(MAX_BPF_DEVICES):
        try:
            descriptor = os.open(f"/dev/bpf{number}", os.O_RDWR)
        except PermissionError:
            return False
        except OSError:
            # EBUSY: another process holds this one, so try the next.
            continue
        os.close(descriptor)
        return True
    return False


class BpfCapture:
    """A capture of one interface, reading whole Ethernet frames.

    Holds the surplus of each read, because one read yields several frames.
    """

    def __init__(self, descriptor: int, *, buffer_length: int, interface: str) -> None:
        self._descriptor = descriptor
        self._buffer_length = buffer_length
        self._interface = interface
        self._pending: deque[bytes] = deque()
        self._closed = False

    @property
    def interface(self) -> str:
        """The interface being captured."""

        return self._interface

    def receive(self, *, timeout: float) -> bytes | None:
        """Return the next frame, or None when none arrived in ``timeout``."""

        if self._pending:
            return self._pending.popleft()
        try:
            readable, _writable, _failed = select.select([self._descriptor], [], [], blocking_wait(timeout))
            if not readable:
                return None
            # The read size must be exactly the kernel's buffer length; a
            # shorter one is refused outright rather than returning less.
            chunk = os.read(self._descriptor, self._buffer_length)
        except OSError:
            if self._closed:
                # Closed underneath a blocked read during teardown. That is a
                # stop, not a failure, and must not surface as one.
                return None
            raise
        self._pending.extend(iter_bpf_frames(chunk))
        return self._pending.popleft() if self._pending else None

    def close(self) -> None:
        """Release the device. Promiscuous mode ends with the descriptor."""

        self._closed = True
        self._pending.clear()
        with contextlib.suppress(OSError):
            os.close(self._descriptor)

    def __enter__(self) -> BpfCapture:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        del exc_type, exc, tb
        self.close()


def open_capture(interface: str, *, promiscuous: bool = True) -> BpfCapture:
    """Open a capture of one interface through a BPF device.

    Args:
        interface: The interface to watch: a physical interface, or for a
            virtual machine the guest's own member port of its bridge (for
            example its ``vmenet`` or ``feth`` interface), never the bridge.
        promiscuous: Whether to ask for promiscuous mode. Leaving it on is
            almost always right; see this module's docstring for what turning
            it off stops you seeing.

    Returns:
        The capture, ready to read.

    Raises:
        IPScoutPermissionError: The process may not open a BPF device.
        IPScoutUnsupportedError: The interface is a bridge (see
            ``bridge_refusal``), there is no such interface, or it does not
            deliver Ethernet frames.

    """

    refusal = bridge_refusal(interface)
    if refusal is not None:
        raise IPScoutUnsupportedError(refusal)
    _require_bpf()
    try:
        descriptor, buffer_length = open_bpf_device(interface, promiscuous=promiscuous, complete_headers=False)
    except PermissionError as exc:
        raise _permission_error(exc) from exc
    except OSError as exc:
        msg = f"cannot capture on {interface!r}: {exc}. Name an interface that exists; local_interfaces() lists them"
        raise IPScoutUnsupportedError(msg) from exc

    link_type = _link_type(descriptor)
    if link_type != DLT_EN10MB:
        os.close(descriptor)
        msg = (
            f"{interface!r} reports link type {link_type}, not Ethernet ({DLT_EN10MB}). Frames there are not "
            f"Ethernet-framed - loopback prefixes a protocol family instead - so reading them as Ethernet would "
            f"decode the wrong bytes. Name the physical interface or the guest's member port the traffic is on"
        )
        raise IPScoutUnsupportedError(msg)

    return BpfCapture(descriptor, buffer_length=buffer_length, interface=interface)


def _link_type(descriptor: int) -> int:
    """Return the BPF device's link type, or -1 when it will not say."""

    try:
        packed = fcntl_module().ioctl(descriptor, BIOCGDLT, struct.pack("=I", 0))
    except OSError:  # pragma: no cover - macOS only
        return -1
    return int(struct.unpack("=I", packed)[0])
