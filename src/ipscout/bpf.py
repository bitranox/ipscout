"""The BSD packet filter: ioctl encoding and record splitting, no I/O.

Contents:
    iter_bpf_frames: Split one BPF read into the frames it holds.
    open_bpf_device: Claim a free /dev/bpf and bind it to an interface.
    BIOCGBLEN, BIOCSETIF, BIOCIMMEDIATE, BIOCSHDRCMPLT, BIOCPROMISC, BIOCGDLT.

Note:
    This lives in one place rather than in each backend that needs it, for the
    reason ``unixio`` records: the first version was written into the macOS
    neighbour backend, and the next caller re-derived it. The DHCP capture is
    that next caller, so the plumbing moved here rather than being copied.

    Everything except :func:`open_bpf_device` is arithmetic over integers and
    slicing over bytes, so the encoding is asserted from any platform - which
    matters more than usual here, because no CI runner is privileged enough to
    open a BPF device and prove it on the real thing.

"""

from __future__ import annotations

import os
import struct

from .unixio import fcntl_module

__all__ = [
    "BIOCGBLEN",
    "BIOCGDLT",
    "BIOCIMMEDIATE",
    "BIOCPROMISC",
    "BIOCSETIF",
    "BIOCSHDRCMPLT",
    "DLT_EN10MB",
    "iter_bpf_frames",
    "open_bpf_device",
]

#: ioctl direction bits and the field widths they encode, from <sys/ioccom.h>.
#: A request with no argument carries IOC_VOID and a size of zero, which is why
#: BIOCPROMISC is encoded differently from every other request here.
_IOC_VOID = 0x20000000
_IOC_WRITE = 0x80000000
_IOC_READ = 0x40000000
_IOCPARM_MASK = 0x1FFF
_BPF_GROUP = ord("B")

#: sizeof(struct ifreq) on macOS: a 16-byte name plus a 16-byte union.
_IFREQ_SIZE = 32
_UINT_SIZE = 4

#: struct bpf_hdr: a 32-bit timeval, captured and original lengths, then the
#: header length, which is what says where the frame actually starts.
_BPF_HDR = struct.Struct("=iiIIH")

#: How many /dev/bpf devices to try before giving up. They are a fixed pool
#: and a busy one simply belongs to another process.
_MAX_BPF_DEVICES = 64

#: The link type that yields Ethernet frames. Anything else - loopback's
#: DLT_NULL, for one - frames its packets differently, so a codec written for
#: Ethernet would read the wrong bytes rather than nothing.
DLT_EN10MB = 1


def _io(number: int) -> int:
    """Return the ioctl number for a request that takes no argument."""

    return _IOC_VOID | (_BPF_GROUP << 8) | number


def _iow(number: int, size: int) -> int:
    """Return the ioctl number for a write-direction request."""

    return _IOC_WRITE | ((size & _IOCPARM_MASK) << 16) | (_BPF_GROUP << 8) | number


def _ior(number: int, size: int) -> int:
    """Return the ioctl number for a read-direction request."""

    return _IOC_READ | ((size & _IOCPARM_MASK) << 16) | (_BPF_GROUP << 8) | number


BIOCGBLEN = _ior(102, _UINT_SIZE)
BIOCGDLT = _ior(106, _UINT_SIZE)
BIOCPROMISC = _io(105)
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


def open_bpf_device(interface: str, *, promiscuous: bool = False, complete_headers: bool = True) -> tuple[int, int]:
    """Claim a free BPF device bound to one interface.

    Args:
        interface: The interface to bind to.
        promiscuous: Ask the interface to accept frames addressed elsewhere.
            Needed to watch another machine's traffic; a capture that only
            wants this host's own does not set it.
        complete_headers: Say that frames written are complete, so the kernel
            does not fill in a source address of its own. Only meaningful for
            a caller that writes; a read-only capture can leave it off.

    Returns:
        The descriptor and the kernel's buffer length, which is the size every
        read must use - a shorter read is refused outright.

    Raises:
        OSError: No device could be claimed, or a request was refused. The
            caller turns this into whichever error names its own remedy.

    Note:
        ``BIOCIMMEDIATE`` is not optional. Without it a read blocks until the
        kernel buffer fills, so a lone exchange sits invisible for the whole
        window - the same class of trap as an unbuffered ``tcpdump`` without
        ``-l``.

    """

    fcntl = fcntl_module()
    last: OSError | None = None
    for number in range(_MAX_BPF_DEVICES):
        try:
            descriptor = os.open(f"/dev/bpf{number}", os.O_RDWR)
        except PermissionError:
            raise
        except OSError as exc:
            # EBUSY simply means another process holds that one.
            last = exc
            continue

        try:
            name = interface.encode()[:15].ljust(_IFREQ_SIZE, b"\x00")
            fcntl.ioctl(descriptor, BIOCSETIF, name)
            fcntl.ioctl(descriptor, BIOCIMMEDIATE, struct.pack("=I", 1))
            if complete_headers:
                fcntl.ioctl(descriptor, BIOCSHDRCMPLT, struct.pack("=I", 1))
            if promiscuous:
                # No argument: BIOCPROMISC is an IOC_VOID request, and passing
                # one makes the kernel refuse it.
                fcntl.ioctl(descriptor, BIOCPROMISC)
            length = struct.unpack("=I", fcntl.ioctl(descriptor, BIOCGBLEN, struct.pack("=I", 0)))[0]
        except OSError:
            os.close(descriptor)
            raise
        return descriptor, int(length)

    raise last or OSError("no BPF device could be opened")
