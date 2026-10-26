"""The macOS capture backend, asserted from any platform where possible.

The unprivileged CI lanes cannot open a BPF device - measured, ``/dev/bpf0`` is
refused with EACCES on every macos-latest lane - so the device path runs only in
the root-only ``host_mutating`` tests (``test_dhcp_macos_live.py``,
``test_dhcp_macos_bridge_live.py``). Everything that does NOT need the device is
pinned here instead, on every platform: the ioctl encoding against the numbers
in ``<net/bpf.h>``, the record splitting against hand-built buffers, and the
refusals.
"""

from __future__ import annotations

import struct
import sys

import pytest

from ipscout.bpf import (
    BIOCGBLEN,
    BIOCGDLT,
    BIOCIMMEDIATE,
    BIOCPROMISC,
    BIOCSETIF,
    BIOCSHDRCMPLT,
    DLT_EN10MB,
    BpfDevice,
    iter_bpf_frames,
)
from ipscout.dhcp_macos import bridge_refusal, capture_available, open_capture
from ipscout.errors import IPScoutPermissionError, IPScoutUnsupportedError

pytestmark = pytest.mark.os_agnostic

#: struct bpf_hdr, as the kernel writes it: timeval, caplen, datalen, hdrlen.
_BPF_HDR = struct.Struct("=iiIIH")


def _bpf_record(payload: bytes) -> bytes:
    """Build one BPF record the way a device would, alignment included."""

    header = _BPF_HDR.pack(0, 0, len(payload), len(payload), _BPF_HDR.size)
    record = header + payload
    return record + b"\x00" * (-len(record) % 4)


# --------------------------------------------------------------------------
# The ioctl encoding, pinned against <net/bpf.h>
# --------------------------------------------------------------------------


def test_the_ioctl_numbers_are_the_ones_the_bsd_header_defines() -> None:
    # Spelled as arithmetic in the source, so a wrong direction bit or width
    # would otherwise only surface on a Mac nobody here has.
    assert BIOCGBLEN == 0x40044266, "_IOR('B', 102, u_int)"
    assert BIOCGDLT == 0x4004426A, "_IOR('B', 106, u_int)"
    assert BIOCSETIF == 0x8020426C, "_IOW('B', 108, struct ifreq)"
    assert BIOCIMMEDIATE == 0x80044270, "_IOW('B', 112, u_int)"
    assert BIOCSHDRCMPLT == 0x80044275, "_IOW('B', 117, u_int)"


def test_the_promiscuous_request_carries_no_argument() -> None:
    # BIOCPROMISC is _IO('B', 105), not _IOW: it takes nothing, and encoding it
    # with a width would make the kernel refuse the call. This is the one
    # request in the set whose shape differs, so it gets its own assertion.
    assert BIOCPROMISC == 0x20004269
    assert BIOCPROMISC & 0x1FFF0000 == 0, "an argument width would be wrong here"


def test_ethernet_is_the_link_type_the_codec_expects() -> None:
    assert DLT_EN10MB == 1


# --------------------------------------------------------------------------
# The record open_bpf_device returns
# --------------------------------------------------------------------------


def test_the_opened_device_names_its_fields_and_is_still_a_pair() -> None:
    # Built directly: opening a real device needs root on a Mac. Both fields
    # are bare ints, so a caller relying on order could swap them silently;
    # the names are the contract, and the tuple shape keeps old unpacking
    # callers working.
    device = BpfDevice(descriptor=7, buffer_length=4096)

    assert BpfDevice._fields == ("descriptor", "buffer_length")
    assert isinstance(device, tuple)
    descriptor, buffer_length = device
    assert (descriptor, buffer_length) == (device.descriptor, device.buffer_length) == (7, 4096)


# --------------------------------------------------------------------------
# Record splitting: one read carries several frames
# --------------------------------------------------------------------------


def test_a_read_holding_several_frames_yields_all_of_them() -> None:
    # The reason the capture buffers: a DHCP exchange arrives in a burst, so a
    # backend that returned only the first frame of a read would drop exactly
    # the reply being waited for.
    buffer = _bpf_record(b"first frame") + _bpf_record(b"second") + _bpf_record(b"third!")

    assert iter_bpf_frames(buffer) == [b"first frame", b"second", b"third!"]


def test_records_are_word_aligned_not_merely_concatenated() -> None:
    # A 5-byte payload pads to a 4-byte boundary. Assuming header+caplen would
    # start the next record mid-padding and decode garbage.
    buffer = _bpf_record(b"12345") + _bpf_record(b"next")

    assert iter_bpf_frames(buffer) == [b"12345", b"next"]


@pytest.mark.parametrize("cut", [1, 5, 12, 17, 20])
def test_a_truncated_read_stops_rather_than_raising(cut: int) -> None:
    buffer = _bpf_record(b"a frame that got cut")

    assert isinstance(iter_bpf_frames(buffer[:cut]), list)


def test_a_zero_length_record_ends_the_walk_instead_of_looping() -> None:
    # caplen 0 would not advance the cursor, so it must terminate the scan.
    buffer = _BPF_HDR.pack(0, 0, 0, 0, _BPF_HDR.size) + b"\x00" * 8

    assert iter_bpf_frames(buffer) == []


def test_a_header_claiming_more_than_the_buffer_holds_is_refused() -> None:
    buffer = _BPF_HDR.pack(0, 0, 9999, 9999, _BPF_HDR.size) + b"short"

    assert iter_bpf_frames(buffer) == []


# --------------------------------------------------------------------------
# What this platform answers
# --------------------------------------------------------------------------


def test_the_module_imports_and_answers_on_every_platform() -> None:
    # It has to import cleanly off macOS, or the assertions above could not run
    # and the facade could not dispatch to it.
    assert isinstance(capture_available(), bool)


@pytest.mark.skipif(sys.platform == "darwin", reason="a Mac may genuinely have /dev/bpf0")
def test_a_platform_without_bpf_devices_reports_no_capability() -> None:
    assert capture_available() is False


@pytest.mark.os_macos
@pytest.mark.skipif(sys.platform != "darwin", reason="the BPF device path is macOS-only")
def test_a_real_capture_opens_or_refuses_with_the_remedy_named() -> None:
    # Unproven anywhere in CI: no runner may open a BPF device. Kept so that
    # somebody with a Mac gets a real signal rather than a silent skip.
    if not capture_available():
        with pytest.raises(IPScoutPermissionError, match=r"sudo|root"):
            open_capture("en0")
        return
    with open_capture("en0") as capture:
        assert capture.interface == "en0"
        capture.receive(timeout=0.2)


@pytest.mark.os_macos
@pytest.mark.skipif(sys.platform != "darwin", reason="the BPF device path is macOS-only")
def test_loopback_is_refused_because_it_is_not_ethernet_framed() -> None:
    # lo0 reports DLT_NULL, which prefixes a protocol family rather than an
    # Ethernet header, so reading it as Ethernet would decode the wrong bytes
    # rather than nothing. It is refused by its link type, not by its name.
    if not capture_available():
        pytest.skip("cannot open a BPF device here")
    with pytest.raises(IPScoutUnsupportedError, match="not Ethernet"):
        open_capture("lo0")


# --------------------------------------------------------------------------
# A bridge: macOS never shows it the frames it forwards to a guest
# --------------------------------------------------------------------------
# Measured on a macos-latest runner with a real macOS DHCP client behind a bridge of feth
# members: BPF on the bridge saw nothing without a bridge address, and with one only the frames
# delivered to this host (broadcasts) - never a reply unicast to the guest - while both member
# ports saw the whole exchange. An empty list there would read as "the machine never asked".


@pytest.mark.parametrize("name", ["bridge0", "bridge100"])
def test_a_bridge_is_refused_with_the_member_port_named_as_the_remedy(name: str) -> None:
    with pytest.raises(IPScoutUnsupportedError, match="member port") as caught:
        open_capture(name)
    assert name in str(caught.value)


@pytest.mark.parametrize("name", ["en0", "feth740", "vmenet0", "bridge", "bridgeX", "mybridge0", "bridge0x"])
def test_only_a_macos_bridge_name_is_refused_as_a_bridge(name: str) -> None:
    assert bridge_refusal(name) is None
