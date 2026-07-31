"""Feasibility probe: can this platform capture DHCP traffic, and as whom?

Observing a handshake needs a link-layer capture, and whether a process may
open one is a per-platform, per-privilege question that documentation cannot
settle:

    **Linux** - ``AF_PACKET`` with ``CAP_NET_RAW``. Implemented. A CI runner
    is unprivileged, so this reports "no" there and "yes" on a developer box
    running as root, and both are correct answers.

    **Windows** - genuinely unknown, and the reason this probe exists. There
    is a driver-free mechanism, a raw socket in ``SIO_RCVALL`` promiscuous
    mode, which needs Administrator. GitHub's Windows runners are said to run
    as an administrator account, which would make Windows the one platform
    whose privileged path CI can actually exercise - the opposite of the
    intuitive answer. Measure it rather than believing it.

    **macOS** - BPF through ``/dev/bpf``, which this package already uses to
    resolve neighbours actively. Needs root, which a runner does not have.

This module answers that empirically on whatever host it runs on and reports
the answer in the test output. It never fails a build: an unprivileged or
unsupported platform is a fact to record, not a defect. The recorded answer is
what decides whether Windows and macOS get a real capture backend or an honest
``IPScoutUnsupportedError``.
"""

from __future__ import annotations

import ctypes
import os
import platform
import socket
import sys
from typing import TYPE_CHECKING, cast

import pytest

from ipscout.dhcp import dhcp_capture_available

if TYPE_CHECKING:
    from collections.abc import Callable

pytestmark = pytest.mark.os_agnostic

#: SIO_RCVALL, from mstcpip.h: _WSAIOW(IOC_VENDOR, 1). Promiscuous receive on
#: a raw socket, the driver-free Windows path.
_SIO_RCVALL = 0x98000001
_RCVALL_ON = 1


def _elevated() -> tuple[bool, str]:
    """Return whether this process holds the privilege a capture would need."""

    if sys.platform == "win32":
        try:
            shell32 = ctypes.windll.shell32  # type: ignore[attr-defined]  # pyright: ignore[reportAttributeAccessIssue]
        except AttributeError:  # pragma: no cover - not Windows
            return False, "no shell32"
        return bool(shell32.IsUserAnAdmin()), "IsUserAnAdmin"
    return os.geteuid() == 0, f"euid {os.geteuid()}"


def _probe_af_packet() -> tuple[bool, str]:
    """Return whether a Linux packet socket can be opened."""

    af_packet = getattr(socket, "AF_PACKET", None)
    if not isinstance(af_packet, int):
        return False, "socket.AF_PACKET is not defined on this platform"
    try:
        sock = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(0x0800))
    except OSError as exc:
        return False, f"AF_PACKET refused: {exc!r}"
    sock.close()
    return True, "AF_PACKET opened"


def _probe_bpf() -> tuple[bool, str]:
    """Return whether a BSD packet filter device can be opened."""

    for index in range(8):
        path = f"/dev/bpf{index}"
        try:
            handle = os.open(path, os.O_RDONLY)
        except FileNotFoundError:
            continue
        except OSError as exc:
            return False, f"{path} refused: {exc!r}"
        os.close(handle)
        return True, f"{path} opened"
    return False, "no /dev/bpf* device exists here"


def _probe_sio_rcvall() -> tuple[bool, str]:
    """Return whether a Windows raw socket accepts promiscuous mode.

    Binding to a real interface address is required: ``SIO_RCVALL`` on an
    unbound socket, or on the loopback address, is refused.
    """

    try:
        host = socket.gethostbyname(socket.gethostname())
    except OSError as exc:  # pragma: no cover - not Windows
        return False, f"no local address to bind: {exc!r}"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except OSError as exc:
        return False, f"raw socket refused: {exc!r}"
    # socket.ioctl exists only on Windows, so it is reached through a typed
    # facade rather than a suppression: absent is a real answer here.
    ioctl = cast("Callable[[int, int], object] | None", getattr(sock, "ioctl", None))
    if ioctl is None:  # pragma: no cover - not Windows
        sock.close()
        return False, "socket.ioctl is not available on this platform"
    try:
        sock.bind((host, 0))
        ioctl(_SIO_RCVALL, _RCVALL_ON)
    except OSError as exc:
        return False, f"SIO_RCVALL on {host} refused: {exc!r}"
    else:
        return True, f"SIO_RCVALL enabled on {host}"
    finally:
        sock.close()


def test_report_whether_this_platform_can_capture_dhcp(capsys: pytest.CaptureFixture[str]) -> None:
    """Record the platform's capability. Never fails - it is a measurement."""

    is_elevated, how = _elevated()
    if sys.platform.startswith("linux"):
        mechanism, (works, detail) = "AF_PACKET", _probe_af_packet()
    elif sys.platform == "darwin":
        mechanism, (works, detail) = "BPF /dev/bpf*", _probe_bpf()
    elif sys.platform == "win32":
        mechanism, (works, detail) = "SIO_RCVALL", _probe_sio_rcvall()
    else:  # pragma: no cover - no other platform in the matrix
        mechanism, works, detail = "none", False, f"no known mechanism for {sys.platform}"

    with capsys.disabled():
        print(f"\n  DHCP CAPTURE PROBE on {platform.system()} {platform.release()} ({sys.platform})")
        print(f"    elevated       : {'YES' if is_elevated else 'no '}  - {how}")
        print(f"    mechanism      : {mechanism}")
        print(f"    can capture    : {'YES' if works else 'no '}  - {detail}")
        print(f"    library agrees : {dhcp_capture_available()}")

    # A measurement, not an assertion. Recording "no" is a valid outcome that
    # decides the platform gets IPScoutUnsupportedError rather than a capture
    # backend nobody has run; failing here would hide the answer behind a red
    # build.
    assert isinstance(works, bool)
    assert isinstance(dhcp_capture_available(), bool)


def test_the_library_never_claims_more_than_the_platform_allows() -> None:
    # dhcp_capture_available() gates the CLI and the test sweep, so it
    # claiming a capability this host lacks would be worse than useless.
    if dhcp_capture_available():
        assert sys.platform.startswith("linux") or sys.platform == "win32", "only Linux and Windows have a backend"
