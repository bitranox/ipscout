"""A real guest VM's DHCP handshake behind a macOS bridge, watched on its member port, as root.

The guest is QEMU on ``vmnet-shared``: macOS creates ``bridge100``, adds the guest's ``vmenetN``
port to it as a member and answers DHCP itself (bootpd), which is how UTM-style hosts network a
VM. The guest needs no disk image: started paused, it is resumed only once the capture is
listening, and its network boot ROM (``-boot n``) asks for an address at once.

Measured first on GitHub's macOS runners (Intel with ``-accel hvf``, Apple Silicon with
``-accel tcg``): ``tcpdump`` on the member port saw the guest's requests and bootpd's replies,
and the capture on that port returned the address the guest was given. Runs only on macOS as
root with ``qemu-system-x86_64`` installed, opted in with ``IPSCOUT_HOST_WRITE_TESTS=1`` - see
``tests/conftest.py``.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import ipscout
from ipscout.errors import IPScoutUnsupportedError

if TYPE_CHECKING:
    from collections.abc import Iterator

_GUEST_MAC = "00:00:5e:00:53:10"
_BRIDGE = "bridge100"
_LEASES = Path("/var/db/dhcpd_leases")
_QEMU = "qemu-system-x86_64"


def _is_root() -> bool:
    """Return whether this POSIX process is root; guarded so the Windows type check sees no geteuid."""

    if sys.platform == "win32":
        return False
    return os.geteuid() == 0


def _tool(name: str, *args: str) -> str:
    path = shutil.which(name) or f"/sbin/{name}"
    result = subprocess.run([path, *args], check=False, capture_output=True, encoding="utf-8", errors="replace")  # noqa: S603 - fixed argv, no shell
    return result.stdout


def _accelerator() -> str:
    # Apple Silicon runners refuse hvf (HV_UNSUPPORTED); emulation is fast enough for a boot ROM.
    return "hvf" if _tool("sysctl", "-n", "kern.hv_support").strip() == "1" else "tcg"


def _member(*, wait: float) -> str:
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        match = re.search(r"member: (\S+)", _tool("ifconfig", _BRIDGE))
        if match:
            return match.group(1)
        time.sleep(0.5)
    return ""


def _monitor(path: Path, command: str) -> None:
    if sys.platform == "win32":
        # Typeshed declares no AF_UNIX for Windows; this branch is what lets the Windows type
        # check see the rest as unreachable. The module never runs there (macOS skipif below).
        raise RuntimeError("the QEMU monitor socket is only driven on macOS")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(str(path))
        sock.sendall(command.encode("ascii") + b"\n")


def _leased_address(mac: str, *, since: float) -> str:
    """The address bootpd recorded for ``mac`` (written without leading zeros) in a lease file written after ``since``.

    A lease left by an earlier run for the same hardware address would otherwise pass for
    this handshake.
    """

    if not _LEASES.exists() or _LEASES.stat().st_mtime < since:
        return ""
    wanted = ":".join(f"{int(part, 16):x}" for part in mac.split(":"))
    for block in _LEASES.read_text(encoding="utf-8", errors="replace").split("}"):
        if f"hw_address=1,{wanted}\n" in block + "\n":
            match = re.search(r"ip_address=(\S+)", block)
            if match:
                return match.group(1)
    return ""


def _await_lease(mac: str, *, since: float, wait: float) -> str:
    # The capture answers on the OFFER; bootpd records the lease only on the ACK that
    # follows, which an emulated (tcg) guest can send seconds after the capture has settled.
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        leased = _leased_address(mac, since=since)
        if leased:
            return leased
        time.sleep(0.5)
    return ""


def _leases_report(since: float) -> str:
    if not _LEASES.exists():
        return f"{_LEASES} does not exist"
    return f"{_LEASES} mtime {_LEASES.stat().st_mtime:.1f}, resumed {since:.1f}:\n{_LEASES.read_text(encoding='utf-8', errors='replace')}"


@pytest.fixture
def guest(tmp_path: Path) -> Iterator[tuple[str, Path]]:
    """Start the paused guest and yield its member port and monitor socket; stop it however the test ends."""

    monitor = tmp_path / "qemu-monitor.sock"
    argv = [
        _QEMU, "-accel", _accelerator(), "-m", "256", "-S", "-display", "none", "-serial", "none",
        "-monitor", f"unix:{monitor},server,nowait",
        "-netdev", "vmnet-shared,id=n0", "-device", f"virtio-net-pci,netdev=n0,mac={_GUEST_MAC}", "-boot", "n",
    ]  # fmt: skip
    process = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # noqa: S603 - fixed argv, no shell
    try:
        member = _member(wait=30.0)
        assert member, f"{_BRIDGE} never gained the guest's member port"
        yield member, monitor
    finally:
        with contextlib.suppress(OSError):
            _monitor(monitor, "quit")
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


pytestmark = [
    pytest.mark.os_macos,
    pytest.mark.host_mutating,
    pytest.mark.skipif(sys.platform != "darwin" or not _is_root(), reason="needs macOS and root: vmnet and BPF"),
    pytest.mark.skipif(shutil.which(_QEMU) is None, reason=f"needs {_QEMU} (brew install qemu)"),
]


def test_the_guest_member_port_shows_a_booting_guest_its_address(guest: tuple[str, Path]) -> None:
    member, monitor = guest

    with ipscout.observe_dhcp_session(_GUEST_MAC, interface=member, timeout=60.0, settle=5.0) as session:
        resumed = time.time()
        _monitor(monitor, "cont")
        offered = session.result()

    assert offered, f"nothing was offered to the guest on {member}"
    leased = _await_lease(_GUEST_MAC, since=resumed - 1.0, wait=30.0)
    assert leased, f"bootpd recorded no lease, so no real handshake was watched; {_leases_report(resumed - 1.0)}"
    assert leased in offered


@pytest.mark.usefixtures("guest")
def test_the_vmnet_bridge_itself_is_refused() -> None:
    with pytest.raises(IPScoutUnsupportedError, match="member port"):
        ipscout.observe_dhcp(_GUEST_MAC, interface=_BRIDGE, timeout=1.0)
