"""The macOS DHCP capture end to end, through a real BPF device, as root.

Everything else about the BPF path is asserted from any platform against
synthetic records; this is the one test that opens ``/dev/bpf``, binds it to an
interface, and reads frames the kernel delivered. It runs only on macOS as
root, opted in with ``IPSCOUT_HOST_WRITE_TESTS=1`` - see ``tests/conftest.py``.

The traffic stays on a ``feth`` pair, the fake Ethernet interfaces macOS can
create as root: frames written onto one end arrive on the other, so nothing
reaches the machine's real network and its own DHCP lease is never touched.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest
from dhcp_capture_fixture import REAL_REPLY_FRAMES

import ipscout
from ipscout.bpf import open_bpf_device

if TYPE_CHECKING:
    from collections.abc import Iterator

#: The pair's two ends. Numbered high so a pair a developer already has on
#: this Mac (feth0/feth1 are the obvious first choice) is left alone.
_WATCHED = "feth740"
_INJECTED = "feth741"

#: The client the fixture's two offers are addressed to; the third frame is for
#: another client and must be ignored.
_CLIENT_MAC = "02:00:5e:10:00:00"


def _is_root() -> bool:
    """Return whether this POSIX process is root; guarded so the Windows type check sees no geteuid."""

    if sys.platform == "win32":
        return False
    return os.geteuid() == 0


def _ifconfig(*args: str) -> None:
    ifconfig = shutil.which("ifconfig") or "/sbin/ifconfig"
    subprocess.run([ifconfig, *args], check=True, capture_output=True, encoding="utf-8", errors="replace")  # noqa: S603 - fixed argv, no shell


@pytest.fixture
def feth_pair() -> Iterator[None]:
    """Create two peered fake Ethernet interfaces, and destroy them however the test ends."""

    created: list[str] = []
    try:
        for name in (_WATCHED, _INJECTED):
            _ifconfig(name, "create")
            created.append(name)
        _ifconfig(_WATCHED, "peer", _INJECTED)
        for name in created:
            _ifconfig(name, "up")
        yield
    finally:
        for name in reversed(created):
            with contextlib.suppress(subprocess.CalledProcessError):
                _ifconfig(name, "destroy")


@pytest.mark.os_macos
@pytest.mark.host_mutating
@pytest.mark.skipif(not _is_root(), reason="opening a BPF device and creating interfaces need root")
@pytest.mark.usefixtures("feth_pair")
def test_offers_written_onto_one_end_of_a_feth_pair_are_captured_on_the_other() -> None:
    frames = [REAL_REPLY_FRAMES["offer_198.51.100.36"], REAL_REPLY_FRAMES["foreign_mac"], REAL_REPLY_FRAMES["offer_198.51.100.51"]]
    writer = open_bpf_device(_INJECTED, complete_headers=True)
    try:
        with ipscout.observe_dhcp_session(_CLIENT_MAC, interface=_WATCHED, timeout=5.0, settle=0.5) as session:
            for frame in frames:
                os.write(writer.descriptor, frame)
            offered = session.result()
    finally:
        os.close(writer.descriptor)

    assert offered == ["198.51.100.36", "198.51.100.51"]
