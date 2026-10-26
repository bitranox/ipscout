"""A real macOS DHCP client's handshake through a bridge, watched by the macOS capture, as root.

The client is macOS's own (``ipconfig set <if> DHCP``), the server is ``dhcp_responder``, and a
bridge joins them, all on ``feth`` interfaces so nothing reaches the machine's real network::

    client feth751 <-peer-> feth750 [bridge member]   bridge
    server feth753 <-peer-> feth752 [bridge member]

Measured here first: a BPF device on the bridge sees only frames delivered to this host, never the
replies the bridge forwards to a guest, while the guest's member port sees the whole exchange. So
the capture must answer from the member port and refuse the bridge. Runs only on macOS as root,
opted in with ``IPSCOUT_HOST_WRITE_TESTS=1`` - see ``tests/conftest.py``.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
import time
from typing import TYPE_CHECKING

import pytest
from dhcp_responder import OFFERED_IP, DhcpResponder

import ipscout
from ipscout.errors import IPScoutUnsupportedError

if TYPE_CHECKING:
    from collections.abc import Iterator

#: Numbered apart from test_dhcp_macos_live.py's pair, so the two never collide.
_CLIENT, _CLIENT_PORT, _SERVER, _SERVER_PORT = "feth751", "feth750", "feth753", "feth752"
_CLIENT_MAC = "02:00:5e:10:00:01"


def _is_root() -> bool:
    """Return whether this POSIX process is root; guarded so the Windows type check sees no geteuid."""

    if sys.platform == "win32":
        return False
    return os.geteuid() == 0


def _tool(name: str, *args: str, check: bool = True) -> str:
    path = shutil.which(name) or f"/sbin/{name}"
    result = subprocess.run([path, *args], check=check, capture_output=True, encoding="utf-8", errors="replace")  # noqa: S603 - fixed argv, no shell
    return result.stdout.strip()


def _bound_address(interface: str, *, wait: float) -> str:
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        address = _tool("ipconfig", "getifaddr", interface, check=False)
        if address:
            return address
        time.sleep(0.5)
    return ""


@pytest.fixture
def bridge() -> Iterator[str]:
    """Build the client, server and bridge, and tear all of it down however the test ends."""

    created: list[str] = []
    name = ""
    try:
        for interface in (_CLIENT_PORT, _CLIENT, _SERVER_PORT, _SERVER):
            _tool("ifconfig", interface, "create")
            created.append(interface)
        _tool("ifconfig", _CLIENT, "peer", _CLIENT_PORT)
        _tool("ifconfig", _SERVER, "peer", _SERVER_PORT)
        _tool("ifconfig", _CLIENT, "lladdr", _CLIENT_MAC)
        for interface in created:
            _tool("ifconfig", interface, "up")
        name = _tool("ifconfig", "bridge", "create")
        _tool("ifconfig", name, "addm", _CLIENT_PORT, "addm", _SERVER_PORT, "up")
        yield name
    finally:
        with contextlib.suppress(subprocess.CalledProcessError):
            _tool("ipconfig", "set", _CLIENT, "NONE")
        for interface in ([name] if name else []) + list(reversed(created)):
            with contextlib.suppress(subprocess.CalledProcessError):
                _tool("ifconfig", interface, "destroy")


pytestmark = [
    pytest.mark.os_macos,
    pytest.mark.host_mutating,
    pytest.mark.skipif(sys.platform != "darwin" or not _is_root(), reason="needs macOS and root: feth, bridges and BPF"),
]


@pytest.mark.usefixtures("bridge")
def test_the_guest_member_port_shows_a_real_client_its_offer() -> None:
    with DhcpResponder(_SERVER) as server, ipscout.observe_dhcp_session(_CLIENT_MAC, interface=_CLIENT_PORT, timeout=30.0, settle=3.0) as session:
        _tool("ipconfig", "set", _CLIENT, "DHCP")
        offered = session.result()

    assert offered == [OFFERED_IP]
    assert server.offers_sent >= 1
    assert _bound_address(_CLIENT, wait=15.0) == OFFERED_IP, "the client never bound, so no real handshake was watched"


def test_the_bridge_itself_is_refused_rather_than_answered_empty(bridge: str) -> None:
    with pytest.raises(IPScoutUnsupportedError, match="member port"):
        ipscout.observe_dhcp(_CLIENT_MAC, interface=bridge, timeout=1.0)
