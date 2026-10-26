"""Which ICMP socket a hop walk gets: the one that can observe expired hops, where any can.

A datagram ICMP socket shows Time Exceeded only through the Linux error queue.
macOS gives that socket to every process, root included, and offers no error
queue, so a walk there must take a raw socket when the process may open one.
Real sockets stand in for the ICMP ones: what is decided is which object comes
back and whether the other was closed, not what the kernel does with it.
"""

from __future__ import annotations

import socket
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the POSIX transport is not built on Windows")

from ipscout.errors import IPScoutPermissionError  # noqa: E402 - after the platform skip, as the module is POSIX-only
from ipscout.models import AddressFamily  # noqa: E402
from ipscout.transport_posix import _hop_socket, open_hop_socket  # noqa: E402  # pyright: ignore[reportPrivateUsage] - the choice is tested apart from the kernel, whose raw socket needs root


def _udp() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def _refused() -> socket.socket:
    raise PermissionError(1, "Operation not permitted")


def test_a_datagram_socket_with_an_error_queue_is_kept() -> None:
    datagram = _udp()
    with datagram:
        assert _hop_socket(datagram, error_queue=True, open_raw=_refused) is datagram


def test_without_an_error_queue_a_raw_socket_replaces_the_datagram_one() -> None:
    datagram, raw = _udp(), _udp()
    with raw:
        assert _hop_socket(datagram, error_queue=False, open_raw=lambda: raw) is raw
        assert datagram.fileno() == -1


def test_without_an_error_queue_and_no_raw_socket_the_datagram_one_is_kept_open() -> None:
    datagram = _udp()
    with datagram:
        assert _hop_socket(datagram, error_queue=False, open_raw=_refused) is datagram
        assert datagram.fileno() != -1


def _raw_socket_allowed() -> bool:
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()
    except OSError:
        return False
    return True


@pytest.mark.skipif(hasattr(socket, "MSG_ERRQUEUE"), reason="with an error queue the walk keeps whichever ICMP socket opened")
def test_without_an_error_queue_the_hop_socket_is_raw_exactly_when_the_process_may_open_one() -> None:
    # Unprivileged on macOS neither socket can see Time Exceeded, and the
    # datagram one is kept so the walk refuses on its capability.
    try:
        sock = open_hop_socket(AddressFamily.IPV4)
    except IPScoutPermissionError as exc:
        pytest.skip(f"no ICMP socket here: {exc}")
    with sock:
        assert (sock.type == socket.SOCK_RAW) is _raw_socket_allowed()
