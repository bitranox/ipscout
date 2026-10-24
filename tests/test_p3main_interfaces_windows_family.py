"""The adapter list decodes a sockaddr by Windows' family numbering, not the host's.

``GetAdaptersAddresses`` fills each ``SOCKET_ADDRESS`` with a Windows sockaddr,
whose family field is Windows' own ``AF_*`` number (23 for IPv6). Comparing it
with the running host's ``socket.AF_INET6`` is right on Windows only by
coincidence: on Linux that constant is 10, so the same bytes read as an unknown
family. Building the sockaddr here, on any OS, pins the numbering the decoder uses.
"""

from __future__ import annotations

import ctypes
import socket
import struct
import sys

import pytest

from ipscout import interfaces_windows, winapi
from ipscout.models import AddressFamily


def _socket_address(raw: bytes) -> tuple[interfaces_windows._SocketAddress, ctypes.Array[ctypes.c_char]]:  # pyright: ignore[reportPrivateUsage] - the decoder takes the module's own ctypes struct; no public path reaches it off Windows
    buffer = ctypes.create_string_buffer(raw, len(raw))
    address = interfaces_windows._SocketAddress(ctypes.cast(buffer, ctypes.c_void_p), len(raw))  # pyright: ignore[reportPrivateUsage] - same struct as above
    return address, buffer


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (struct.pack("<HH4s8x", winapi.WIN_AF_INET, 0, socket.inet_pton(socket.AF_INET, "192.0.2.7")), (AddressFamily.IPV4, "192.0.2.7")),
        (struct.pack("<HHI16sI", winapi.WIN_AF_INET6, 0, 0, socket.inet_pton(socket.AF_INET6, "2001:db8::7"), 0), (AddressFamily.IPV6, "2001:db8::7")),
    ],
)
def test_a_windows_sockaddr_decodes_whatever_the_host_numbering(raw: bytes, expected: tuple[AddressFamily, str]) -> None:
    address, _keepalive = _socket_address(raw)

    decoded = interfaces_windows._sockaddr_text(address)  # pyright: ignore[reportPrivateUsage] - the decode step under test has no public entry off Windows

    assert decoded is not None
    assert (decoded.family, decoded.address) == expected


@pytest.mark.skipif(sys.platform == "win32", reason="on Windows the host and Windows numbering coincide")
def test_the_host_ipv6_number_is_not_mistaken_for_windows_ipv6() -> None:
    raw = struct.pack("<HHI16sI", int(socket.AF_INET6), 0, 0, socket.inet_pton(socket.AF_INET6, "2001:db8::7"), 0)
    address, _keepalive = _socket_address(raw)

    assert interfaces_windows._sockaddr_text(address) is None  # pyright: ignore[reportPrivateUsage] - as above
