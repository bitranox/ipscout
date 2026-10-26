"""A minimal DHCP server for the macOS live tests, speaking through a BPF device.

It answers a DISCOVER with an OFFER and a REQUEST with an ACK of one fixed address, so a real DHCP
client binds. Replies are unicast to the client's hardware address: that is what real servers
usually send, and it is the case a capture is most likely to miss. Everything is built from
RFC 5737 / RFC 7042 documentation values.
"""

from __future__ import annotations

import os
import select
import socket
import struct
import threading
from typing import TYPE_CHECKING

from ipscout.bpf import iter_bpf_frames, open_bpf_device

if TYPE_CHECKING:
    from types import TracebackType

__all__ = ["OFFERED_IP", "SERVER_IP", "DhcpResponder", "client_message_type", "reply_frame"]

SERVER_MAC = bytes.fromhex("02005e100002")
SERVER_IP = "198.51.100.1"
OFFERED_IP = "198.51.100.50"
_MASK = "255.255.255.0"
_LEASE_SECONDS = 3600

_DISCOVER, _OFFER, _REQUEST, _ACK = 1, 2, 3, 5
_ETHERNET_IPV4 = b"\x08\x00"
_UDP = 17
_SERVER_PORT, _CLIENT_PORT = 67, 68
_HEADERS = 14 + 20 + 8  # Ethernet, IPv4 without options, UDP
_FIXED_BOOTP = 240  # the BOOTP fields plus the magic cookie, before the options
_MAGIC_COOKIE = b"\x63\x82\x53\x63"


def _checksum(header: bytes) -> int:
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def client_message_type(frame: bytes) -> int | None:
    """Return the DHCP message type of a client's frame to the server port, or None.

    Args:
        frame: One Ethernet frame.

    Returns:
        Option 53's value for a client message sent to UDP port 67, else None.

    Examples:
        >>> client_message_type(b"") is None
        True

    """

    if len(frame) < _HEADERS + _FIXED_BOOTP or frame[12:14] != _ETHERNET_IPV4 or frame[23] != _UDP:
        return None
    if struct.unpack("!H", frame[36:38])[0] != _SERVER_PORT:
        return None
    options = frame[_HEADERS + _FIXED_BOOTP :]
    index = 0
    while index + 2 < len(options) and options[index] != 255:
        if options[index] == 0:
            index += 1
            continue
        if options[index] == 53:
            return options[index + 2]
        index += 2 + options[index + 1]
    return None


def reply_frame(request: bytes, message_type: int) -> bytes:
    """Return the OFFER or ACK answering ``request``, unicast to the client.

    Args:
        request: The client's DISCOVER or REQUEST frame.
        message_type: 2 for an OFFER, 5 for an ACK.

    Returns:
        A complete Ethernet frame from this server to the client's hardware address.

    """

    bootp = request[_HEADERS:]
    xid, flags, chaddr = bootp[4:8], bootp[10:12], bootp[28:44]
    body = struct.pack("!BBBB", 2, 1, 6, 0) + xid + b"\x00\x00" + flags + b"\x00" * 4
    body += socket.inet_aton(OFFERED_IP) + socket.inet_aton(SERVER_IP) + b"\x00" * 4 + chaddr + b"\x00" * 192
    body += _MAGIC_COOKIE + bytes([53, 1, message_type, 54, 4]) + socket.inet_aton(SERVER_IP)
    body += bytes([1, 4]) + socket.inet_aton(_MASK) + bytes([51, 4]) + struct.pack("!I", _LEASE_SECONDS) + b"\xff"
    body = body.ljust(300, b"\x00")
    udp = struct.pack("!HHHH", _SERVER_PORT, _CLIENT_PORT, 8 + len(body), 0) + body
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, _UDP, 0, socket.inet_aton(SERVER_IP), socket.inet_aton(OFFERED_IP))
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return chaddr[:6] + SERVER_MAC + _ETHERNET_IPV4 + ip + udp


class DhcpResponder:
    """Serve one address on an interface until the block exits.

    Attributes:
        offers_sent: How many OFFERs went out.
        acks_sent: How many ACKs went out.

    """

    def __init__(self, interface: str) -> None:
        self._interface = interface
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._ready = threading.Event()
        self.offers_sent = 0
        self.acks_sent = 0

    def __enter__(self) -> DhcpResponder:
        self._thread.start()
        self._ready.wait(timeout=5.0)
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self._stop.set()
        self._thread.join(timeout=5.0)

    def _serve(self) -> None:
        device = open_bpf_device(self._interface, promiscuous=True, complete_headers=True)
        self._ready.set()
        try:
            while not self._stop.is_set():
                readable, _writable, _failed = select.select([device.descriptor], [], [], 0.2)
                if readable:
                    self._answer(device.descriptor, os.read(device.descriptor, device.buffer_length))
        finally:
            os.close(device.descriptor)

    def _answer(self, descriptor: int, chunk: bytes) -> None:
        for frame in iter_bpf_frames(chunk):
            kind = client_message_type(frame)
            if kind == _DISCOVER:
                os.write(descriptor, reply_frame(frame, _OFFER))
                self.offers_sent += 1
            elif kind == _REQUEST:
                os.write(descriptor, reply_frame(frame, _ACK))
                self.acks_sent += 1
