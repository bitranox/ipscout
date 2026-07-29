"""Local interface enumeration on Windows, via ``GetAdaptersAddresses``.

One call returns every adapter with its unicast addresses, prefix lengths,
hardware address, MTU and link state - and, usefully for the subnet layer, the
DHCP server and DNS configuration the OS already learned. No elevation is
required, matching the rest of this library.

Contents:
    list_interfaces: Enumerate every adapter this host has.

Note:
    ``IP_ADAPTER_ADDRESSES`` is a large structure whose tail has grown across
    Windows versions. Only the leading fields are declared here, up to the ones
    actually read; the API is told the buffer size and fills what fits, so
    stopping early is safe as long as nothing past the declared tail is
    touched. Fixed-width integer types are used throughout for the same reason
    as in :mod:`ipscout.winapi`.

"""

from __future__ import annotations

import ctypes
import socket
from typing import Any

from .models import Interface
from .winapi import iphlpapi

__all__ = ["list_interfaces"]

#: Return codes from GetAdaptersAddresses.
_ERROR_SUCCESS = 0
_ERROR_BUFFER_OVERFLOW = 111

#: AF_UNSPEC asks for both families in one pass.
_AF_UNSPEC = 0

#: Skip the parts of the result this library never reads, which keeps the
#: buffer small and the call fast.
_GAA_FLAG_SKIP_ANYCAST = 0x0002
_GAA_FLAG_SKIP_MULTICAST = 0x0004
_GAA_FLAG_INCLUDE_PREFIX = 0x0010

#: IF_TYPE_SOFTWARE_LOOPBACK from the IANA interface-type registry.
_IF_TYPE_LOOPBACK = 24

#: IfOperStatusUp.
_OPER_STATUS_UP = 1

#: MAX_ADAPTER_ADDRESS_LENGTH.
_MAX_ADAPTER_ADDRESS = 8

#: Starting buffer. The API reports the size it wants if this is too small.
_INITIAL_BUFFER = 15 * 1024

_MS_LAYOUT = "ms"


class _SocketAddress(ctypes.Structure):
    """``SOCKET_ADDRESS``: a pointer to a sockaddr plus its length."""

    _layout_ = _MS_LAYOUT
    _fields_ = (
        ("lpSockaddr", ctypes.c_void_p),
        ("iSockaddrLength", ctypes.c_int32),
    )


class _IpAdapterUnicastAddress(ctypes.Structure):
    """``IP_ADAPTER_UNICAST_ADDRESS``, to the prefix-length field."""


_IpAdapterUnicastAddress._layout_ = _MS_LAYOUT
_IpAdapterUnicastAddress._fields_ = (
    ("Length", ctypes.c_uint32),
    ("Flags", ctypes.c_uint32),
    ("Next", ctypes.POINTER(_IpAdapterUnicastAddress)),
    ("Address", _SocketAddress),
    ("PrefixOrigin", ctypes.c_uint32),
    ("SuffixOrigin", ctypes.c_uint32),
    ("DadState", ctypes.c_uint32),
    ("ValidLifetime", ctypes.c_uint32),
    ("PreferredLifetime", ctypes.c_uint32),
    ("LeaseLifetime", ctypes.c_uint32),
    ("OnLinkPrefixLength", ctypes.c_uint8),
)


class _IpAdapterAddresses(ctypes.Structure):
    """``IP_ADAPTER_ADDRESSES``, declared as far as the fields used here."""


_IpAdapterAddresses._layout_ = _MS_LAYOUT
_IpAdapterAddresses._fields_ = (
    # The leading union is Length + IfIndex, which is what the alignment
    # member overlays.
    ("Length", ctypes.c_uint32),
    ("IfIndex", ctypes.c_uint32),
    ("Next", ctypes.POINTER(_IpAdapterAddresses)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(_IpAdapterUnicastAddress)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_uint8 * _MAX_ADAPTER_ADDRESS),
    ("PhysicalAddressLength", ctypes.c_uint32),
    ("Flags", ctypes.c_uint32),
    ("Mtu", ctypes.c_uint32),
    ("IfType", ctypes.c_uint32),
    ("OperStatus", ctypes.c_uint32),
)


def _sockaddr_text(address: _SocketAddress) -> tuple[int, str] | None:
    """Return the family and text form of a ``SOCKET_ADDRESS``."""

    if not address.lpSockaddr or address.iSockaddrLength <= 0:
        return None
    raw = ctypes.string_at(address.lpSockaddr, address.iSockaddrLength)
    if len(raw) < 2:  # noqa: PLR2004 - needs at least the family field
        return None
    family = int.from_bytes(raw[:2], "little")
    if family == socket.AF_INET and len(raw) >= 8:  # noqa: PLR2004 - sockaddr_in through the address
        return family, socket.inet_ntop(socket.AF_INET, raw[4:8])
    if family == socket.AF_INET6 and len(raw) >= 24:  # noqa: PLR2004 - sockaddr_in6 through the address
        return family, socket.inet_ntop(socket.AF_INET6, raw[8:24])
    return None


def _mac_text(adapter: Any) -> str | None:
    """Return the adapter's hardware address, or None when it has none."""

    length = int(adapter.PhysicalAddressLength)
    if not 1 <= length <= _MAX_ADAPTER_ADDRESS:
        return None
    octets = bytes(adapter.PhysicalAddress[:length])
    if not any(octets):
        return None
    return ":".join(f"{byte:02x}" for byte in octets)


def list_interfaces() -> list[Interface]:  # pragma: no cover - Windows only
    """Return every local adapter with its addresses and hardware address.

    Returns:
        One :class:`~ipscout.models.Interface` per adapter, in the order the
        API reports them. Returns an empty list if the table cannot be read.

    """

    library = iphlpapi()
    library.GetAdaptersAddresses.restype = ctypes.c_uint32
    library.GetAdaptersAddresses.argtypes = (
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    )

    size = ctypes.c_uint32(_INITIAL_BUFFER)
    flags = _GAA_FLAG_SKIP_ANYCAST | _GAA_FLAG_SKIP_MULTICAST | _GAA_FLAG_INCLUDE_PREFIX
    buffer = ctypes.create_string_buffer(size.value)
    result = library.GetAdaptersAddresses(
        ctypes.c_uint32(_AF_UNSPEC),
        ctypes.c_uint32(flags),
        None,
        ctypes.cast(buffer, ctypes.c_void_p),
        ctypes.byref(size),
    )
    if result == _ERROR_BUFFER_OVERFLOW:
        buffer = ctypes.create_string_buffer(size.value)
        result = library.GetAdaptersAddresses(
            ctypes.c_uint32(_AF_UNSPEC),
            ctypes.c_uint32(flags),
            None,
            ctypes.cast(buffer, ctypes.c_void_p),
            ctypes.byref(size),
        )
    if result != _ERROR_SUCCESS:
        return []

    interfaces: list[Interface] = []
    cursor = ctypes.cast(buffer, ctypes.POINTER(_IpAdapterAddresses))
    while cursor:
        adapter = cursor.contents
        interfaces.append(_to_interface(adapter))
        cursor = adapter.Next
    return interfaces


def _to_interface(adapter: Any) -> Interface:  # pragma: no cover - Windows only
    """Build the public record for one adapter."""

    ipv4: list[tuple[str, int]] = []
    ipv6: list[tuple[str, int]] = []
    unicast = adapter.FirstUnicastAddress
    while unicast:
        entry = unicast.contents
        found = _sockaddr_text(entry.Address)
        if found is not None:
            family, text = found
            pair = (text, int(entry.OnLinkPrefixLength))
            (ipv6 if family == socket.AF_INET6 else ipv4).append(pair)
        unicast = entry.Next

    return Interface(
        name=str(adapter.FriendlyName or adapter.AdapterName or ""),
        ipv4=tuple(ipv4),
        ipv6=tuple(ipv6),
        mac=_mac_text(adapter),
        is_up=int(adapter.OperStatus) == _OPER_STATUS_UP,
        is_loopback=int(adapter.IfType) == _IF_TYPE_LOOPBACK,
        mtu=int(adapter.Mtu) or None,
    )
