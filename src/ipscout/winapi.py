"""ctypes bindings for the Windows IP Helper API (``iphlpapi.dll``).

This is how ipscout works on Windows without administrator rights. Windows has
no unprivileged ICMP socket - ``SOCK_DGRAM``/``IPPROTO_ICMP`` simply does not
exist there, and a raw socket needs elevation - but ``IcmpSendEcho`` and
friends are ordinary user-mode calls that any process may make. That asymmetry
is the entire reason this module exists rather than reusing the POSIX path.

Contents:
    Structures mirroring the C layouts in ``ipexport.h`` and ``iphlpapi.h``.
    iphlpapi: Lazily loaded, cached handle to the DLL.
    status_message: Human-readable text for an ``IP_STATUS`` code.

Fixed-width integers, deliberately:
    Every field is declared with an explicit width (``c_uint32`` for ``ULONG``
    and ``DWORD``, ``c_uint16`` for ``USHORT``) rather than ``c_ulong``.

    ``c_ulong`` is 4 bytes on Windows and 8 bytes on 64-bit Linux, because
    Windows x64 is LLP64 while Linux x86-64 is LP64. Using it would give these
    structures a different layout depending on where Python happened to be
    running - silently producing garbage offsets. Fixed widths make the layout
    identical everywhere, which additionally means the structure sizes can be
    asserted by tests running on Linux, where the DLL itself cannot be loaded.

Note:
    Importing this module is safe on every platform. Nothing is loaded until
    :func:`iphlpapi` is called, so the structures stay inspectable by tests on
    Linux and macOS.

"""

from __future__ import annotations

import ctypes
import socket
import struct
import sys
from typing import Any

from .errors import IPScoutUnsupportedError

__all__ = [
    "ICMPV6_ECHO_REPLY",
    "ICMP_ECHO_REPLY",
    "INVALID_HANDLE_VALUE",
    "IPV6_ADDRESS_EX",
    "IP_ADDRESS_PREFIX",
    "IP_DEST_HOST_UNREACHABLE",
    "IP_DEST_NET_UNREACHABLE",
    "IP_OPTION_INFORMATION",
    "IP_REQ_TIMED_OUT",
    "IP_SUCCESS",
    "IP_TTL_EXPIRED_TRANSIT",
    "MIB_IPFORWARD_ROW2",
    "MIB_IPFORWARD_TABLE2",
    "NET_LUID",
    "SOCKADDR_IN",
    "SOCKADDR_IN6",
    "SOCKADDR_INET",
    "WIN_AF_INET",
    "WIN_AF_INET6",
    "iphlpapi",
    "ipv4_to_string",
    "ipv6_words_to_string",
    "sockaddr_inet_to_string",
    "status_message",
    "string_to_ipv4",
]

#: ``IP_STATUS`` values this library actually distinguishes.
IP_SUCCESS = 0
IP_BUF_TOO_SMALL = 11001
IP_DEST_NET_UNREACHABLE = 11002
IP_DEST_HOST_UNREACHABLE = 11003
IP_DEST_PROT_UNREACHABLE = 11004
IP_DEST_PORT_UNREACHABLE = 11005
IP_NO_RESOURCES = 11006
IP_REQ_TIMED_OUT = 11010
#: A router discarded the packet because its hop limit ran out. Traceroute is
#: built on this: the reply's Address field carries that router.
IP_TTL_EXPIRED_TRANSIT = 11013

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_STATUS_TEXT = {
    IP_SUCCESS: "success",
    IP_BUF_TOO_SMALL: "reply buffer too small",
    IP_DEST_NET_UNREACHABLE: "destination network unreachable",
    IP_DEST_HOST_UNREACHABLE: "destination host unreachable",
    IP_DEST_PROT_UNREACHABLE: "destination protocol unreachable",
    IP_DEST_PORT_UNREACHABLE: "destination port unreachable",
    IP_NO_RESOURCES: "insufficient resources",
    IP_REQ_TIMED_OUT: "request timed out",
    IP_TTL_EXPIRED_TRANSIT: "TTL expired in transit",
}


def status_message(status: int) -> str:
    """Return readable text for an ``IP_STATUS`` code.

    Args:
        status: The numeric status from a reply structure.

    Returns:
        A short description, or a generic label for codes not listed.

    Examples:
        >>> status_message(IP_SUCCESS)
        'success'
        >>> status_message(IP_TTL_EXPIRED_TRANSIT)
        'TTL expired in transit'
        >>> status_message(99999)
        'IP_STATUS 99999'

    """

    return _STATUS_TEXT.get(status, f"IP_STATUS {status}")


#: Force the MSVC structure layout rather than the host compiler's native one.
#: These types mirror Windows headers, so MSVC rules are the correct ones even
#: when the layout is being computed on Linux by a test. Accepted and ignored
#: before Python 3.14; honoured from 3.14 on, where leaving it implicit on a
#: packed structure is deprecated and becomes an error in 3.19.
_MS_LAYOUT = "ms"


class IP_OPTION_INFORMATION(ctypes.Structure):  # noqa: N801 - mirrors the Windows C type name
    """``IP_OPTION_INFORMATION`` from ``ipexport.h``.

    Carries the outgoing TTL, which is what makes traceroute possible through
    this API.
    """

    _layout_ = _MS_LAYOUT
    _fields_ = (
        ("Ttl", ctypes.c_uint8),
        ("Tos", ctypes.c_uint8),
        ("Flags", ctypes.c_uint8),
        ("OptionsSize", ctypes.c_uint8),
        ("OptionsData", ctypes.c_void_p),
    )


class ICMP_ECHO_REPLY(ctypes.Structure):  # noqa: N801 - mirrors the Windows C type name
    """``ICMP_ECHO_REPLY`` from ``ipexport.h``.

    Note:
        ``Address`` is an ``IPAddr``: a 32-bit IPv4 address in network byte
        order, not a string.
    """

    _layout_ = _MS_LAYOUT
    _fields_ = (
        ("Address", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("RoundTripTime", ctypes.c_uint32),
        ("DataSize", ctypes.c_uint16),
        ("Reserved", ctypes.c_uint16),
        ("Data", ctypes.c_void_p),
        ("Options", IP_OPTION_INFORMATION),
    )


class IPV6_ADDRESS_EX(ctypes.Structure):  # noqa: N801 - mirrors the Windows C type name
    """``IPV6_ADDRESS_EX`` from ``ipexport.h``.

    Note:
        Declared between ``packon.h`` and ``packoff.h`` in the Windows headers,
        so it is byte-packed with no padding. ``_pack_ = 1`` reproduces that.
        Without it the compiler-natural alignment would insert two bytes after
        ``sin6_port`` and every later field would be read from the wrong offset.
    """

    _pack_ = 1
    _layout_ = _MS_LAYOUT
    _fields_ = (
        ("sin6_port", ctypes.c_uint16),
        ("sin6_flowinfo", ctypes.c_uint32),
        ("sin6_addr", ctypes.c_uint16 * 8),
        ("sin6_scope_id", ctypes.c_uint32),
    )


class ICMPV6_ECHO_REPLY(ctypes.Structure):  # noqa: N801 - mirrors the Windows C type name
    """``ICMPV6_ECHO_REPLY`` from ``ipexport.h``.

    Note:
        Unlike the address structure it contains, this one is *not* packed, so
        ``Status`` sits on its natural 4-byte boundary after the 26-byte
        address.
    """

    _layout_ = _MS_LAYOUT
    _fields_ = (
        ("Address", IPV6_ADDRESS_EX),
        ("Status", ctypes.c_uint32),
        ("RoundTripTime", ctypes.c_uint32),
    )


class SOCKADDR_IN6(ctypes.Structure):  # noqa: N801 - mirrors the Windows C type name
    """``sockaddr_in6`` as ``Icmp6SendEcho2`` expects it."""

    _layout_ = _MS_LAYOUT
    _fields_ = (
        ("sin6_family", ctypes.c_uint16),
        ("sin6_port", ctypes.c_uint16),
        ("sin6_flowinfo", ctypes.c_uint32),
        ("sin6_addr", ctypes.c_uint8 * 16),
        ("sin6_scope_id", ctypes.c_uint32),
    )


class SOCKADDR_IN(ctypes.Structure):  # noqa: N801 - mirrors the Windows C type name
    """``sockaddr_in``, the IPv4 arm of :class:`SOCKADDR_INET`."""

    _layout_ = _MS_LAYOUT
    _fields_ = (
        ("sin_family", ctypes.c_uint16),
        ("sin_port", ctypes.c_uint16),
        ("sin_addr", ctypes.c_uint8 * 4),
        ("sin_zero", ctypes.c_uint8 * 8),
    )


class SOCKADDR_INET(ctypes.Union):  # noqa: N801 - mirrors the Windows C type name
    """``SOCKADDR_INET``: either address family, tagged by the family field.

    Every arm begins with the family, which is what makes reading ``si_family``
    first and then the matching arm well defined rather than a guess.
    """

    _fields_ = (
        ("Ipv4", SOCKADDR_IN),
        ("Ipv6", SOCKADDR_IN6),
        ("si_family", ctypes.c_uint16),
    )


class NET_LUID(ctypes.Union):  # noqa: N801 - mirrors the Windows C type name
    """``NET_LUID``: an opaque 64-bit interface identifier."""

    _fields_ = (("Value", ctypes.c_uint64),)


class IP_ADDRESS_PREFIX(ctypes.Structure):  # noqa: N801 - mirrors the Windows C type name
    """``IP_ADDRESS_PREFIX``: an address plus its prefix length."""

    _layout_ = _MS_LAYOUT
    _fields_ = (
        ("Prefix", SOCKADDR_INET),
        ("PrefixLength", ctypes.c_uint8),
    )


class MIB_IPFORWARD_ROW2(ctypes.Structure):  # noqa: N801 - mirrors the Windows C type name
    """``MIB_IPFORWARD_ROW2``: one row of the IP forwarding table.

    Declared in full even though only the next hop and interface index are
    read. A short structure would make ``GetBestRoute2`` write past the buffer
    it was given, which corrupts memory rather than failing cleanly.
    """

    _layout_ = _MS_LAYOUT
    _fields_ = (
        ("InterfaceLuid", NET_LUID),
        ("InterfaceIndex", ctypes.c_uint32),
        ("DestinationPrefix", IP_ADDRESS_PREFIX),
        ("NextHop", SOCKADDR_INET),
        ("SitePrefixLength", ctypes.c_uint8),
        ("ValidLifetime", ctypes.c_uint32),
        ("PreferredLifetime", ctypes.c_uint32),
        ("Metric", ctypes.c_uint32),
        ("Protocol", ctypes.c_uint32),
        ("Loopback", ctypes.c_uint8),
        ("AutoconfigureAddress", ctypes.c_uint8),
        ("Publish", ctypes.c_uint8),
        ("Immortal", ctypes.c_uint8),
        ("Age", ctypes.c_uint32),
        ("Origin", ctypes.c_uint32),
    )


class MIB_IPFORWARD_TABLE2(ctypes.Structure):  # noqa: N801 - mirrors the Windows C type name
    """``MIB_IPFORWARD_TABLE2``: a count followed by that many rows.

    Declared with a single-element array, as the C header does. The real row
    count comes from ``NumEntries``, and the rows are read by casting to an
    array of that length rather than by trusting this declaration's size.
    """

    _layout_ = _MS_LAYOUT
    _fields_ = (
        ("NumEntries", ctypes.c_uint32),
        ("Table", MIB_IPFORWARD_ROW2 * 1),
    )


#: Windows numbers AF_INET6 23, not the 10 that POSIX uses. Reading the
#: platform's own socket.AF_INET6 here would decode IPv6 rows as unknown on
#: every non-Windows host that inspects a captured structure.
WIN_AF_INET = 2
WIN_AF_INET6 = 23


def sockaddr_inet_to_string(sockaddr: SOCKADDR_INET) -> str | None:
    """Return the address held in a ``SOCKADDR_INET``, or None if it holds none.

    Args:
        sockaddr: The union to read.

    Returns:
        The printable address, or ``None`` when the family is neither IPv4 nor
        IPv6 (an unspecified next hop reads as family zero, which is how an
        on-link route reports having no router).

    Examples:
        >>> blank = SOCKADDR_INET()
        >>> sockaddr_inet_to_string(blank) is None
        True

    """

    family = sockaddr.si_family
    if family == WIN_AF_INET:
        return socket.inet_ntop(socket.AF_INET, bytes(sockaddr.Ipv4.sin_addr))
    if family == WIN_AF_INET6:
        return socket.inet_ntop(socket.AF_INET6, bytes(sockaddr.Ipv6.sin6_addr))
    return None


def ipv4_to_string(address: int) -> str:
    """Return the dotted-quad form of an ``IPAddr``.

    Args:
        address: A 32-bit IPv4 address in network byte order, as the API
            returns it.

    Returns:
        The address as text.

    Examples:
        >>> ipv4_to_string(0x0100007F)   # 127.0.0.1 little-endian on the wire
        '127.0.0.1'
        >>> ipv4_to_string(0)
        '0.0.0.0'

    """

    return socket.inet_ntoa(struct.pack("<I", address & 0xFFFFFFFF))


def string_to_ipv4(address: str) -> int:
    """Return the ``IPAddr`` form of a dotted-quad string.

    Args:
        address: An IPv4 address in text form.

    Returns:
        The 32-bit value in the byte order the API expects.

    Examples:
        >>> string_to_ipv4("127.0.0.1") == 0x0100007F
        True
        >>> ipv4_to_string(string_to_ipv4("192.168.1.1"))
        '192.168.1.1'

    """

    return int(struct.unpack("<I", socket.inet_aton(address))[0])


def ipv6_words_to_string(words: object) -> str:
    """Return the text form of an ``IPV6_ADDRESS_EX`` address field.

    Args:
        words: The ``sin6_addr`` array of eight 16-bit words, in network byte
            order.

    Returns:
        The address as text.

    Examples:
        >>> import ctypes
        >>> loopback = (ctypes.c_uint16 * 8)(0, 0, 0, 0, 0, 0, 0, 0x0100)
        >>> ipv6_words_to_string(loopback)
        '::1'

    """

    raw = b"".join(struct.pack("<H", int(word) & 0xFFFF) for word in words)  # type: ignore[union-attr]
    return socket.inet_ntop(socket.AF_INET6, raw)


_library_cache: Any = None


def iphlpapi() -> Any:
    """Return the loaded ``iphlpapi.dll``, loading it on first use.

    Returns:
        The ctypes library handle.

    Raises:
        IPScoutUnsupportedError: Not running on Windows, or the DLL could not
            be loaded.

    Note:
        Loading is deferred so that merely importing this module stays safe on
        Linux and macOS, which keeps the structure layouts inspectable by tests
        that run on any platform.

    """

    global _library_cache  # noqa: PLW0603 - a process-wide DLL handle is genuinely global
    if _library_cache is not None:
        return _library_cache
    if sys.platform != "win32":
        msg = f"iphlpapi.dll is a Windows library; this process is running on {sys.platform!r}"
        raise IPScoutUnsupportedError(msg)
    try:  # pragma: no cover - Windows only
        _library_cache = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)  # type: ignore[attr-defined]
    except OSError as exc:  # pragma: no cover - Windows only
        msg = f"could not load iphlpapi.dll: {exc}"
        raise IPScoutUnsupportedError(msg) from exc
    _configure(_library_cache)  # pragma: no cover - Windows only
    return _library_cache  # pragma: no cover - Windows only


def _configure(library: Any) -> None:  # pragma: no cover - Windows only
    """Declare argument and return types so ctypes marshals correctly.

    Without explicit ``restype`` ctypes assumes ``int``, which truncates the
    64-bit HANDLE that ``IcmpCreateFile`` returns.
    """

    library.IcmpCreateFile.restype = ctypes.c_void_p
    library.IcmpCreateFile.argtypes = ()

    library.Icmp6CreateFile.restype = ctypes.c_void_p
    library.Icmp6CreateFile.argtypes = ()

    library.IcmpCloseHandle.restype = ctypes.c_bool
    library.IcmpCloseHandle.argtypes = (ctypes.c_void_p,)

    library.IcmpSendEcho.restype = ctypes.c_uint32
    library.IcmpSendEcho.argtypes = (
        ctypes.c_void_p,  # IcmpHandle
        ctypes.c_uint32,  # DestinationAddress
        ctypes.c_void_p,  # RequestData
        ctypes.c_uint16,  # RequestSize
        ctypes.POINTER(IP_OPTION_INFORMATION),
        ctypes.c_void_p,  # ReplyBuffer
        ctypes.c_uint32,  # ReplySize
        ctypes.c_uint32,  # Timeout, milliseconds
    )

    library.GetBestRoute2.restype = ctypes.c_uint32
    library.GetBestRoute2.argtypes = (
        ctypes.POINTER(NET_LUID),  # InterfaceLuid, optional
        ctypes.c_uint32,  # InterfaceIndex
        ctypes.POINTER(SOCKADDR_INET),  # SourceAddress, optional
        ctypes.POINTER(SOCKADDR_INET),  # DestinationAddress
        ctypes.c_uint32,  # AddressSortOptions
        ctypes.POINTER(MIB_IPFORWARD_ROW2),  # BestRoute, written by the call
        ctypes.POINTER(SOCKADDR_INET),  # BestSourceAddress, written by the call
    )

    library.GetIpForwardTable2.restype = ctypes.c_uint32
    library.GetIpForwardTable2.argtypes = (
        ctypes.c_uint16,  # Family
        ctypes.POINTER(ctypes.POINTER(MIB_IPFORWARD_TABLE2)),  # Table, allocated by the call
    )

    library.FreeMibTable.restype = None
    library.FreeMibTable.argtypes = (ctypes.c_void_p,)

    library.Icmp6SendEcho2.restype = ctypes.c_uint32
    library.Icmp6SendEcho2.argtypes = (
        ctypes.c_void_p,  # IcmpHandle
        ctypes.c_void_p,  # Event
        ctypes.c_void_p,  # ApcRoutine
        ctypes.c_void_p,  # ApcContext
        ctypes.POINTER(SOCKADDR_IN6),  # SourceAddress
        ctypes.POINTER(SOCKADDR_IN6),  # DestinationAddress
        ctypes.c_void_p,  # RequestData
        ctypes.c_uint16,  # RequestSize
        ctypes.POINTER(IP_OPTION_INFORMATION),
        ctypes.c_void_p,  # ReplyBuffer
        ctypes.c_uint32,  # ReplySize
        ctypes.c_uint32,  # Timeout, milliseconds
    )


def reset_library_cache() -> None:
    """Forget the cached DLL handle. Exists for tests."""

    global _library_cache  # noqa: PLW0603 - mirrors the cache it clears
    _library_cache = None
