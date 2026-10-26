"""ctypes bindings for the Windows IP Helper API (``iphlpapi.dll``).

This is how ipscout works on Windows without administrator rights. Windows has
no unprivileged ICMP socket - ``SOCK_DGRAM``/``IPPROTO_ICMP`` simply does not
exist there, and a raw socket needs elevation - but ``IcmpSendEcho`` and
friends are ordinary user-mode calls that any process may make. That asymmetry
is the entire reason this module exists rather than reusing the POSIX path.

Contents:
    Structures mirroring the C layouts in ``ipexport.h`` and ``iphlpapi.h``.
    iphlpapi: Lazily loaded, cached handle to the DLL.
    win_family / family_from_win: Windows' own ``AF_*`` numbering, both ways.
    IpStatus: The ``IP_STATUS`` codes, each with its text; status_message
        renders a raw one.
    sockaddr_inet / sockaddr_inet_address / address_text: Encode and decode
        a ``SOCKADDR_INET`` once, and render an address the way every
        backend does.

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
import enum
import ipaddress
import socket
import struct
import sys
from typing import TYPE_CHECKING

from .errors import IPScoutUnsupportedError
from .models import AddressFamily

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = [
    "DEFAULT_TTL",
    "ICMPV6_ECHO_REPLY",
    "ICMP_ECHO_REPLY",
    "ICMP_REPLY_HEADROOM",
    "INVALID_HANDLE_VALUE",
    "IPV6_ADDRESS_EX",
    "IP_ADDRESS_PREFIX",
    "IP_OPTION_INFORMATION",
    "MAX_ADAPTER_ADDRESS_LENGTH",
    "MIB_IPFORWARD_ROW2",
    "MIB_IPFORWARD_TABLE2",
    "MIB_IPNET_ROW2",
    "MIB_IPNET_TABLE2",
    "MS_LAYOUT",
    "NET_LUID",
    "NO_ERROR",
    "SOCKADDR_IN",
    "SOCKADDR_IN6",
    "SOCKADDR_INET",
    "WIN_AF_INET",
    "WIN_AF_INET6",
    "WIN_AF_UNSPEC",
    "IpStatus",
    "address_text",
    "echo_status",
    "family_from_win",
    "iphlpapi",
    "ipv4_to_string",
    "ipv6_words_to_string",
    "last_error",
    "packed_to_ipv4",
    "reply_buffer_size",
    "sockaddr_in6",
    "sockaddr_inet",
    "sockaddr_inet_address",
    "sockaddr_inet_to_string",
    "status_message",
    "string_to_ipv4",
    "win_family",
]

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

#: Windows' own default IP time-to-live: what ``ping.exe`` sends, and the hop
#: limit an ``IcmpSendEcho`` request carries when its caller asks for none.
DEFAULT_TTL = 128

#: Bytes an echo reply buffer holds beyond the reply structure and the echoed
#: payload. The ``IcmpSendEcho`` documentation requires room for an ICMP error
#: message as well, which is at least 8 bytes; 64 leaves margin for the IP
#: options a router may quote back.
ICMP_REPLY_HEADROOM = 64


class IpStatus(enum.IntEnum):
    """The ``IP_STATUS`` codes an ICMP reply (or ``GetLastError``) carries.

    Each member carries its readable text, so the code and what it means are
    written down once. Only the codes this library acts on or reports are
    listed; ``ipexport.h`` defines more (``IP_STATUS_BASE`` plus an offset),
    and an unlisted one is decoded as ``None`` by :meth:`parse` rather than
    raising.

    Attributes:
        text: A short human-readable description of the status.

    Examples:
        >>> IpStatus.TTL_EXPIRED_TRANSIT.text
        'TTL expired in transit'
        >>> int(IpStatus.REQ_TIMED_OUT)
        11010

    """

    text: str

    def __new__(cls, code: int, text: str) -> IpStatus:
        member = int.__new__(cls, code)
        member._value_ = code
        member.text = text
        return member

    SUCCESS = (0, "success")
    BUF_TOO_SMALL = (11001, "reply buffer too small")
    DEST_NET_UNREACHABLE = (11002, "destination network unreachable")
    DEST_HOST_UNREACHABLE = (11003, "destination host unreachable")
    DEST_PROT_UNREACHABLE = (11004, "destination protocol unreachable")
    DEST_PORT_UNREACHABLE = (11005, "destination port unreachable")
    NO_RESOURCES = (11006, "insufficient resources")
    #: The probe would have to be fragmented and carries don't-fragment.
    PACKET_TOO_BIG = (11009, "packet too big")
    REQ_TIMED_OUT = (11010, "request timed out")
    #: A router discarded the packet because its hop limit ran out.
    #: Traceroute is built on this: the reply's Address field carries that
    #: router.
    TTL_EXPIRED_TRANSIT = (11013, "TTL expired in transit")

    @classmethod
    def parse(cls, code: int) -> IpStatus | None:
        """Decode a raw status number, or return None for one not listed.

        The decode edge for every ``Status`` field and ``GetLastError`` value:
        the API can report codes this library has no member for, and those are
        an answer ("something else went wrong"), not a crash.

        Args:
            code: The number as the API wrote it.

        Returns:
            The member, or ``None`` for an unlisted code.

        Examples:
            >>> IpStatus.parse(11013) is IpStatus.TTL_EXPIRED_TRANSIT
            True
            >>> IpStatus.parse(99999) is None
            True

        """

        try:
            return cls(code)
        except ValueError:
            return None


def status_message(code: int) -> str:
    """Return readable text for a raw ``IP_STATUS`` code.

    Args:
        code: The numeric status from a reply structure.

    Returns:
        A short description, or a generic label for codes not listed.

    Examples:
        >>> status_message(IpStatus.SUCCESS)
        'success'
        >>> status_message(11013)
        'TTL expired in transit'
        >>> status_message(99999)
        'IP_STATUS 99999'

    """

    status = IpStatus.parse(code)
    return status.text if status is not None else f"IP_STATUS {code}"


def echo_status(replies: int, *, reply_status: int, last_error: int) -> IpStatus | None:
    """Return the status one ``IcmpSendEcho`` call reports.

    The call reports in two places. With no reply it returns 0 and the status
    is in ``GetLastError``. With a reply it returns the count, and the status
    is the reply's own ``Status`` - which is not ``SUCCESS`` when the reply is
    an ICMP error: a router's TTL expiry comes back as one reply carrying
    ``TTL_EXPIRED_TRANSIT``. Reading the count alone takes every such error
    for an answer.

    Args:
        replies: What the call returned.
        reply_status: The first reply's ``Status`` field; ignored when
            ``replies`` is 0, since nothing was written.
        last_error: ``GetLastError`` right after the call.

    Returns:
        The status, or ``None`` for a code :class:`IpStatus` does not list.

    Examples:
        >>> echo_status(1, reply_status=11013, last_error=0) is IpStatus.TTL_EXPIRED_TRANSIT
        True
        >>> echo_status(0, reply_status=0, last_error=11010) is IpStatus.REQ_TIMED_OUT
        True

    """

    return IpStatus.parse(reply_status if replies else last_error)


#: Force the MSVC structure layout rather than the host compiler's native one.
#: These types mirror Windows headers, so MSVC rules are the correct ones even
#: when the layout is being computed on Linux by a test. Accepted and ignored
#: before Python 3.14; honoured from 3.14 on, where leaving it implicit on a
#: packed structure is deprecated and becomes an error in 3.19.
MS_LAYOUT = "ms"

#: ``NO_ERROR`` (also spelled ``ERROR_SUCCESS``): the one success value every
#: iphlpapi call returning a Win32 error code reports.
NO_ERROR = 0

#: ``MAX_ADAPTER_ADDRESS_LENGTH`` from ``iptypes.h``: the hardware-address
#: buffer an adapter record and ``SendARP`` use. Longer link addresses exist
#: (the neighbour row holds 32 bytes), but not in these two places.
MAX_ADAPTER_ADDRESS_LENGTH = 8


class IP_OPTION_INFORMATION(ctypes.Structure):  # noqa: N801 - mirrors the Windows C type name
    """``IP_OPTION_INFORMATION`` from ``ipexport.h``.

    Carries the outgoing TTL, which is what makes traceroute possible through
    this API.
    """

    _layout_ = MS_LAYOUT
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

    _layout_ = MS_LAYOUT
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
    _layout_ = MS_LAYOUT
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

    _layout_ = MS_LAYOUT
    _fields_ = (
        ("Address", IPV6_ADDRESS_EX),
        ("Status", ctypes.c_uint32),
        ("RoundTripTime", ctypes.c_uint32),
    )


class SOCKADDR_IN6(ctypes.Structure):  # noqa: N801 - mirrors the Windows C type name
    """``sockaddr_in6`` as ``Icmp6SendEcho2`` expects it."""

    _layout_ = MS_LAYOUT
    _fields_ = (
        ("sin6_family", ctypes.c_uint16),
        ("sin6_port", ctypes.c_uint16),
        ("sin6_flowinfo", ctypes.c_uint32),
        ("sin6_addr", ctypes.c_uint8 * 16),
        ("sin6_scope_id", ctypes.c_uint32),
    )


class SOCKADDR_IN(ctypes.Structure):  # noqa: N801 - mirrors the Windows C type name
    """``sockaddr_in``, the IPv4 arm of :class:`SOCKADDR_INET`."""

    _layout_ = MS_LAYOUT
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

    _layout_ = MS_LAYOUT
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

    _layout_ = MS_LAYOUT
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

    _layout_ = MS_LAYOUT
    _fields_ = (
        ("NumEntries", ctypes.c_uint32),
        ("Table", MIB_IPFORWARD_ROW2 * 1),
    )


class MIB_IPNET_ROW2(ctypes.Structure):  # noqa: N801 - mirrors the Windows C type name
    """``MIB_IPNET_ROW2``: one neighbour-cache entry.

    The flags field is a bitfield in the C header. It is declared here as the
    ULONG it occupies rather than as named bits, because nothing reads it and
    an approximate bitfield would only be a way to get the size wrong.
    """

    _layout_ = MS_LAYOUT
    _fields_ = (
        ("Address", SOCKADDR_INET),
        ("InterfaceIndex", ctypes.c_uint32),
        ("InterfaceLuid", NET_LUID),
        ("PhysicalAddress", ctypes.c_uint8 * 32),
        ("PhysicalAddressLength", ctypes.c_uint32),
        ("State", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("ReachabilityTime", ctypes.c_uint32),
    )


class MIB_IPNET_TABLE2(ctypes.Structure):  # noqa: N801 - mirrors the Windows C type name
    """``MIB_IPNET_TABLE2``: a count followed by that many neighbour rows."""

    _layout_ = MS_LAYOUT
    _fields_ = (
        ("NumEntries", ctypes.c_uint32),
        ("Table", MIB_IPNET_ROW2 * 1),
    )


#: Windows numbers AF_INET6 23, not the 10 that POSIX uses. Reading the
#: platform's own socket.AF_INET6 here would decode IPv6 rows as unknown on
#: every non-Windows host that inspects a captured structure.
WIN_AF_UNSPEC = 0
WIN_AF_INET = 2
WIN_AF_INET6 = 23


def win_family(family: AddressFamily) -> int:
    """Return the Windows ``AF_*`` number for an address family.

    Not :attr:`AddressFamily.socket_family`: Windows numbers ``AF_INET6`` as
    23, where Linux uses 10 and macOS 30, and the iphlpapi structures carry
    the Windows number whatever platform builds them.

    Args:
        family: The family to encode.

    Returns:
        :data:`WIN_AF_INET` or :data:`WIN_AF_INET6`.

    Examples:
        >>> win_family(AddressFamily.IPV6)
        23
        >>> win_family(AddressFamily.IPV4)
        2

    """

    return WIN_AF_INET6 if family is AddressFamily.IPV6 else WIN_AF_INET


def family_from_win(value: int) -> AddressFamily | None:
    """Return the address family a Windows ``AF_*`` number names.

    Args:
        value: The family field read out of an iphlpapi structure.

    Returns:
        The family, or ``None`` for any number other than :data:`WIN_AF_INET`
        and :data:`WIN_AF_INET6`. ``AF_UNSPEC`` is the common case: an
        on-link next hop comes back with family zero.

    Examples:
        >>> family_from_win(WIN_AF_INET6)
        <AddressFamily.IPV6: 'ipv6'>
        >>> family_from_win(WIN_AF_UNSPEC) is None
        True

    """

    if value == WIN_AF_INET6:
        return AddressFamily.IPV6
    if value == WIN_AF_INET:
        return AddressFamily.IPV4
    return None


#: ``in6addr_any``, the all-zero IPv6 address.
_IN6ADDR_ANY = bytes(16)


def sockaddr_in6(packed: bytes = _IN6ADDR_ANY, *, scope_id: int = 0) -> SOCKADDR_IN6:
    """Build a ``SOCKADDR_IN6`` carrying Windows' own ``AF_INET6`` number.

    Args:
        packed: The 16-byte address; the default is the unspecified address,
            which is what ``Icmp6SendEcho2`` takes as "any source".
        scope_id: The interface index a link-local address is scoped to.

    Returns:
        The structure, its family field set to :data:`WIN_AF_INET6` rather
        than the host's ``socket.AF_INET6``, which is 10 on Linux.

    Examples:
        >>> sockaddr_in6().sin6_family
        23

    """

    sockaddr = SOCKADDR_IN6(sin6_family=WIN_AF_INET6, sin6_scope_id=scope_id)
    sockaddr.sin6_addr[:] = packed
    return sockaddr


def reply_buffer_size(reply: type[ctypes.Structure], payload_size: int) -> int:
    """Return the bytes an echo reply buffer needs for one reply.

    Args:
        reply: The reply structure the call writes, :class:`ICMP_ECHO_REPLY`
            or :class:`ICMPV6_ECHO_REPLY`.
        payload_size: Bytes of payload the request echoes.

    Returns:
        The structure, the echoed payload and :data:`ICMP_REPLY_HEADROOM`.

    Examples:
        >>> reply_buffer_size(ICMP_ECHO_REPLY, 0) == ctypes.sizeof(ICMP_ECHO_REPLY) + ICMP_REPLY_HEADROOM
        True

    """

    return ctypes.sizeof(reply) + payload_size + ICMP_REPLY_HEADROOM


def last_error() -> int:
    """Return the thread's last Windows error code, or 0 elsewhere.

    ``ctypes.get_last_error`` is declared only for Windows in the type stubs,
    so reading it directly is an unknown attribute on the other two platform
    checks. Looking it up by name keeps every call site typed without turning
    a rule off.

    Examples:
        >>> isinstance(last_error(), int)
        True

    """

    getter = getattr(ctypes, "get_last_error", None)
    if getter is None:  # pragma: no cover - POSIX
        return 0
    value = getter()
    return value if isinstance(value, int) else 0


def sockaddr_inet(packed: bytes, family: AddressFamily) -> SOCKADDR_INET:
    """Build a ``SOCKADDR_INET`` holding one address, tagged with its family.

    The inverse of :func:`sockaddr_inet_address`: the tag is written in
    Windows' own numbering (:func:`win_family`), and the address goes into
    the arm that tag selects.

    Args:
        packed: The address in network byte order, 4 bytes for IPv4 and 16
            for IPv6.
        family: The family ``packed`` belongs to.

    Returns:
        The union, ready to pass to an iphlpapi call.

    Raises:
        ValueError: ``packed`` is not the length ``family`` needs. ctypes
            refuses the assignment rather than padding or truncating it.

    Examples:
        >>> sockaddr = sockaddr_inet(bytes((192, 0, 2, 1)), AddressFamily.IPV4)
        >>> sockaddr.si_family == WIN_AF_INET, sockaddr_inet_address(sockaddr)
        (True, IPv4Address('192.0.2.1'))
        >>> sockaddr_inet(bytes(4), AddressFamily.IPV6)
        Traceback (most recent call last):
        ...
        ValueError: Can only assign sequence of same size

    """

    sockaddr = SOCKADDR_INET()
    sockaddr.si_family = win_family(family)
    if family is AddressFamily.IPV6:
        sockaddr.Ipv6.sin6_addr[:] = packed
    else:
        sockaddr.Ipv4.sin_addr[:] = packed
    return sockaddr


def sockaddr_inet_address(sockaddr: SOCKADDR_INET) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return the address held in a ``SOCKADDR_INET``, or None if it holds none.

    The one place the union's family tag is read: the tag picks the arm, and
    the arm's packed bytes become the address, so nothing downstream decodes
    the family again or re-parses a text form.

    Args:
        sockaddr: The union to read.

    Returns:
        The address, or ``None`` when the family is neither IPv4 nor IPv6 (an
        unspecified next hop reads as family zero, which is how an on-link
        route reports having no router).

    Examples:
        >>> sockaddr_inet_address(SOCKADDR_INET()) is None
        True
        >>> tagged = SOCKADDR_INET()
        >>> tagged.si_family = WIN_AF_INET
        >>> tagged.Ipv4.sin_addr[:] = (192, 0, 2, 1)
        >>> sockaddr_inet_address(tagged)
        IPv4Address('192.0.2.1')

    """

    family = family_from_win(int(sockaddr.si_family))
    if family is AddressFamily.IPV4:
        return ipaddress.IPv4Address(bytes(sockaddr.Ipv4.sin_addr))
    if family is AddressFamily.IPV6:
        return ipaddress.IPv6Address(bytes(sockaddr.Ipv6.sin6_addr))
    return None


def address_text(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Return the text form of an address, as ``inet_ntop`` writes it.

    ``inet_ntop`` rather than ``str()``: the two disagree on an IPv4-mapped
    IPv6 address before Python 3.13 (``::ffff:102:304`` against
    ``::ffff:1.2.3.4``), and every other backend reports the ``inet_ntop``
    form.

    Args:
        address: The address to render.

    Returns:
        The address as text.

    Examples:
        >>> address_text(ipaddress.IPv6Address("::ffff:192.0.2.1"))
        '::ffff:192.0.2.1'

    """

    family = AddressFamily.of_version(address.version)
    return socket.inet_ntop(family.socket_family, address.packed)


def sockaddr_inet_to_string(sockaddr: SOCKADDR_INET) -> str | None:
    """Return the text form of the address in a ``SOCKADDR_INET``, or None.

    Args:
        sockaddr: The union to read.

    Returns:
        :func:`address_text` of :func:`sockaddr_inet_address`, or ``None``
        when the union holds no address.

    Examples:
        >>> blank = SOCKADDR_INET()
        >>> sockaddr_inet_to_string(blank) is None
        True

    """

    address = sockaddr_inet_address(sockaddr)
    return address_text(address) if address is not None else None


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

    Parsed with ``inet_pton`` rather than ``inet_aton``: the latter accepts
    shorthand (``127.1``, ``0x7f.1``) that no other part of this package
    reads as an address, so a typo would reach the API as a different host.

    Args:
        address: An IPv4 address in full dotted-quad form.

    Returns:
        The 32-bit value in the byte order the API expects.

    Raises:
        OSError: ``address`` is not a full dotted-quad IPv4 address.

    Examples:
        >>> string_to_ipv4("127.0.0.1") == 0x0100007F
        True
        >>> ipv4_to_string(string_to_ipv4("192.168.1.1"))
        '192.168.1.1'
        >>> try:
        ...     string_to_ipv4("127.1")
        ... except OSError:
        ...     print("refused")
        refused

    """

    return packed_to_ipv4(socket.inet_pton(AddressFamily.IPV4.socket_family, address))


def packed_to_ipv4(packed: bytes) -> int:
    """Return the ``IPAddr`` form of an IPv4 address already parsed to its four bytes.

    For a caller that has validated the address itself (``require_address``
    gives ``.packed``), so it is converted without being parsed a second time.

    Raises:
        struct.error: ``packed`` is not exactly four bytes.

    Examples:
        >>> packed_to_ipv4(bytes([127, 0, 0, 1])) == 0x0100007F
        True

    """

    # "<I": IPAddr is the four network-order bytes read as one native
    # little-endian DWORD, which is how every Windows architecture stores it.
    return int(struct.unpack("<I", packed)[0])


def ipv6_words_to_string(words: Iterable[int]) -> str:
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

    raw = b"".join(struct.pack("<H", word & 0xFFFF) for word in words)
    return socket.inet_ntop(AddressFamily.IPV6.socket_family, raw)


_library_cache: ctypes.CDLL | None = None


def iphlpapi() -> ctypes.CDLL:
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


def _configure(library: ctypes.CDLL) -> None:  # pragma: no cover - Windows only
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

    library.SendARP.restype = ctypes.c_uint32
    library.SendARP.argtypes = (
        ctypes.c_uint32,  # DestIP
        ctypes.c_uint32,  # SrcIP, 0 to let the stack choose
        ctypes.POINTER(ctypes.c_uint8 * MAX_ADAPTER_ADDRESS_LENGTH),  # PhysAddr, written by the call
        ctypes.POINTER(ctypes.c_uint32),  # PhysAddrLen, in and out
    )

    library.ResolveIpNetEntry2.restype = ctypes.c_uint32
    library.ResolveIpNetEntry2.argtypes = (
        ctypes.POINTER(MIB_IPNET_ROW2),  # Row, filled in by the call
        ctypes.c_void_p,  # SourceAddress, optional
    )

    # CreateIpNetEntry2 and DeleteIpNetEntry2 take the row by const pointer and
    # need Administrator; both return a Win32 error code.
    library.CreateIpNetEntry2.restype = ctypes.c_uint32
    library.CreateIpNetEntry2.argtypes = (ctypes.POINTER(MIB_IPNET_ROW2),)

    library.DeleteIpNetEntry2.restype = ctypes.c_uint32
    library.DeleteIpNetEntry2.argtypes = (ctypes.POINTER(MIB_IPNET_ROW2),)

    library.GetIpNetTable2.restype = ctypes.c_uint32
    library.GetIpNetTable2.argtypes = (
        ctypes.c_uint16,  # Family
        ctypes.POINTER(ctypes.POINTER(MIB_IPNET_TABLE2)),  # Table, allocated by the call
    )

    library.FreeMibTable.restype = None
    library.FreeMibTable.argtypes = (ctypes.c_void_p,)

    library.GetAdaptersAddresses.restype = ctypes.c_uint32
    library.GetAdaptersAddresses.argtypes = (
        ctypes.c_uint32,  # Family
        ctypes.c_uint32,  # Flags
        ctypes.c_void_p,  # Reserved, must be NULL
        ctypes.c_void_p,  # AdapterAddresses, written by the call
        ctypes.POINTER(ctypes.c_uint32),  # SizePointer, in and out
    )

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
