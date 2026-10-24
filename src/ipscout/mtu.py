"""Path MTU discovery, without sending a single packet where possible.

Contents:
    path_mtu: The largest packet that reaches a destination unfragmented.

Note:
    Unprivileged on both platforms that support it, by entirely different
    means. Linux asks the kernel, which already tracks the path MTU per route
    and updates it from the ICMP Fragmentation Needed messages it receives -
    so nothing is sent at all. Windows has no equivalent query, so it probes
    with the don't-fragment flag set and narrows by bisection.

    macOS and the BSDs have neither, so they bisect with ``IP_DONTFRAG`` set
    and watch for the kernel's refusal. Where even that is unavailable the
    call raises rather than guessing: an MTU is used to size packets, so a
    wrong one is a silent black hole, and an honest error beats it.

"""

from __future__ import annotations

import contextlib
import ctypes
import socket
import sys
from typing import NamedTuple

from .errors import IPScoutPermissionError, IPScoutUnsupportedError
from .models import DEFAULT_TIMEOUT, DISCARD_PORT, AddressFamily
from .packet import HEADER_SIZE, IPV4_MIN_HEADER_SIZE, UDP_HEADER_SIZE
from .resolve import resolve_one
from .winapi import (
    DEFAULT_TTL,
    ICMP_ECHO_REPLY,
    INVALID_HANDLE_VALUE,
    IP_OPTION_INFORMATION,
    IpStatus,
    iphlpapi,
    last_error,
    reply_buffer_size,
    string_to_ipv4,
)

__all__ = ["path_mtu"]

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

#: IP_PMTUDISC_DO: always set don't-fragment, so the kernel tracks the path
#: MTU. Linux's IPV6_PMTUDISC_DO has the same value, so one constant serves
#: both families. Hardcoded because CPython's socket module does not export
#: it; the value is Linux kernel ABI from include/uapi/linux/in.h and in6.h,
#: fixed for every compiled binary.
_IP_PMTUDISC_DO = 2


class _LinuxMtuOptions(NamedTuple):
    """The two Linux socket options the path MTU query uses, for one family.

    Hardcoded for the same reason as :data:`_IP_PMTUDISC_DO`: CPython's socket
    module does not export them, and the values are Linux kernel ABI from
    include/uapi/linux/in.h (IPv4) and in6.h (IPv6).

    Attributes:
        discover: ``IP_MTU_DISCOVER`` / ``IPV6_MTU_DISCOVER``, which turns on
            path MTU discovery for the socket.
        mtu: ``IP_MTU`` / ``IPV6_MTU``, which reads the route's path MTU back.

    """

    discover: int
    mtu: int


_LINUX_MTU_OPTIONS: dict[AddressFamily, _LinuxMtuOptions] = {
    AddressFamily.IPV4: _LinuxMtuOptions(discover=10, mtu=14),
    AddressFamily.IPV6: _LinuxMtuOptions(discover=23, mtu=24),
}

#: IP_FLAG_DF, in the Windows echo options.
_IP_FLAG_DF = 0x02


#: How long each Windows probe waits for its reply, in the whole milliseconds
#: IcmpSendEcho takes: the same per-echo wait a ping uses by default.
_PROBE_TIMEOUT_MS = round(DEFAULT_TIMEOUT * 1000)

#: The search bounds for the Windows probe. 68 is the smallest IPv4 MTU a host
#: must support; 9000 covers jumbo frames.
_MIN_MTU = 68
_MAX_MTU = 9000

#: Bytes of header in front of the payload, which is what the probe varies:
#: an option-less IPv4 header, then the ICMP echo or the UDP header.
_IPV4_ICMP_OVERHEAD = IPV4_MIN_HEADER_SIZE + HEADER_SIZE
_IPV4_UDP_OVERHEAD = IPV4_MIN_HEADER_SIZE + UDP_HEADER_SIZE

#: IP_DONTFRAG, the BSD option that refuses to fragment rather than doing it.
_IP_DONTFRAG = 28


def _linux_mtu(address: str, family: AddressFamily) -> int | None:
    """Return the kernel's own path MTU for a destination, sending nothing.

    Connecting a datagram socket picks the route without putting anything on
    the wire, and the kernel already knows that route's MTU.
    """

    level, options = family.ip_option_level, _LINUX_MTU_OPTIONS[family]

    try:
        with socket.socket(family.socket_family, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(level, options.discover, _IP_PMTUDISC_DO)
            # Nothing is sent, so the port only has to be a valid one for
            # connect() to pick a route.
            sock.connect((address, DISCARD_PORT))
            value = sock.getsockopt(level, options.mtu)
    except OSError:
        return None
    return value if value > 0 else None


def _windows_mtu(address: str) -> int | None:  # pragma: no cover - Windows only
    """Return the path MTU by probing with the don't-fragment flag set.

    Windows has no query for this, so the size is narrowed by bisection: the
    largest payload that is not answered with "packet too big" is the answer.
    """

    try:
        library = iphlpapi()
    except IPScoutUnsupportedError:
        return None

    handle = library.IcmpCreateFile()
    if handle in (None, INVALID_HANDLE_VALUE):
        return None

    def fits(payload: int) -> bool:
        options = IP_OPTION_INFORMATION(Ttl=DEFAULT_TTL, Tos=0, Flags=_IP_FLAG_DF, OptionsSize=0, OptionsData=None)
        request = b"\x00" * payload
        reply = (ctypes.c_uint8 * reply_buffer_size(ICMP_ECHO_REPLY, payload))()
        count = library.IcmpSendEcho(handle, string_to_ipv4(address), request, payload, ctypes.byref(options), reply, len(reply), _PROBE_TIMEOUT_MS)
        if count:
            return True
        return IpStatus.parse(last_error()) is not IpStatus.PACKET_TOO_BIG

    try:
        low, high = _MIN_MTU - _IPV4_ICMP_OVERHEAD, _MAX_MTU - _IPV4_ICMP_OVERHEAD
        if not fits(low):
            return None
        while low < high:
            middle = (low + high + 1) // 2
            if fits(middle):
                low = middle
            else:
                high = middle - 1
        return low + _IPV4_ICMP_OVERHEAD
    finally:
        with contextlib.suppress(OSError):
            library.IcmpCloseHandle(handle)


def _bsd_mtu(address: str) -> int | None:  # pragma: no cover - macOS and the BSDs only
    """Return the path MTU by probing with don't-fragment set.

    macOS and the BSDs have no ``IP_MTU`` to ask, so the size is narrowed by
    bisection: send a datagram that may not be fragmented and see whether the
    kernel refuses it as too large. The socket must be raw for the ICMP
    Fragmentation Needed reply to be visible.

    Raises:
        IPScoutPermissionError: The raw socket needed for the probe was
            refused, which on a stock macOS means the process is not root.
    """

    try:
        sock = socket.socket(AddressFamily.IPV4.socket_family, socket.SOCK_DGRAM)
    except OSError as exc:  # pragma: no cover - no IPv4 stack at all
        msg = f"path MTU discovery could not open a socket: {exc}"
        raise IPScoutPermissionError(msg) from exc

    try:
        sock.setsockopt(AddressFamily.IPV4.ip_option_level, _IP_DONTFRAG, 1)
    except OSError as exc:
        # No IP_DONTFRAG means there is no way to ask the question at all.
        sock.close()
        msg = (
            f"path MTU discovery needs IP_DONTFRAG, which this platform refused: {exc}. "
            f"Run as root, or read the interface MTU from local_interfaces() instead, "
            f"which is the link MTU rather than the path's"
        )
        raise IPScoutPermissionError(msg) from exc

    try:
        sock.settimeout(1.0)
        sock.connect((address, DISCARD_PORT))
        low, high = _MIN_MTU - _IPV4_UDP_OVERHEAD, _MAX_MTU - _IPV4_UDP_OVERHEAD

        def fits(payload: int) -> bool:
            try:
                sock.send(b"\x00" * payload)
            except OSError:
                # EMSGSIZE: the kernel refused rather than fragmenting.
                return False
            return True

        if not fits(low):
            return None
        while low < high:
            middle = (low + high + 1) // 2
            if fits(middle):
                low = middle
            else:
                high = middle - 1
        return low + _IPV4_UDP_OVERHEAD
    except OSError:
        return None
    finally:
        with contextlib.suppress(OSError):
            sock.close()


def path_mtu(target: str, *, family: AddressFamily | None = None) -> int | None:
    """Return the largest packet that reaches a target without fragmenting.

    Args:
        target: The host, as a name or a literal address.
        family: Which address family to ask about. ``None`` takes the
            resolver's preference.

    Returns:
        The path MTU in bytes, or ``None`` when this platform cannot report
        it, or when the path is not known well enough to say.

    Raises:
        IPScoutResolutionError: The target does not resolve.

    Note:
        ``None`` is a real answer here, not a failure to try. An MTU is used
        to size packets, so a guessed one produces a silent black hole where
        traffic simply disappears - much worse than being told the number is
        unavailable.

    Examples:
        >>> value = path_mtu("127.0.0.1")
        >>> value is None or value > 0
        True

    """

    resolved = resolve_one(target, family=family)

    if IS_LINUX:
        return _linux_mtu(resolved.address, resolved.family)
    if IS_WINDOWS:  # pragma: no cover - Windows only
        if resolved.family is AddressFamily.IPV6:
            # Icmp6SendEcho2 has no don't-fragment option, so there is nothing
            # to bisect on.
            return None
        return _windows_mtu(resolved.address)
    # macOS and the BSDs: no IP_MTU to query, so the only way to learn this
    # is to probe with don't-fragment set and watch for the refusal, which
    # needs a raw socket.
    if resolved.family is AddressFamily.IPV6:
        return None
    return _bsd_mtu(resolved.address)
