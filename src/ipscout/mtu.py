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
import socket
import sys
from typing import Any

from .errors import IPScoutPermissionError, IPScoutUnsupportedError
from .models import AddressFamily
from .resolve import resolve_one

__all__ = ["path_mtu"]

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

#: IP_MTU_DISCOVER / IP_PMTUDISC_DO, and the option holding the answer. Only
#: Linux defines these, and CPython exposes them there.
_IP_MTU_DISCOVER = 10
_IP_PMTUDISC_DO = 2
_IP_MTU = 14
_IPV6_MTU_DISCOVER = 23
_IPV6_MTU = 24

#: IP_FLAG_DF, in the Windows echo options.
_IP_FLAG_DF = 0x02

#: IP_PACKET_TOO_BIG: the reply saying the probe would have to fragment.
_IP_PACKET_TOO_BIG = 11009

#: The search bounds for the Windows probe. 68 is the smallest IPv4 MTU a host
#: must support; 9000 covers jumbo frames.
_MIN_MTU = 68
_MAX_MTU = 9000

#: Bytes of header in front of the payload, which is what the probe varies.
_IPV4_ICMP_OVERHEAD = 28
_IPV4_UDP_OVERHEAD = 28

#: IP_DONTFRAG, the BSD option that refuses to fragment rather than doing it.
_IP_DONTFRAG = 28


def _linux_mtu(address: str, family: AddressFamily) -> int | None:
    """Return the kernel's own path MTU for a destination, sending nothing.

    Connecting a datagram socket picks the route without putting anything on
    the wire, and the kernel already knows that route's MTU.
    """

    if family is AddressFamily.IPV6:
        af, level, discover, option = socket.AF_INET6, socket.IPPROTO_IPV6, _IPV6_MTU_DISCOVER, _IPV6_MTU
    else:
        af, level, discover, option = socket.AF_INET, socket.IPPROTO_IP, _IP_MTU_DISCOVER, _IP_MTU

    try:
        with socket.socket(af, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(level, discover, _IP_PMTUDISC_DO)
            # Port 9 is the discard service; nothing is sent, so it only has
            # to be a valid port for connect() to pick a route.
            sock.connect((address, 9))
            value = sock.getsockopt(level, option)
    except OSError:
        return None
    return value if value > 0 else None


def _windows_mtu(address: str) -> int | None:  # pragma: no cover - Windows only
    """Return the path MTU by probing with the don't-fragment flag set.

    Windows has no query for this, so the size is narrowed by bisection: the
    largest payload that is not answered with "packet too big" is the answer.
    """

    import ctypes  # noqa: PLC0415 - used only on this path

    from .winapi import (  # noqa: PLC0415 - Windows-only import
        ICMP_ECHO_REPLY,
        INVALID_HANDLE_VALUE,
        IP_OPTION_INFORMATION,
        iphlpapi,
        last_error,
        string_to_ipv4,
    )

    try:
        library: Any = iphlpapi()
    except IPScoutUnsupportedError:
        return None

    handle = library.IcmpCreateFile()
    if handle in (None, INVALID_HANDLE_VALUE):
        return None

    def fits(payload: int) -> bool:
        options = IP_OPTION_INFORMATION(Ttl=64, Tos=0, Flags=_IP_FLAG_DF, OptionsSize=0, OptionsData=None)
        request = b"\x00" * payload
        reply = (ctypes.c_uint8 * (payload + ctypes.sizeof(ICMP_ECHO_REPLY) + 64))()
        count = library.IcmpSendEcho(handle, string_to_ipv4(address), request, payload, ctypes.byref(options), reply, len(reply), 2000)
        if count:
            return True
        return last_error() != _IP_PACKET_TOO_BIG

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
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as exc:  # pragma: no cover - no IPv4 stack at all
        msg = f"path MTU discovery could not open a socket: {exc}"
        raise IPScoutPermissionError(msg) from exc

    try:
        sock.setsockopt(socket.IPPROTO_IP, _IP_DONTFRAG, 1)
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
        sock.connect((address, 9))
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

    address, resolved_family = resolve_one(target, family=family)

    if IS_LINUX:
        return _linux_mtu(address, resolved_family)
    if IS_WINDOWS:  # pragma: no cover - Windows only
        if resolved_family is AddressFamily.IPV6:
            # Icmp6SendEcho2 has no don't-fragment option, so there is nothing
            # to bisect on.
            return None
        return _windows_mtu(address)
    # macOS and the BSDs: no IP_MTU to query, so the only way to learn this
    # is to probe with don't-fragment set and watch for the refusal, which
    # needs a raw socket.
    if resolved_family is AddressFamily.IPV6:
        return None
    return _bsd_mtu(address)
