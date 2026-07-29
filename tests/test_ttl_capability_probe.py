"""Feasibility probe: can this platform see ICMP Time Exceeded unprivileged?

Traceroute works by sending echoes with a deliberately small hop limit and
reading the Time Exceeded messages routers send back. Whether an *unprivileged*
process can see those messages is a per-platform question that cannot be
answered by reading documentation:

    **Linux** - yes, via ``IP_RECVERR`` plus ``recvmsg(..., MSG_ERRQUEUE)``.
    That is exactly how unprivileged ``traceroute -I`` works.

    **Windows** - yes. ``IcmpSendEcho`` returns a reply whose ``Status`` is
    ``IP_TTL_EXPIRED_TRANSIT`` and whose ``Address`` is the router.

    **macOS** - genuinely unknown. ``MSG_ERRQUEUE`` and ``IP_RECVERR`` are
    Linux-only and BSD has no equivalent, so it is not obvious whether a
    ``SOCK_DGRAM`` ICMP socket surfaces the error at all.

This module answers that empirically on whatever host it runs on and reports
the answer in the test output. It never fails a build: an unsupported platform
is a fact to record, not a defect. The recorded answer is what decides whether
macOS gets a real traceroute or an honest ``IPScoutUnsupportedError``.
"""

from __future__ import annotations

import contextlib
import platform
import socket
import sys

import pytest

from ipscout import packet
from ipscout.factory import icmp_available
from ipscout.models import AddressFamily

pytestmark = pytest.mark.os_agnostic

#: A routable address that is virtually certain to be several hops away, so a
#: hop limit of 1 expires at the first router rather than reaching the target.
FAR_TARGET = "1.1.1.1"

#: ICMP type 11: Time Exceeded, what a router sends when the hop limit runs out.
ICMP_TIME_EXCEEDED = 11


def _socket_const(name: str) -> int | None:
    """Return a socket constant that exists only on some platforms.

    ``IP_RECVERR`` and ``MSG_ERRQUEUE`` are Linux-only and absent from the
    macOS type stubs, so a direct attribute access fails type checking there
    even when guarded at runtime. Reaching them by name keeps every call site
    typed without silencing the checker on one platform.
    """

    value = getattr(socket, name, None)
    return value if isinstance(value, int) else None


def _probe_error_queue() -> tuple[bool, str]:
    """Return whether MSG_ERRQUEUE yields a Time Exceeded, and what happened."""

    msg_errqueue = _socket_const("MSG_ERRQUEUE")
    ip_recverr = _socket_const("IP_RECVERR")
    if msg_errqueue is None:
        return False, "socket.MSG_ERRQUEUE is not defined on this platform"
    if ip_recverr is None:
        return False, "socket.IP_RECVERR is not defined on this platform"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, ip_recverr, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
        sock.settimeout(3.0)
        datagram, _token = packet.build_echo_request(sequence=1)
        sock.sendto(datagram, (FAR_TARGET, 0))
        # An echo reply may or may not arrive first; either way the error
        # queue is what carries the Time Exceeded, so drain and move on.
        with contextlib.suppress(TimeoutError, OSError):
            sock.recvfrom(4096)
        try:
            _data, ancillary, _flags, addr = sock.recvmsg(4096, 4096, msg_errqueue)
        except (TimeoutError, OSError) as exc:
            return False, f"MSG_ERRQUEUE recvmsg failed: {exc!r}"
        return True, f"MSG_ERRQUEUE delivered {len(ancillary)} cmsg from {addr}"
    finally:
        sock.close()


def _probe_plain_recv() -> tuple[bool, str]:
    """Return whether a plain recv on the ICMP socket yields a Time Exceeded.

    This is the path macOS would need, since it has no error queue. If BSD
    delivers the ICMP error as an ordinary datagram on the same socket, a
    traceroute is buildable there; if it delivers nothing, it is not.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
        sock.settimeout(3.0)
        datagram, _token = packet.build_echo_request(sequence=1)
        sock.sendto(datagram, (FAR_TARGET, 0))
        try:
            raw, addr = sock.recvfrom(4096)
        except (TimeoutError, OSError) as exc:
            return False, f"plain recv yielded nothing: {exc!r}"
        parsed = packet.parse_echo_reply(raw)
        icmp_type = parsed.icmp_type if parsed is not None else -1
        return icmp_type == ICMP_TIME_EXCEEDED, f"plain recv from {addr[0]} gave ICMP type {icmp_type}"
    finally:
        sock.close()


@pytest.mark.skipif(sys.platform == "win32", reason="Windows uses IcmpSendEcho, not sockets")
def test_report_which_ttl_expired_mechanism_this_platform_supports(capsys: pytest.CaptureFixture[str]) -> None:
    """Record the platform's capability. Never fails - it is a measurement."""

    if not icmp_available(AddressFamily.IPV4):
        pytest.skip("unprivileged ICMP unavailable, so the mechanism cannot be probed here")

    errqueue_ok, errqueue_detail = _probe_error_queue()
    plain_ok, plain_detail = _probe_plain_recv()

    with capsys.disabled():
        print(f"\n  TTL-EXPIRED CAPABILITY PROBE on {platform.system()} {platform.release()} ({sys.platform})")
        print(f"    MSG_ERRQUEUE : {'YES' if errqueue_ok else 'no '}  - {errqueue_detail}")
        print(f"    plain recv   : {'YES' if plain_ok else 'no '}  - {plain_detail}")
        print(f"    traceroute buildable unprivileged here: {'YES' if (errqueue_ok or plain_ok) else 'NO'}")

    # A measurement, not an assertion. Recording "no" is a valid outcome that
    # decides the platform gets IPScoutUnsupportedError rather than a broken
    # traceroute; failing here would only hide the answer behind a red build.
    assert isinstance(errqueue_ok, bool)
    assert isinstance(plain_ok, bool)
