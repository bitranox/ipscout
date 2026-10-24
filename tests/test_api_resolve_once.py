"""The api layer resolves a target once and decides everything from that answer.

Two stories, both about deriving one fact from one source:

* The probe method (ICMP, or the TCP fallback) is chosen for the family the
  target RESOLVED to. ICMP availability is per family, so deciding it for IPv4
  and then probing an IPv6 address answers the wrong question.
* ``is_reachable`` asks the resolver once. Asking again for the TCP fallback
  can return a different address (round-robin DNS, v4/v6 preference), so the
  ICMP and TCP legs of one answer would probe two different hosts.

Only stdlib edges are replaced: ``socket.socket`` with a subclass that refuses
the ICMP socket for one family (what a host whose ping sockets are disabled for
that family does), and ``socket.getaddrinfo`` with a spy for one test name.
"""

from __future__ import annotations

import asyncio
import errno
import socket
import threading
from typing import TYPE_CHECKING, Any

import pytest

import ipscout
from ipscout.models import AddressFamily, ProbeMethod

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from ipscout.models import ResponseObject

pytestmark = pytest.mark.os_posix

#: TEST-NET-3 (RFC 5737): reserved, unrouted, so a TCP connect never answers.
NEVER_ANSWERS = "203.0.113.1"

_ROTATING_NAME = "rotating-resolver.invalid"
_ICMP_PROTOCOLS = frozenset({socket.IPPROTO_ICMP, socket.IPPROTO_ICMPV6})

# Read before any test replaces socket.socket, so a skip reflects the real host.
_ICMP_ON_HOST = {family: ipscout.icmp_available(family) for family in AddressFamily}


def _refusing_icmp(refused: frozenset[int]) -> type[socket.socket]:
    """Return a ``socket.socket`` that refuses an ICMP socket in the ``refused`` families.

    A subclass rather than a function, because asyncio and the TCP transport
    still construct ordinary sockets through ``socket.socket`` while it is
    replaced, and anything checking ``isinstance`` must keep working.
    """

    class RefusingIcmpSocket(socket.socket):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            family = kwargs.get("family", args[0] if args else -1)
            proto = kwargs.get("proto", args[2] if len(args) > 2 else 0)
            if family in refused and proto in _ICMP_PROTOCOLS:
                raise PermissionError(errno.EACCES, "ICMP refused for this family by the test")
            super().__init__(*args, **kwargs)

    return RefusingIcmpSocket


def _refuse_icmp(monkeypatch: pytest.MonkeyPatch, *families: AddressFamily) -> None:
    monkeypatch.setattr(socket, "socket", _refusing_icmp(frozenset(f.socket_family for f in families)))


def _require_icmp(family: AddressFamily) -> None:
    if not _ICMP_ON_HOST[family]:
        pytest.skip(f"no {family.value} ICMP socket on this host, so its availability cannot differ from the other family's")


@pytest.fixture
def ipv6_listener() -> Iterator[int]:
    """Bind a real listener on an ephemeral IPv6 loopback port."""

    try:
        listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        listener.bind(("::1", 0))
    except OSError as exc:
        pytest.skip(f"no IPv6 loopback here: {exc}")
    listener.listen(8)
    try:
        yield int(listener.getsockname()[1])
    finally:
        listener.close()


@pytest.fixture
def ipv4_listener() -> Iterator[int]:
    """Bind a real listener on an ephemeral IPv4 loopback port."""

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    try:
        yield int(listener.getsockname()[1])
    finally:
        listener.close()


def _ping_sync(target: str, port: int) -> ResponseObject:
    return ipscout.ping(target, 1, timeout=1.0, interval=0, allow_tcp_fallback=True, tcp_port=port)


def _ping_async(target: str, port: int) -> ResponseObject:
    return asyncio.run(ipscout.aping(target, 1, timeout=1.0, interval=0, allow_tcp_fallback=True, tcp_port=port))


_PINGERS = pytest.mark.parametrize("pinger", [_ping_sync, _ping_async], ids=["ping", "aping"])


@_PINGERS
def test_an_ipv6_target_uses_icmp_when_only_ipv4_icmp_is_refused(
    pinger: Callable[[str, int], ResponseObject], monkeypatch: pytest.MonkeyPatch, ipv6_listener: int
) -> None:
    _require_icmp(AddressFamily.IPV6)
    _refuse_icmp(monkeypatch, AddressFamily.IPV4)

    result = pinger("::1", ipv6_listener)

    # IPv6 ICMP works, so the fallback has nothing to substitute for.
    assert result.method is ProbeMethod.ICMP
    assert result.reached


@_PINGERS
def test_an_ipv6_target_falls_back_to_tcp_when_only_ipv6_icmp_is_refused(
    pinger: Callable[[str, int], ResponseObject], monkeypatch: pytest.MonkeyPatch, ipv6_listener: int
) -> None:
    _require_icmp(AddressFamily.IPV4)
    _refuse_icmp(monkeypatch, AddressFamily.IPV6)

    result = pinger("::1", ipv6_listener)

    # IPv4 ICMP working says nothing about an IPv6 probe; the fallback was
    # allowed and IPv6 ICMP is unavailable, so TCP is what must have run.
    assert result.method is ProbeMethod.TCP
    assert result.reached


class RotatingResolver:
    """Stands in for ``socket.getaddrinfo``: each lookup of one name answers the next address.

    Every other name goes to the real resolver. The calling threads are kept,
    so the async test can also check the lookup stayed off the loop thread.
    """

    def __init__(self, *addresses: str) -> None:
        self._real = socket.getaddrinfo
        self._addresses = list(addresses)
        self.threads: list[int] = []

    def __call__(self, host: str | bytes | None, *args: Any, **kwargs: Any) -> object:
        if host != _ROTATING_NAME:
            return self._real(host, *args, **kwargs)
        self.threads.append(threading.get_ident())
        address = self._addresses[min(len(self.threads), len(self._addresses)) - 1]
        return [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", (address, 0))]


@pytest.fixture
def rotating(monkeypatch: pytest.MonkeyPatch) -> RotatingResolver:
    # The first answer is the live listener, every later one a host that never answers.
    resolver = RotatingResolver("127.0.0.1", NEVER_ANSWERS)
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    return resolver


def test_is_reachable_probes_both_legs_at_the_one_address_it_resolved(rotating: RotatingResolver, monkeypatch: pytest.MonkeyPatch, ipv4_listener: int) -> None:
    # ICMP refused everywhere: the ICMP leg fails, so the TCP leg decides.
    _refuse_icmp(monkeypatch, AddressFamily.IPV4, AddressFamily.IPV6)

    reachable = ipscout.is_reachable(_ROTATING_NAME, timeout=1.0, tcp_port=ipv4_listener)

    assert len(rotating.threads) == 1, "the name was resolved more than once"
    assert reachable is True


def test_ais_reachable_probes_both_legs_at_the_one_address_it_resolved(rotating: RotatingResolver, monkeypatch: pytest.MonkeyPatch, ipv4_listener: int) -> None:
    _refuse_icmp(monkeypatch, AddressFamily.IPV4, AddressFamily.IPV6)

    async def attempt() -> tuple[bool, int]:
        return await ipscout.ais_reachable(_ROTATING_NAME, timeout=1.0, tcp_port=ipv4_listener), threading.get_ident()

    reachable, loop_thread = asyncio.run(attempt())

    assert len(rotating.threads) == 1, "the name was resolved more than once"
    assert loop_thread not in rotating.threads
    assert reachable is True


def _recording_icmp(opened: list[int]) -> type[socket.socket]:
    """Return a ``socket.socket`` that records the family of every ICMP socket opened through it."""

    class RecordingSocket(socket.socket):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            family = kwargs.get("family", args[0] if args else -1)
            proto = kwargs.get("proto", args[2] if len(args) > 2 else 0)
            if proto in _ICMP_PROTOCOLS:
                opened.append(int(family))
            super().__init__(*args, **kwargs)

    return RecordingSocket


def _ping_zero_times_sync(target: str) -> ResponseObject:
    return ipscout.ping(target, 0, allow_tcp_fallback=True)


def _ping_zero_times_async(target: str) -> ResponseObject:
    return asyncio.run(ipscout.aping(target, 0, allow_tcp_fallback=True))


@pytest.mark.parametrize("pinger", [_ping_zero_times_sync, _ping_zero_times_async], ids=["ping", "aping"])
def test_a_bad_argument_is_refused_before_the_fallback_check_opens_an_icmp_socket(
    pinger: Callable[[str], ResponseObject], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Choosing between ICMP and the TCP fallback asks the machine whether an
    # ICMP socket opens. A request that validation rejects must never get that
    # far: validation comes before anything touches the machine.
    opened: list[int] = []
    monkeypatch.setattr(socket, "socket", _recording_icmp(opened))

    with pytest.raises(ValueError, match="times"):
        pinger("127.0.0.1")

    assert opened == [], "an ICMP socket was opened for a request that validation rejects"


def test_the_icmp_recording_socket_sees_the_fallback_check(monkeypatch: pytest.MonkeyPatch) -> None:
    # Liveness for the test above: a VALID fallback request does open the ICMP
    # socket that answers the availability question, so an empty record there
    # means "never asked", not "the spy cannot see it".
    _require_icmp(AddressFamily.IPV4)
    opened: list[int] = []
    monkeypatch.setattr(socket, "socket", _recording_icmp(opened))

    ipscout.ping("127.0.0.1", 1, timeout=1.0, interval=0, allow_tcp_fallback=True)

    assert int(socket.AF_INET) in opened
