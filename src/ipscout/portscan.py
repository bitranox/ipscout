"""Port scanning, by full connect or by half-open SYN.

Contents:
    scan_ports / ascan_ports: What state each of a set of ports is in.
    syn_scan: The half-open scan, used through ``method=ScanMethod.SYN``.
    parse_ports: Turn a ``22,80,8000-8100`` specification into port numbers.

Note:
    Two methods, measuring different things.

    A **connect** scan completes the handshake. It needs no privileges and
    works everywhere, and it lands in the target's logs as a real connection.
    It still separates a refused port from a silent one: a refusal is an
    answer, a timeout is not.

    A **SYN** scan never completes the handshake, so it is quieter and faster,
    and it needs a raw socket - root or ``CAP_NET_RAW`` - on Linux and macOS.
    Windows has blocked raw TCP sends since XP SP2, so no privilege level
    makes it available there. Where it cannot run, it raises rather than
    quietly falling back to a connect scan, which would report a different
    measurement under the same name.

"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import sys
import time

from .errors import IPScoutPermissionError, IPScoutUnsupportedError
from .models import PortState, ScanMethod
from .routes import query_route
from .tcpsyn import build_syn, parse_tcp_reply

__all__ = ["DEFAULT_CONCURRENCY", "MAX_PORT", "ascan_ports", "parse_ports", "scan_ports", "syn_scan"]

IS_WINDOWS = sys.platform == "win32"

#: Enough to finish a wide scan quickly without exhausting file handles.
DEFAULT_CONCURRENCY = 256

#: Ports are 16-bit, and zero is not a usable destination.
MIN_PORT = 1
MAX_PORT = 65535

#: The ephemeral range a SYN scan picks its source port from.
_EPHEMERAL_LOW = 32768
_EPHEMERAL_HIGH = 60999


def parse_ports(specification: str) -> list[int]:
    """Turn a port specification into the ports it names.

    Args:
        specification: Comma-separated ports and ranges, as in
            ``22,80,443,8000-8100``. Whitespace is ignored.

    Returns:
        The ports, sorted and deduplicated, so an overlapping specification
        does not scan anything twice.

    Raises:
        ValueError: A port is out of range, a range runs backwards, or a piece
            is not a number at all.

    Examples:
        >>> parse_ports("22,80,443")
        [22, 80, 443]
        >>> parse_ports("8000-8003")
        [8000, 8001, 8002, 8003]
        >>> parse_ports("80,80,79-81")
        [79, 80, 81]

    """

    found: set[int] = set()
    for piece in specification.split(","):
        text = piece.strip()
        if not text:
            continue
        if "-" in text:
            low_text, _, high_text = text.partition("-")
            low, high = _port(low_text), _port(high_text)
            if low > high:
                msg = f"port range runs backwards: {text!r}"
                raise ValueError(msg)
            found.update(range(low, high + 1))
        else:
            found.add(_port(text))
    return sorted(found)


def _port(text: str) -> int:
    """Return one port number, or raise saying why it is not one."""

    try:
        value = int(text.strip())
    except ValueError:
        msg = f"not a port number: {text.strip()!r}"
        raise ValueError(msg) from None
    if not MIN_PORT <= value <= MAX_PORT:
        msg = f"port out of range 1-{MAX_PORT}: {value}"
        raise ValueError(msg)
    return value


def _wanted(ports: str | list[int]) -> list[int]:
    """Return the ports to scan, however they were specified."""

    return parse_ports(ports) if isinstance(ports, str) else sorted(set(ports))


def _source_for(host: str) -> str | None:
    """Return the address this host would send to ``host`` from.

    The route lookup answers this where the kernel recorded a preferred
    source, but it often does not for on-link and loopback destinations - the
    loopback route on a stock CI runner carries none. Connecting a datagram
    socket resolves it in every one of those cases: it picks the route and
    binds a local address without putting anything on the wire.
    """

    route = query_route(host)
    if route is not None and route.source:
        return route.source

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # Port 9 is discard; nothing is sent, so this only has to be a
            # valid destination for the kernel to choose a source for.
            sock.connect((host, 9))
            name = sock.getsockname()
    except OSError:
        return None
    return name[0] if isinstance(name, tuple) and isinstance(name[0], str) else None


def syn_scan(host: str, ports: list[int], *, timeout: float = 1.0) -> dict[int, PortState]:
    """Scan ports half-open, sending a SYN and never completing the handshake.

    Args:
        host: The target address.
        ports: The ports to ask about.
        timeout: Seconds to wait for replies, in total.

    Returns:
        Each port mapped to its state. A SYN-ACK is ``OPEN``, a RST is
        ``CLOSED``, and silence is ``FILTERED`` - a distinction a connect scan
        can only partly make.

    Raises:
        IPScoutPermissionError: The process may not open a raw socket, which
            means root or ``CAP_NET_RAW`` on Linux and macOS.
        IPScoutUnsupportedError: Windows, which has blocked raw TCP sends
            since XP SP2, or no route to the target.

    Note:
        Never falls back to a connect scan. The two measure different things,
        and silently substituting one would report a full handshake as though
        it had been a half-open probe.

    """

    if IS_WINDOWS:  # pragma: no cover - Windows only
        msg = "Windows blocks raw TCP sends, so a SYN scan is unavailable at any privilege level; use the connect method"
        raise IPScoutUnsupportedError(msg)

    source_ip = _source_for(host)
    if source_ip is None:
        msg = f"no route to {host}, so no source address to send a SYN from"
        raise IPScoutUnsupportedError(msg)

    try:
        sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError as exc:
        msg = (
            f"a SYN scan needs a raw socket, so root or CAP_NET_RAW: {exc}. "
            f"Grant it with 'setcap cap_net_raw+ep $(readlink -f $(which python3))', run as root, "
            f"or use the connect method, which needs no privileges"
        )
        raise IPScoutPermissionError(msg) from exc
    except OSError as exc:  # pragma: no cover - no raw socket support at all
        msg = f"a SYN scan needs a raw socket, which this host refused: {exc}"
        raise IPScoutPermissionError(msg) from exc

    # Ports the target never answers about stay FILTERED, which is the honest
    # reading of silence rather than an assumption that they are closed.
    found: dict[int, PortState] = dict.fromkeys(ports, PortState.FILTERED)
    source_port = _EPHEMERAL_LOW + (os.getpid() % (_EPHEMERAL_HIGH - _EPHEMERAL_LOW))

    try:
        receiver.settimeout(timeout)
        for port in ports:
            packet = build_syn(source_ip=source_ip, target_ip=host, source_port=source_port, target_port=port)
            with contextlib.suppress(OSError):
                sender.sendto(packet, (host, port))

        # One socket collects every reply. A raw TCP socket sees all TCP
        # traffic on the host, so each packet is matched on the port pair
        # before it is believed.
        deadline = time.monotonic() + timeout
        outstanding = set(ports)
        while outstanding and time.monotonic() < deadline:
            receiver.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                packet = receiver.recv(65535)
            except (TimeoutError, OSError):
                break
            for port in list(outstanding):
                state = parse_tcp_reply(packet, source_port=source_port, target_port=port)
                if state is not None:
                    found[port] = state
                    outstanding.discard(port)
                    break
        return found
    finally:
        with contextlib.suppress(OSError):
            sender.close()
        with contextlib.suppress(OSError):
            receiver.close()


def scan_ports(
    host: str,
    ports: str | list[int],
    *,
    method: ScanMethod = ScanMethod.CONNECT,
    timeout: float = 1.0,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> dict[int, PortState]:
    """Return the state of each of a set of ports.

    Args:
        host: The target, as a name or a literal address.
        ports: Either a specification like ``"22,80,8000-8100"`` or a list of
            port numbers.
        method: ``CONNECT`` completes the handshake and needs no privileges.
            ``SYN`` is half-open and needs a raw socket.
        timeout: Seconds to wait per port.
        concurrency: How many connects are in flight at once. Ignored by the
            SYN method, which sends everything and then listens once.

    Returns:
        Every port asked about, mapped to its state. Ports not asked about do
        not appear, so the result cannot be read as a statement about a whole
        range.

    Raises:
        ValueError: The port specification is malformed.
        IPScoutPermissionError: A SYN scan without the privilege it needs.
        IPScoutUnsupportedError: A SYN scan where the platform has none.
        RuntimeError: The connect method called from inside a running event
            loop; ``await ascan_ports(...)`` there instead.

    Examples:
        >>> result = scan_ports("127.0.0.1", "1", timeout=0.2)
        >>> list(result)
        [1]

    """

    wanted = _wanted(ports)
    if method is ScanMethod.SYN:
        return syn_scan(host, wanted, timeout=timeout)

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(ascan_ports(host, wanted, timeout=timeout, concurrency=concurrency))
    msg = "scan_ports() cannot run inside an event loop; await ascan_ports() instead"
    raise RuntimeError(msg)


async def ascan_ports(host: str, ports: str | list[int], *, timeout: float = 1.0, concurrency: int = DEFAULT_CONCURRENCY) -> dict[int, PortState]:
    """Return the state of each of a set of ports, by full connect.

    Args:
        host: The target, as a name or a literal address.
        ports: Either a specification like ``"22,80,8000-8100"`` or a list of
            port numbers.
        timeout: Seconds to wait per port.
        concurrency: How many connects are in flight at once.

    Returns:
        Every port asked about, mapped to its state. A refusal is ``CLOSED``
        and silence is ``FILTERED``: a refusal is an answer, and conflating
        the two would hide a firewall.

    Raises:
        ValueError: The port specification is malformed.

    """

    wanted = _wanted(ports)
    limit = asyncio.Semaphore(max(1, concurrency))

    async def probe(port: int) -> tuple[int, PortState]:
        async with limit:
            try:
                _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            except ConnectionRefusedError:
                return port, PortState.CLOSED
            except (TimeoutError, asyncio.TimeoutError):
                return port, PortState.FILTERED
            except (OSError, ValueError):
                # Unreachable, or a name that does not resolve: not an answer
                # about the port itself.
                return port, PortState.FILTERED
            writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError, ConnectionError):
                await writer.wait_closed()
            return port, PortState.OPEN

    results = await asyncio.gather(*(probe(port) for port in wanted))
    return dict(results)
