"""Port scanning, by full connect or by half-open SYN.

Contents:
    scan_ports / ascan_ports: What state each of a set of ports is in.
    syn_scan: The half-open scan, used through ``method=ScanMethod.SYN``.
    parse_ports: Turn a ``22,80,8000-8100`` specification into port numbers.

Note:
    Two methods, measuring different things.

    A **connect** scan completes the handshake. It needs no privileges and
    works everywhere, and it lands in the target's logs as a real connection.
    It separates a refused port from a silent one on Linux and macOS: a
    refusal is an answer, a timeout is not.

    Windows does not draw that line. Measured on a runner, a closed loopback
    port there neither refuses nor resets within the timeout, so a connect
    scan reports FILTERED where the other two report CLOSED. Read a Windows
    CLOSED as reliable and a Windows FILTERED as "no answer, for one of two
    reasons"; a SYN scan distinguishes them, and is unavailable there.

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
import secrets
import socket
import sys
import time
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Strict, ValidationError

from .deadline import seconds_left
from .errors import IPScoutPermissionError, IPScoutUnsupportedError, refused_arguments, setcap_command
from .models import DISCARD_PORT, MAX_PORT, AddressFamily, Port, PortState, ScanMethod, Timeout, require_port
from .packet import MAX_IP_LENGTH
from .pool import Concurrency, gather_bounded
from .resolve import ResolvedTarget, resolve_one
from .routes import query_route
from .sockerr import is_refusal
from .tcpsyn import build_syn, read_reply

__all__ = [
    "DEFAULT_CONCURRENCY",
    "DEFAULT_TIMEOUT",
    "MAX_PORT",
    "PortScanSettings",
    "ascan_ports",
    "choose_source_port",
    "parse_ports",
    "scan_ports",
    "syn_scan",
]

IS_WINDOWS = sys.platform == "win32"

#: Enough to finish a wide scan quickly without exhausting file handles.
DEFAULT_CONCURRENCY = 256

#: Default seconds to wait for one port to answer a connect or a SYN.
DEFAULT_TIMEOUT = 1.0

#: The ephemeral range a SYN scan picks its source port from, at random.
#: A predictable choice collides with a concurrent scan in the same
#: process, and both then read replies meant for the other.
_EPHEMERAL_LOW = 32768
_EPHEMERAL_HIGH = 60999


class PortScanSettings(BaseModel):
    """How a scan probes, how long it waits and how many connects it keeps in flight, checked once.

    The bounds are declared on the fields, so the check and its documentation
    cannot drift apart, and the command line reads these same declarations for
    its options. Strict: ``"1"`` is not a timeout and ``"syn"`` is not a
    :class:`ScanMethod`.

    Examples:
        >>> PortScanSettings().concurrency == DEFAULT_CONCURRENCY
        True
        >>> PortScanSettings(timeout=0)
        Traceback (most recent call last):
        ...
        pydantic_core._pydantic_core.ValidationError: ...

    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    #: Seconds to wait for one port, or for every SYN reply in total, under the
    #: library's one timeout rule. Zero never waits and reports every port
    #: FILTERED, which reads as a firewall rather than as the caller's mistake.
    timeout: Timeout = DEFAULT_TIMEOUT
    #: Connects in flight at once, under the pool's one concurrency rule.
    concurrency: Concurrency = DEFAULT_CONCURRENCY
    #: Full connect or half-open SYN. A member, never its value: a string that
    #: merely equals one would otherwise fail the identity test and run the
    #: other method under the name the caller asked for.
    method: ScanMethod = ScanMethod.CONNECT


def _settings(*, timeout: float, concurrency: int = DEFAULT_CONCURRENCY, method: ScanMethod = ScanMethod.CONNECT) -> PortScanSettings:
    """Return the checked settings, or raise one ``ValueError`` naming every bad argument."""

    try:
        return PortScanSettings(timeout=timeout, concurrency=concurrency, method=method)
    except ValidationError as exc:
        raise refused_arguments("port scan", exc) from exc


class _PortList(BaseModel):
    """A list of port numbers, each an ``int`` in range, checked before anything is sent.

    The container is lax, so a tuple or a set of ports reads as meant, while
    every entry is strict: ``True`` and ``80.5`` are not port numbers, and
    letting them through would report a result keyed by something no host
    can listen on.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ports: list[Annotated[Port, Strict()]]


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
    return require_port(value)


def _listed(ports: list[int]) -> list[int]:
    """Return a list of ports checked entry by entry, in the order given.

    Raises:
        ValueError: An entry is not an ``int`` (``True`` included) or is outside
            ``MIN_PORT``-``MAX_PORT``, as
            ``port scan refused its arguments: ports.<index>: <reason>``.
    """

    try:
        return _PortList(ports=ports).ports
    except ValidationError as refused:
        raise refused_arguments("port scan", refused) from refused


def _distinct(ports: list[int]) -> list[int]:
    """Return a list of ports checked, each once, in port order.

    The one normalisation every entry point applies to a list, so a duplicate
    is probed once and every result lists its ports in the same order, whether
    it came from a connect scan or a SYN scan. A list is held to the same range
    as a specification, so a port no host can listen on is refused before any
    connect or SYN is attempted.
    """

    return sorted(set(_listed(ports)))


def _wanted(ports: str | list[int]) -> list[int]:
    """Return the ports to scan, given as a specification string or a list: each once, in port order."""

    return parse_ports(ports) if isinstance(ports, str) else _distinct(ports)


def choose_source_port() -> int:
    """Return the port a scan will send from and match replies on.

    Random per scan rather than derived from the process id. A per-process
    value means two concurrent scans share it, and since replies are claimed
    on the port pair, each would then read the other's and report them against
    its own target - silently, and only under the concurrency a scan is used
    for.

    Examples:
        >>> port = choose_source_port()
        >>> 32768 <= port < 61000
        True

    """

    return _EPHEMERAL_LOW + secrets.randbelow(_EPHEMERAL_HIGH - _EPHEMERAL_LOW)


def _source_for(address: str) -> str | None:
    """Return the address this host would send to ``address`` from.

    The route lookup answers this where the kernel recorded a preferred
    source, but it often does not for on-link and loopback destinations - the
    loopback route on a stock CI runner carries none. Connecting a datagram
    socket resolves it in every one of those cases: it picks the route and
    binds a local address without putting anything on the wire.
    """

    route = query_route(address)
    if route is not None and route.source:
        return route.source

    try:
        with socket.socket(AddressFamily.IPV4.socket_family, socket.SOCK_DGRAM) as sock:
            # Nothing is sent, so this only has to be a valid destination for
            # the kernel to choose a source for.
            sock.connect((address, DISCARD_PORT))
            name = sock.getsockname()
    except OSError:
        return None
    return name[0] if isinstance(name, tuple) and isinstance(name[0], str) else None


def syn_scan(host: str, ports: list[int], *, timeout: float = DEFAULT_TIMEOUT) -> dict[int, PortState]:
    """Scan ports half-open, sending a SYN and never completing the handshake.

    Args:
        host: The target, as a name or an IPv4 literal. A name is resolved
            once, here, and every SYN goes to that one address.
        ports: The ports to ask about. A port listed twice is sent one SYN.
        timeout: Seconds to wait for replies, in total.

    Returns:
        Each port mapped to its state, in port order as :func:`scan_ports`
        returns it. A SYN-ACK is ``OPEN``, a RST is ``CLOSED``, and silence is
        ``FILTERED`` - a distinction a connect scan can only partly make.

    Raises:
        IPScoutPermissionError: The process may not open a raw socket, which
            means root or ``CAP_NET_RAW`` on Linux and macOS.
        IPScoutUnsupportedError: Windows, which has blocked raw TCP sends
            since XP SP2, or no route to the target.
        IPScoutResolutionError: ``host`` has no IPv4 address.
        ValueError: A port is not an ``int`` or is outside
            ``MIN_PORT``-``MAX_PORT``, or ``timeout`` is not above 0 and at
            most ``MAX_TIMEOUT``. Checked first, so a bad argument is reported
            as such whatever the privileges.

    Note:
        Never falls back to a connect scan. The two measure different things,
        and silently substituting one would report a full handshake as though
        it had been a half-open probe.

    """

    wanted = _distinct(ports)
    return _half_open(host, wanted, _settings(timeout=timeout))


def _half_open(host: str, ports: list[int], settings: PortScanSettings) -> dict[int, PortState]:
    """Run a SYN scan of ports and settings already checked by the caller."""

    if IS_WINDOWS:  # pragma: no cover - Windows only
        msg = "Windows blocks raw TCP sends, so a SYN scan is unavailable at any privilege level; use the connect method"
        raise IPScoutUnsupportedError(msg)

    # Resolved once: the packet builder and the reply matcher both need the
    # address literal, and a name resolved per use could answer differently.
    # IPv4 only, because the raw socket and the packet builder are.
    target = resolve_one(host, family=AddressFamily.IPV4)
    source_ip = _source_for(target.address)
    if source_ip is None:
        msg = f"no route to {host}, so no source address to send a SYN from"
        raise IPScoutUnsupportedError(msg)

    try:
        sender = socket.socket(AddressFamily.IPV4.socket_family, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sender.setsockopt(AddressFamily.IPV4.ip_option_level, socket.IP_HDRINCL, 1)
        receiver = socket.socket(AddressFamily.IPV4.socket_family, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError as exc:
        msg = (
            f"a SYN scan needs a raw socket, so root or CAP_NET_RAW: {exc}. "
            f"Grant it with '{setcap_command('cap_net_raw')}', run as root, "
            f"or use the connect method, which needs no privileges"
        )
        raise IPScoutPermissionError(msg) from exc
    except OSError as exc:  # pragma: no cover - no raw socket support at all
        msg = f"a SYN scan needs a raw socket, which this host refused: {exc}"
        raise IPScoutPermissionError(msg) from exc

    return _syn_exchange(sender, receiver, target.address, ports, source_ip=source_ip, timeout=settings.timeout)


def _syn_exchange(  # noqa: PLR0913 - one parameter per piece of the exchange, all required
    sender: socket.socket,
    receiver: socket.socket,
    host: str,
    ports: list[int],
    *,
    source_ip: str,
    timeout: float,
) -> dict[int, PortState]:  # pragma: no cover - past the raw socket, so privileged only
    """Send the SYNs and collect whatever answers within the timeout."""

    # Ports the target never answers about stay FILTERED, which is the honest
    # reading of silence rather than an assumption that they are closed.
    found: dict[int, PortState] = dict.fromkeys(ports, PortState.FILTERED)
    source_port = choose_source_port()

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
            receiver.settimeout(seconds_left(deadline))
            try:
                packet = receiver.recv(MAX_IP_LENGTH)
            except (TimeoutError, OSError):
                break
            # The packet names its own port, so it is read once and looked
            # up. Testing every outstanding port against it is quadratic.
            answer = read_reply(packet, source_port=source_port, peer_ip=host)
            if answer is not None and answer.port in outstanding:
                found[answer.port] = answer.state
                outstanding.discard(answer.port)
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
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> dict[int, PortState]:
    """Return the state of each of a set of ports.

    Args:
        host: The target, as a name or a literal address. A name is resolved
            once, before the first probe, and every port is asked of that one
            address.
        ports: Either a specification like ``"22,80,8000-8100"`` or a list of
            port numbers.
        method: ``CONNECT`` completes the handshake and needs no privileges.
            ``SYN`` is half-open and needs a raw socket.
        timeout: Seconds to wait per port.
        concurrency: How many connects are in flight at once. Ignored by the
            SYN method, which sends everything and then listens once, but
            checked for it too.

    Returns:
        Every port asked about, mapped to its state. Ports not asked about do
        not appear, so the result cannot be read as a statement about a whole
        range.

    Raises:
        ValueError: The port specification is malformed, a listed port is
            not an ``int`` (``True`` included) or is outside
            ``MIN_PORT``-``MAX_PORT``, ``timeout`` is not above 0 and at most
            ``MAX_TIMEOUT``, ``concurrency`` is below 1, or ``method`` is not
            a :class:`ScanMethod` member.
        IPScoutResolutionError: ``host`` does not resolve. Raised rather than
            reporting every port FILTERED, which would read as a firewall.
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
    settings = _settings(timeout=timeout, concurrency=concurrency, method=method)
    if settings.method is ScanMethod.SYN:
        return _half_open(host, wanted, settings)

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_connect_scan(resolve_one(host), wanted, settings))
    msg = "scan_ports() cannot run inside an event loop; await ascan_ports() instead"
    raise RuntimeError(msg)


async def ascan_ports(host: str, ports: str | list[int], *, timeout: float = DEFAULT_TIMEOUT, concurrency: int = DEFAULT_CONCURRENCY) -> dict[int, PortState]:
    """Return the state of each of a set of ports, by full connect.

    Args:
        host: The target, as a name or a literal address. A name is resolved
            once, in a thread so the event loop keeps running, and every port
            is asked of that one address.
        ports: Either a specification like ``"22,80,8000-8100"`` or a list of
            port numbers.
        timeout: Seconds to wait per port.
        concurrency: How many connects are in flight at once.

    Returns:
        Every port asked about, mapped to its state. A refusal is ``CLOSED``
        and silence is ``FILTERED``: a refusal is an answer, and conflating
        the two would hide a firewall.

    Raises:
        ValueError: The port specification is malformed, a listed port is
            not an ``int`` (``True`` included) or is outside
            ``MIN_PORT``-``MAX_PORT``, ``timeout`` is not above 0 and at most
            ``MAX_TIMEOUT``, or ``concurrency`` is below 1.
        IPScoutResolutionError: ``host`` does not resolve.

    """

    wanted = _wanted(ports)
    settings = _settings(timeout=timeout, concurrency=concurrency)
    target = await asyncio.to_thread(resolve_one, host)
    return await _connect_scan(target, wanted, settings)


async def _connect_scan(target: ResolvedTarget, wanted: list[int], settings: PortScanSettings) -> dict[int, PortState]:
    """Connect-scan ports already checked, de-duplicated and sorted by :func:`_wanted`.

    The two entry points that connect-scan, :func:`scan_ports` and
    :func:`ascan_ports`, parse the ports, check the settings and resolve the
    host themselves and then share this, so each is done once whichever of
    them a caller used.
    """

    async def probe(port: int) -> tuple[int, PortState]:
        try:
            connecting = asyncio.open_connection(target.address, port, family=target.family.socket_family)
            _reader, writer = await asyncio.wait_for(connecting, settings.timeout)
        except (TimeoutError, asyncio.TimeoutError):
            return port, PortState.FILTERED
        except OSError as exc:
            return port, PortState.CLOSED if is_refusal(exc) else PortState.FILTERED
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError, ConnectionError):
            await writer.wait_closed()
        return port, PortState.OPEN

    # A worker pool rather than a semaphore inside a gather over everything:
    # the semaphore would bound sockets while still creating one Task per
    # port, which is 65535 of them for a full-range scan.
    return dict(await gather_bounded(wanted, probe, settings.concurrency))
