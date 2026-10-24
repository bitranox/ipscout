"""The public callables. Everything a user of this library normally touches.

This module owns the error contract, because it is the only layer that knows
both what the caller asked for and what the machine could actually do.

The contract, in one sentence: **setup problems raise, network conditions do
not.** A host that is down, a packet that times out, a link losing everything -
all come back as a ``ResponseObject`` with ``reached=False``. Missing ICMP
permission, an unresolvable name, or a nonsensical argument raise, because no
amount of retrying fixes them and reporting them as "unreachable" sends people
hunting for network faults that do not exist.

Contents:
    ping / aping: Probe one target.
    ping_many / aping_many: Probe many, with bounded concurrency.
    is_reachable / ais_reachable: The deliberately total convenience shortcut.

Note:
    ``is_reachable`` is the one exception to the contract above, on purpose:
    it never raises and it always falls back to TCP. That is what makes it a
    shortcut. It is documented on its own docstring so nobody mistakes it for
    ``ping(...).reached``.

"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from .errors import IPScoutError
from .factory import icmp_available, make_async_transport, make_transport
from .models import AddressFamily, ProbeMethod, ResponseObject
from .packet import DEFAULT_PAYLOAD_SIZE
from .pool import gather_bounded
from .resolve import resolve_one
from .service import DEFAULT_INTERVAL, DEFAULT_TIMEOUT, DEFAULT_TIMES, PingRequest, arun_ping, run_ping
from .transport_tcp import DEFAULT_TCP_PORT

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .resolve import ResolvedTarget

__all__ = [
    "ais_reachable",
    "aping",
    "aping_many",
    "is_reachable",
    "ping",
    "ping_many",
]

#: Default concurrency for a sweep. High enough to be useful, low enough not to
#: exhaust file descriptors on a default ulimit.
DEFAULT_CONCURRENCY = 64

#: Everything ``is_reachable`` turns into False rather than raising: the setup
#: errors ``ping`` raises, plus a socket error from either probe.
_NOT_REACHED = (IPScoutError, ValueError, OSError)


def _probe_method(family: AddressFamily, *, allow_tcp_fallback: bool) -> ProbeMethod:
    """Return TCP only when the caller allowed it and ICMP cannot be used for ``family``.

    ``family`` is the RESOLVED one, never the caller's optional preference:
    ICMP availability differs per family, so asking about IPv4 before the
    target turned out to be IPv6 would answer the wrong question.
    """

    if allow_tcp_fallback and not icmp_available(family):
        return ProbeMethod.TCP
    return ProbeMethod.ICMP


def _with_method(request: PingRequest, method: ProbeMethod) -> PingRequest:
    """Return ``request`` probing by ``method`` instead.

    A copy rather than a second construction: every other field was validated
    already, and ``model_copy`` skips validation, which is sound here only
    because the one value it sets is a ``ProbeMethod`` member, the field's own type.
    """

    return request.model_copy(update={"method": method})


def _request(  # noqa: PLR0913 - mirrors the public API's knobs, every one keyword-only and independently useful
    target: str,
    resolved: ResolvedTarget,
    *,
    times: int,
    timeout: float,
    interval: float,
    payload_size: int,
    tcp_port: int,
    allow_tcp_fallback: bool,
) -> PingRequest:
    """Validate the parameters into a request for an already-resolved target.

    Validation comes first and the probe method second: choosing it can open
    an ICMP socket to see whether one is available, and a request that
    validation rejects must not touch the machine at all.
    """

    request = PingRequest(
        target=target,
        address=resolved.address,
        family=resolved.family,
        times=times,
        timeout=timeout,
        interval=interval,
        payload_size=payload_size,
        tcp_port=tcp_port,
    )
    return _with_method(request, _probe_method(request.family, allow_tcp_fallback=allow_tcp_fallback))


def _send(request: PingRequest) -> ResponseObject:
    """Run a validated request over a synchronous transport."""

    with make_transport(
        request.address,
        request.family,
        payload_size=request.payload_size,
        method=request.method,
        tcp_port=request.tcp_port,
    ) as transport:
        return run_ping(request, transport)


async def _asend(request: PingRequest) -> ResponseObject:
    """Run a validated request over an asynchronous transport."""

    transport = make_async_transport(
        request.address,
        request.family,
        payload_size=request.payload_size,
        method=request.method,
        tcp_port=request.tcp_port,
    )
    async with transport:
        return await arun_ping(request, transport)


def _suppressed(target: str, times: int, exc: Exception) -> ResponseObject:
    """Return the unreached result used when ``raise_on_error=False``."""

    return ResponseObject(target=target, number_of_pings=times, error=str(exc))


def ping(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    target: str,
    times: int = DEFAULT_TIMES,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    interval: float = DEFAULT_INTERVAL,
    family: AddressFamily | None = None,
    payload_size: int = DEFAULT_PAYLOAD_SIZE,
    allow_tcp_fallback: bool = False,
    tcp_port: int = DEFAULT_TCP_PORT,
    raise_on_error: bool = True,
) -> ResponseObject:
    """Ping a target and report what came back.

    Args:
        target: Hostname or IP address literal.
        times: How many echoes to send.
        timeout: Seconds to wait for each reply.
        interval: Seconds between the start of consecutive echoes.
        family: Force IPv4 or IPv6. ``None`` takes the resolver's preference.
        payload_size: Bytes of ICMP payload per echo.
        allow_tcp_fallback: Probe over TCP when ICMP is unavailable for the
            family the target resolved to. Off by default: a TCP result is not
            an ICMP result, and substituting one silently would misreport a
            filtered port as a dead host.
        tcp_port: Port used only when the TCP fallback is engaged.
        raise_on_error: Keep the strict contract. Set False to report every
            failure as ``reached=False`` with the reason on ``.error``
            instead.

    Returns:
        The result. Unreachable targets, timeouts and total loss are all
        reported here rather than raised.

    Raises:
        IPScoutResolutionError: The target does not resolve.
        IPScoutPermissionError: ICMP is unavailable and no fallback was allowed.
        IPScoutUnsupportedError: No ICMP backend exists for this platform.
        ValueError: ``times``, ``timeout``, ``interval`` or ``tcp_port`` is out of range.

    Examples:
        >>> result = ping("127.0.0.1", 2, interval=0)
        >>> result.reached, result.packets_received
        (True, 2)
        >>> result.ip
        '127.0.0.1'

        A name that does not resolve raises rather than reading as "down":

        >>> ping("nothing.invalid")
        Traceback (most recent call last):
        ...
        ipscout.errors.IPScoutResolutionError: cannot resolve 'nothing.invalid': ...

        Unless the caller asks for failures to be reported rather than raised:

        >>> muted = ping("nothing.invalid", raise_on_error=False)
        >>> muted.reached, muted.error is None
        (False, False)

    """

    try:
        resolved = resolve_one(target, family=family)
        request = _request(
            target,
            resolved,
            times=times,
            timeout=timeout,
            interval=interval,
            payload_size=payload_size,
            tcp_port=tcp_port,
            allow_tcp_fallback=allow_tcp_fallback,
        )
        return _send(request)
    except (IPScoutError, ValueError) as exc:
        if raise_on_error:
            raise
        return _suppressed(target, times, exc)


async def aping(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    target: str,
    times: int = DEFAULT_TIMES,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    interval: float = DEFAULT_INTERVAL,
    family: AddressFamily | None = None,
    payload_size: int = DEFAULT_PAYLOAD_SIZE,
    allow_tcp_fallback: bool = False,
    tcp_port: int = DEFAULT_TCP_PORT,
    raise_on_error: bool = True,
) -> ResponseObject:
    """Ping a target without blocking the event loop.

    Takes the same arguments as :func:`ping` and honours the same contract.

    Returns:
        The result.

    Note:
        Genuinely asynchronous on Linux and macOS, where the ICMP socket is
        registered with the event loop. On Windows the underlying
        ``IcmpSendEcho`` is a blocking C call with no asyncio integration, so
        it runs in a bounded thread pool instead. The behaviour is identical;
        the scaling characteristics are not.

    Examples:
        >>> import asyncio
        >>> result = asyncio.run(aping("127.0.0.1", 2, interval=0))
        >>> result.reached
        True

    """

    try:
        # getaddrinfo blocks for as long as the name server takes; on the loop
        # thread one slow name would stall every other probe in a sweep.
        resolved = await asyncio.to_thread(resolve_one, target, family=family)
        request = _request(
            target,
            resolved,
            times=times,
            timeout=timeout,
            interval=interval,
            payload_size=payload_size,
            tcp_port=tcp_port,
            allow_tcp_fallback=allow_tcp_fallback,
        )
        return await _asend(request)
    except (IPScoutError, ValueError) as exc:
        if raise_on_error:
            raise
        return _suppressed(target, times, exc)


async def aping_many(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    targets: Iterable[str],
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    times: int = DEFAULT_TIMES,
    timeout: float = DEFAULT_TIMEOUT,
    interval: float = DEFAULT_INTERVAL,
    family: AddressFamily | None = None,
    payload_size: int = DEFAULT_PAYLOAD_SIZE,
    allow_tcp_fallback: bool = False,
    tcp_port: int = DEFAULT_TCP_PORT,
    raise_on_error: bool = False,
) -> dict[str, ResponseObject]:
    """Ping many targets concurrently.

    Args:
        targets: The targets. Duplicates are collapsed, since the result is
            keyed by target and a repeat could only overwrite itself.
        concurrency: Maximum probes in flight at once.
        times: Echoes per target.
        timeout: Seconds to wait for each reply.
        interval: Seconds between one target's consecutive echoes.
        family: Force IPv4 or IPv6.
        payload_size: Bytes of ICMP payload per echo.
        allow_tcp_fallback: Allow the TCP probe when ICMP is unavailable.
        tcp_port: Port used only when the TCP fallback is engaged.
        raise_on_error: Defaults to **False** here, unlike :func:`ping`. In a
            sweep one bad name among two hundred should not destroy the other
            199 results; the failure is reported on that target's own
            ``.error`` instead. Set True to make any single failure raise.

    Returns:
        A mapping of target to result, in the order the targets were given.

    Examples:
        >>> import asyncio
        >>> results = asyncio.run(aping_many(["127.0.0.1", "::1"], times=1))
        >>> sorted(results)
        ['127.0.0.1', '::1']
        >>> all(r.reached for r in results.values())
        True

    """

    unique = list(dict.fromkeys(targets))

    async def one(target: str) -> tuple[str, ResponseObject]:
        # Returns the target with its result: the pool completes out of order,
        # so pairing by position afterwards would attribute results to the
        # wrong hosts.
        result = await aping(
            target,
            times,
            timeout=timeout,
            interval=interval,
            family=family,
            payload_size=payload_size,
            allow_tcp_fallback=allow_tcp_fallback,
            tcp_port=tcp_port,
            raise_on_error=raise_on_error,
        )
        return target, result

    # A worker pool rather than a semaphore inside a gather over everything:
    # the semaphore bounds probes in flight while still creating one Task per
    # target up front, so a sweep of a large subnet holds them all at once.
    completed = dict(await gather_bounded(unique, one, concurrency))
    if len(completed) != len(unique):  # pragma: no cover - a lost result is a bug, not a condition
        msg = f"sweep returned {len(completed)} results for {len(unique)} targets"
        raise RuntimeError(msg)
    # Rebuilt from the input list: the pool's own order is completion order.
    return {target: completed[target] for target in unique}


def ping_many(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    targets: Iterable[str],
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    times: int = DEFAULT_TIMES,
    timeout: float = DEFAULT_TIMEOUT,
    interval: float = DEFAULT_INTERVAL,
    family: AddressFamily | None = None,
    payload_size: int = DEFAULT_PAYLOAD_SIZE,
    allow_tcp_fallback: bool = False,
    tcp_port: int = DEFAULT_TCP_PORT,
    raise_on_error: bool = False,
) -> dict[str, ResponseObject]:
    """Ping many targets concurrently from synchronous code.

    Takes the same arguments as :func:`aping_many`.

    Returns:
        A mapping of target to result, in the order the targets were given.

    Raises:
        RuntimeError: Called from inside a running event loop, where it would
            deadlock. Await :func:`aping_many` there instead. Failing loudly
            beats hanging.

    Examples:
        >>> results = ping_many(["127.0.0.1", "::1"], times=1)
        >>> sorted(results)
        ['127.0.0.1', '::1']

    """

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        msg = "ping_many() cannot run inside an event loop; await aping_many() instead"
        raise RuntimeError(msg)

    return asyncio.run(
        aping_many(
            targets,
            concurrency=concurrency,
            times=times,
            timeout=timeout,
            interval=interval,
            family=family,
            payload_size=payload_size,
            allow_tcp_fallback=allow_tcp_fallback,
            tcp_port=tcp_port,
            raise_on_error=raise_on_error,
        )
    )


def is_reachable(
    target: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    tcp_port: int = DEFAULT_TCP_PORT,
    family: AddressFamily | None = None,
) -> bool:
    """Return whether a target answers, by any means available.

    The deliberate exception to this module's error contract. It **never
    raises** and it **always** tries TCP when ICMP does not answer or is
    unavailable. That is the entire point of the shortcut. The target is
    resolved once, and both attempts probe that one address.

    Args:
        target: Hostname or IP address literal.
        timeout: Seconds to allow for each attempt.
        tcp_port: Port for the TCP attempt. Outside 1-65535 the check answers False.
        family: Force IPv4 or IPv6.

    Returns:
        True if anything answered.

    Note:
        This is not ``ping(target).reached``. That reports whether *ICMP*
        succeeded and raises on a bad name; this reports whether the host is
        alive by any route and answers False for a bad name. Use ``ping`` when
        the distinction matters, and this when it does not.

    Examples:
        >>> is_reachable("127.0.0.1")
        True
        >>> is_reachable("nothing.invalid")
        False

    """

    # One lookup for both tries: a second could answer a different address
    # (round-robin DNS, a v4/v6 preference), and the two tries would then probe
    # two different hosts for what is reported as one answer.
    try:
        resolved = resolve_one(target, family=family)
        icmp = _reachability_request(target, resolved, timeout)
    except _NOT_REACHED:
        return False
    if _answers(icmp):
        return True
    tcp = _tcp_leg(target, resolved, timeout, tcp_port)
    return tcp is not None and _answers(tcp)


def _reachability_request(
    target: str,
    resolved: ResolvedTarget,
    timeout: float,
    tcp_port: int = DEFAULT_TCP_PORT,
) -> PingRequest:
    """Validate the single echo a reachability check sends on one leg.

    Both legs probe the one resolved address. The ICMP leg leaves ``tcp_port``
    at its default because the port is the TCP leg's alone: a caller's bad port
    must not make a host that answers ICMP read as unreachable.
    """

    return PingRequest(
        target=target,
        address=resolved.address,
        family=resolved.family,
        times=1,
        timeout=timeout,
        interval=0,
        tcp_port=tcp_port,
    )


def _tcp_leg(target: str, resolved: ResolvedTarget, timeout: float, tcp_port: int) -> PingRequest | None:
    """Return the validated TCP leg, or None when ``tcp_port`` is refused.

    Tried unconditionally after ICMP, which ``ping(allow_tcp_fallback=True)``
    would not do: that only substitutes TCP when ICMP is *unavailable*, and the
    common case here is ICMP being available but the target not answering it.
    """

    try:
        return _with_method(_reachability_request(target, resolved, timeout, tcp_port), ProbeMethod.TCP)
    except _NOT_REACHED:
        return None


def _answers(request: PingRequest) -> bool:
    """Return whether ``request`` reached its target; any failure is False."""

    try:
        return _send(request).reached
    except _NOT_REACHED:
        return False


async def ais_reachable(
    target: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    tcp_port: int = DEFAULT_TCP_PORT,
    family: AddressFamily | None = None,
) -> bool:
    """Return whether a target answers, without blocking the event loop.

    Same total, never-raising contract as :func:`is_reachable`.

    Returns:
        True if anything answered.

    Examples:
        >>> import asyncio
        >>> asyncio.run(ais_reachable("127.0.0.1"))
        True

    """

    # One lookup for both tries, as in is_reachable, and off the loop thread,
    # as in aping.
    try:
        resolved = await asyncio.to_thread(resolve_one, target, family=family)
        icmp = _reachability_request(target, resolved, timeout)
    except _NOT_REACHED:
        return False
    if await _aanswers(icmp):
        return True
    tcp = _tcp_leg(target, resolved, timeout, tcp_port)
    return tcp is not None and await _aanswers(tcp)


async def _aanswers(request: PingRequest) -> bool:
    """Return whether ``request`` reached its target; any failure is False."""

    try:
        return (await _asend(request)).reached
    except _NOT_REACHED:
        return False
