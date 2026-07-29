"""The public callables. Everything a user of this library normally touches.

This module owns the error contract, because it is the only layer that knows
both what the caller asked for and what the machine could actually do.

The contract, in one sentence: **setup problems raise, network conditions do
not.** A host that is down, a packet that times out, a link losing everything -
all come back as a ``ResponseObject`` with ``reached=False``. Missing ICMP
permission, an unresolvable name, or a nonsensical argument raise, because no
amount of retrying fixes them and reporting them as "unreachable" is how the
pre-1.0 library sent people hunting for network faults that did not exist.

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
from .resolve import resolve_one
from .service import PingRequest, arun_ping, run_ping

if TYPE_CHECKING:
    from collections.abc import Iterable

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


def _prepare(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    target: str,
    times: int,
    timeout: float,
    interval: float,
    family: AddressFamily | None,
    *,
    use_tcp: bool,
) -> PingRequest:
    """Resolve the target and validate the parameters into a request."""

    address, resolved_family = resolve_one(target, family=family)
    return PingRequest(
        target=target,
        address=address,
        family=resolved_family,
        times=times,
        timeout=timeout,
        interval=interval,
        method=ProbeMethod.TCP if use_tcp else ProbeMethod.ICMP,
    )


def _suppressed(target: str, times: int, exc: Exception) -> ResponseObject:
    """Return the unreached result used when ``raise_on_error=False``."""

    return ResponseObject(target=target, number_of_pings=times, error=str(exc))


def ping(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    target: str,
    times: int = 4,
    *,
    timeout: float = 2.0,
    interval: float = 0.2,
    family: AddressFamily | None = None,
    payload_size: int = 56,
    allow_tcp_fallback: bool = False,
    tcp_port: int = 443,
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
        allow_tcp_fallback: Probe over TCP when ICMP is unavailable. Off by
            default: a TCP result is not an ICMP result, and substituting one
            silently would misreport a filtered port as a dead host.
        tcp_port: Port used only when the TCP fallback is engaged.
        raise_on_error: Keep the strict contract. Set False to restore the
            pre-1.0 behaviour where every failure became ``reached=False``
            with the reason on ``.error``.

    Returns:
        The result. Unreachable targets, timeouts and total loss are all
        reported here rather than raised.

    Raises:
        IPScoutResolutionError: The target does not resolve.
        IPScoutPermissionError: ICMP is unavailable and no fallback was allowed.
        IPScoutUnsupportedError: No ICMP backend exists for this platform.
        ValueError: ``times``, ``timeout`` or ``interval`` is out of range.

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

        Unless the caller opts back into the old swallow-everything behaviour:

        >>> muted = ping("nothing.invalid", raise_on_error=False)
        >>> muted.reached, muted.error is None
        (False, False)

    """

    try:
        use_tcp = allow_tcp_fallback and not icmp_available(family or AddressFamily.IPV4)
        request = _prepare(target, times, timeout, interval, family, use_tcp=use_tcp)
        with make_transport(
            request.address,
            request.family,
            payload_size=payload_size,
            use_tcp=use_tcp,
            tcp_port=tcp_port,
        ) as transport:
            return run_ping(request, transport)
    except (IPScoutError, ValueError) as exc:
        if raise_on_error:
            raise
        return _suppressed(target, times, exc)


async def aping(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    target: str,
    times: int = 4,
    *,
    timeout: float = 2.0,
    interval: float = 0.2,
    family: AddressFamily | None = None,
    payload_size: int = 56,
    allow_tcp_fallback: bool = False,
    tcp_port: int = 443,
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
        use_tcp = allow_tcp_fallback and not icmp_available(family or AddressFamily.IPV4)
        request = _prepare(target, times, timeout, interval, family, use_tcp=use_tcp)
        transport = make_async_transport(
            request.address,
            request.family,
            payload_size=payload_size,
            use_tcp=use_tcp,
            tcp_port=tcp_port,
        )
        async with transport:
            return await arun_ping(request, transport)
    except (IPScoutError, ValueError) as exc:
        if raise_on_error:
            raise
        return _suppressed(target, times, exc)


async def aping_many(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    targets: Iterable[str],
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    times: int = 4,
    timeout: float = 2.0,
    interval: float = 0.2,
    family: AddressFamily | None = None,
    payload_size: int = 56,
    allow_tcp_fallback: bool = False,
    tcp_port: int = 443,
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
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def one(target: str) -> ResponseObject:
        async with semaphore:
            return await aping(
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

    completed = await asyncio.gather(*(one(target) for target in unique))
    # strict=True because a length mismatch here would mean results were
    # silently dropped from a sweep rather than a visible failure.
    return dict(zip(unique, completed, strict=True))


def ping_many(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    targets: Iterable[str],
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    times: int = 4,
    timeout: float = 2.0,
    interval: float = 0.2,
    family: AddressFamily | None = None,
    payload_size: int = 56,
    allow_tcp_fallback: bool = False,
    tcp_port: int = 443,
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
    timeout: float = 2.0,
    tcp_port: int = 443,
    family: AddressFamily | None = None,
) -> bool:
    """Return whether a target answers, by any means available.

    The deliberate exception to this module's error contract. It **never
    raises** and it **always** tries TCP when ICMP does not answer or is
    unavailable. That is the entire point of the shortcut.

    Args:
        target: Hostname or IP address literal.
        timeout: Seconds to allow for each attempt.
        tcp_port: Port for the TCP attempt.
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

    if ping(target, 1, timeout=timeout, interval=0, family=family, raise_on_error=False).reached:
        return True

    # Fall through to TCP unconditionally. Going via ping(allow_tcp_fallback=True)
    # would not do it: that only substitutes TCP when ICMP is *unavailable*, and
    # the common case here is ICMP being available but the target not answering it.
    try:
        address, resolved = resolve_one(target, family=family)
        with make_transport(address, resolved, use_tcp=True, tcp_port=tcp_port) as transport:
            return transport.probe(sequence=1, timeout=timeout).answered
    except (IPScoutError, ValueError, OSError):
        return False


async def ais_reachable(
    target: str,
    *,
    timeout: float = 2.0,
    tcp_port: int = 443,
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

    icmp = await aping(target, 1, timeout=timeout, interval=0, family=family, raise_on_error=False)
    if icmp.reached:
        return True

    try:
        address, resolved = resolve_one(target, family=family)
        transport = make_async_transport(address, resolved, use_tcp=True, tcp_port=tcp_port)
        async with transport:
            return (await transport.probe(sequence=1, timeout=timeout)).answered
    except (IPScoutError, ValueError, OSError):
        return False
