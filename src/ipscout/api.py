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
from typing import TYPE_CHECKING, Annotated, NamedTuple

from pydantic import BaseModel, BeforeValidator, ConfigDict, StrictStr, TypeAdapter, ValidationError

from .errors import IPScoutError, refused_arguments
from .factory import icmp_available, make_async_transport, make_transport
from .models import AddressFamily, ProbeMethod, ResponseObject
from .packet import DEFAULT_PAYLOAD_SIZE
from .pool import Concurrency, gather_bounded
from .resolve import resolve_one
from .service import DEFAULT_INTERVAL, DEFAULT_TIMEOUT, DEFAULT_TIMES, PingRequest, arun_ping, run_ping
from .transport_tcp import DEFAULT_TCP_PORT

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .resolve import ResolvedTarget

__all__ = [
    "DEFAULT_CONCURRENCY",
    "HostNames",
    "SweepSettings",
    "ais_reachable",
    "aping",
    "aping_many",
    "is_reachable",
    "ping",
    "ping_many",
    "require_host_names",
]

#: Default concurrency for a sweep. High enough to be useful, low enough not to
#: exhaust file descriptors on a default ulimit.
DEFAULT_CONCURRENCY = 64

#: Everything ``is_reachable`` turns into False rather than raising: the setup
#: errors ``ping`` raises, plus a socket error from either probe.
_NOT_REACHED = (IPScoutError, ValueError, OSError)


def _refuse_bare_text(value: object) -> object:
    """Refuse one ``str`` or ``bytes`` where a collection of host names belongs.

    A string is itself an iterable of strings, so ``"printer.lan"`` would
    otherwise be read as the hosts ``"p"``, ``"r"``, ``"i"``... and every
    one of them probed. No caller means that, so it is refused rather than
    wrapped: wrapping would guess, and the guess hides the mistake.
    """

    if isinstance(value, (str, bytes, bytearray)):
        msg = "one string is a single host, not a collection of hosts; pass a list such as ['printer.lan']"
        # A ValueError, not a TypeError: pydantic turns only a ValueError into a field refusal.
        raise ValueError(msg)
    return value


#: Many host names or address literals, as every many-host entry point takes
#: them: any collection or iterator of ``str`` (consumed once), never one bare
#: string, and never a non-string entry.
HostNames = Annotated[list[StrictStr], BeforeValidator(_refuse_bare_text)]

_HOST_NAMES: TypeAdapter[list[str]] = TypeAdapter(HostNames)


def require_host_names(values: Iterable[str], *, operation: str, argument: str) -> list[str]:
    """Return ``values`` as a list of distinct host names, in the order given, or refuse them.

    The one check every many-host entry point applies to its hosts, so a
    ping sweep and a banner grab refuse the same mistake in the same words.
    Duplicates are collapsed because every caller keys its result by host,
    where a repeat could only overwrite itself.

    Args:
        values: The hosts, as the caller passed them. Consumed once.
        operation: What refused, as the caller knows it (``"ping sweep"``).
        argument: The parameter's name, so the refusal names it.

    Returns:
        The distinct names, in first-seen order.

    Raises:
        ValueError: ``values`` is one bare string, is not a collection at all,
            or holds an entry that is not a ``str``; in the
            ``<operation> refused its arguments: <argument>: <reason>`` shape.

    Examples:
        >>> require_host_names(["b", "a", "b"], operation="ping sweep", argument="targets")
        ['b', 'a']
        >>> require_host_names("ab", operation="ping sweep", argument="targets")
        Traceback (most recent call last):
        ...
        ValueError: ping sweep refused its arguments: targets: one string is a single host, ...

    """

    try:
        names = _HOST_NAMES.validate_python(values)
    except ValidationError as refused:
        raise refused_arguments(operation, refused, field=argument) from refused
    return list(dict.fromkeys(names))


class SweepSettings(BaseModel):
    """The sweep-wide arguments of a ping sweep, checked before any target is taken.

    Only what belongs to the sweep as a whole lives here; every per-probe
    argument is checked by the request each target builds, under
    ``raise_on_error``. Strict: ``True`` is not a concurrency.

    Examples:
        >>> SweepSettings().concurrency == DEFAULT_CONCURRENCY
        True
        >>> SweepSettings(concurrency=0)
        Traceback (most recent call last):
        ...
        pydantic_core._pydantic_core.ValidationError: ...

    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    #: Probes in flight at once, under the pool's one concurrency rule.
    concurrency: Concurrency = DEFAULT_CONCURRENCY
    #: Whether one target's failure raises for the whole sweep.
    raise_on_error: bool = False


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

    Raises:
        ValueError: A parameter is refused. Raised as a plain ``ValueError``
            naming each refused field, with pydantic's own error as its cause:
            ``str()`` of that error is written for the model's author and
            carries a docs URL and the input echoed back, none of which helps
            the caller who passed the value.
    """

    try:
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
    except ValidationError as refused:
        raise refused_arguments("ping", refused) from refused
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


def _suppressed(target: str, exc: Exception, *, resolved: ResolvedTarget | None, family: AddressFamily | None) -> ResponseObject:
    """Return the unreached result used when ``raise_on_error=False``.

    Reports what was learned before the failure and nothing more: the
    resolved address and its family when resolution got that far, otherwise
    the family the caller asked for (IPv4 when they named none) with that
    family's unspecified address. Nothing was sent, so every count is zero
    whatever ``times`` was - a refused ``times`` is not a count to repeat.
    """

    # An exception with no message still has a class name, and the record
    # refuses an empty reason because it would say nothing.
    reason = str(exc) or type(exc).__name__
    if resolved is not None:
        return ResponseObject(target=target, ip=resolved.address, family=resolved.family, error=reason)
    known = family or AddressFamily.IPV4
    return ResponseObject(target=target, ip=known.unspecified_address, family=known, error=reason)


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
        payload_size: Bytes of ICMP payload per echo. At most
            ``ipscout.packet.MAX_PAYLOAD_SIZE_IPV4`` for IPv4 and
            ``MAX_PAYLOAD_SIZE_IPV6`` for IPv6, the most an IP packet can
            carry; one below the probe's minimum is raised to it.
        allow_tcp_fallback: Probe over TCP when ICMP is unavailable for the
            family the target resolved to. Off by default: a TCP result is not
            an ICMP result, and substituting one silently would misreport a
            filtered port as a dead host.
        tcp_port: Port the TCP fallback connects to. Only the fallback uses
            it, but it is validated on every call, so a bad port is reported
            even when ICMP answers.
        raise_on_error: Keep the strict contract. Set False to report every
            failure as ``reached=False`` with the reason on ``.error``
            instead, argument mistakes included. Such a result sent nothing,
            so its counts are zero; its ``ip`` and ``family`` are the resolved
            ones when the target resolved before the failure, otherwise the
            requested family (IPv4 when none was) and its unspecified address.

    Returns:
        The result. Unreachable targets, timeouts and total loss are all
        reported here rather than raised.

    Raises:
        IPScoutResolutionError: The target does not resolve.
        IPScoutPermissionError: ICMP is unavailable and no fallback was allowed.
        IPScoutUnsupportedError: No ICMP backend exists for this platform.
        ValueError: ``times`` (1-``MAX_TIMES``), ``timeout`` (above 0, at
            most ``MAX_TIMEOUT``), ``interval`` (0 to ``MAX_TIMEOUT``),
            ``payload_size`` or ``tcp_port`` is out of range, whichever probe
            method runs. The message names each refused argument.

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

        An argument mistake is reported in the caller's terms, and the
        address it resolved to is kept:

        >>> refused = ping("::1", 0, raise_on_error=False)
        >>> refused.error
        'ping refused its arguments: times: Input should be greater than or equal to 1'
        >>> refused.ip, refused.family.value
        ('::1', 'ipv6')

    """

    resolved: ResolvedTarget | None = None
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
        return _suppressed(target, exc, resolved=resolved, family=family)


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

    resolved: ResolvedTarget | None = None
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
        return _suppressed(target, exc, resolved=resolved, family=family)


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
        concurrency: Maximum probes in flight at once; at least 1.
        times: Echoes per target.
        timeout: Seconds to wait for each reply.
        interval: Seconds between one target's consecutive echoes.
        family: Force IPv4 or IPv6.
        payload_size: Bytes of ICMP payload per echo, bounded as in :func:`ping`.
        allow_tcp_fallback: Allow the TCP probe when ICMP is unavailable.
        tcp_port: Port the TCP fallback connects to; validated on every
            call, as in :func:`ping`.
        raise_on_error: Defaults to **False** here, unlike :func:`ping`. In a
            sweep one bad name among two hundred should not destroy the other
            199 results; the failure is reported on that target's own
            ``.error`` instead. Set True to make any single failure raise.

    Returns:
        A mapping of target to result, in the order the targets were given.

    Raises:
        ValueError: ``targets`` is one bare string (a string is an iterable
            of one-letter names, which no caller means) or holds a non-``str``
            entry, ``concurrency`` is below 1 or not an ``int``, or
            ``raise_on_error`` is not a ``bool``. Refused for the whole sweep
            whatever ``raise_on_error`` says, before any target is taken from
            ``targets`` and before any probe: these are mistakes about the
            sweep, not about one target. The message reads
            ``ping sweep refused its arguments: <argument>: <reason>``.

    Examples:
        >>> import asyncio
        >>> results = asyncio.run(aping_many(["127.0.0.1", "::1"], times=1))
        >>> sorted(results)
        ['127.0.0.1', '::1']
        >>> all(r.reached for r in results.values())
        True

    """

    try:
        sweep = SweepSettings(concurrency=concurrency, raise_on_error=raise_on_error)
    except ValidationError as refused:
        raise refused_arguments("ping sweep", refused) from refused
    unique = require_host_names(targets, operation="ping sweep", argument="targets")

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
            raise_on_error=sweep.raise_on_error,
        )
        return target, result

    # A worker pool rather than a semaphore inside a gather over everything:
    # the semaphore bounds probes in flight while still creating one Task per
    # target up front, so a sweep of a large subnet holds them all at once.
    completed = dict(await gather_bounded(unique, one, sweep.concurrency))
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
        ValueError: A sweep-wide argument is refused, as in :func:`aping_many`.

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
        tcp_port: Port for the TCP attempt. Outside 1-65535 that attempt
            answers False; a host that answers ICMP still reads as reachable.
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
        legs = _reachability_legs(target, resolved, timeout=timeout, tcp_port=tcp_port)
    except _NOT_REACHED:
        return False
    if _answers(legs.icmp):
        return True
    return legs.tcp is not None and _answers(legs.tcp)


class _ReachabilityLegs(NamedTuple):
    """Both validated legs of one reachability check.

    ``tcp`` is None when the caller's ``tcp_port`` was refused: the port is the
    TCP leg's alone, so a bad one silences that leg and must not make a host
    that answers ICMP read as unreachable.
    """

    icmp: PingRequest
    tcp: PingRequest | None


def _reachability_request(target: str, resolved: ResolvedTarget, *, timeout: float, method: ProbeMethod, tcp_port: int) -> PingRequest:
    """Validate the single echo a reachability check sends on one leg, at the one resolved address."""

    return PingRequest(
        target=target,
        address=resolved.address,
        family=resolved.family,
        times=1,
        timeout=timeout,
        interval=0,
        tcp_port=tcp_port,
        method=method,
    )


def _reachability_legs(target: str, resolved: ResolvedTarget, *, timeout: float, tcp_port: int) -> _ReachabilityLegs:
    """Validate both legs before either one probes.

    The TCP leg is tried unconditionally after ICMP, which
    ``ping(allow_tcp_fallback=True)`` would not do: that only substitutes TCP
    when ICMP is *unavailable*, and the common case here is ICMP being
    available but the target not answering it.

    Raises:
        ValueError: The ICMP leg is refused (a bad ``timeout``), which the
            caller turns into False before anything is sent.
    """

    # The ICMP leg carries the default port: the caller's port belongs to the
    # TCP leg, and validating it on the ICMP leg would refuse both legs at once.
    icmp = _reachability_request(target, resolved, timeout=timeout, method=ProbeMethod.ICMP, tcp_port=DEFAULT_TCP_PORT)
    try:
        tcp = _reachability_request(target, resolved, timeout=timeout, method=ProbeMethod.TCP, tcp_port=tcp_port)
    except ValueError:
        return _ReachabilityLegs(icmp=icmp, tcp=None)
    return _ReachabilityLegs(icmp=icmp, tcp=tcp)


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
        legs = _reachability_legs(target, resolved, timeout=timeout, tcp_port=tcp_port)
    except _NOT_REACHED:
        return False
    if await _aanswers(legs.icmp):
        return True
    return legs.tcp is not None and await _aanswers(legs.tcp)


async def _aanswers(request: PingRequest) -> bool:
    """Return whether ``request`` reached its target; any failure is False."""

    try:
        return (await _asend(request)).reached
    except _NOT_REACHED:
        return False
