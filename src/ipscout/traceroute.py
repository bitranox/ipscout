"""Path discovery by walking the hop limit upward.

Sends echoes with a deliberately small hop limit and collects the Time Exceeded
messages routers return, one hop at a time, until the target itself answers.

Contents:
    trace_path: Drive a transport through the hop sweep.
    traceroute / atraceroute: The public entry points.

Whether an unprivileged process can observe Time Exceeded at all is a
per-platform fact, and it was settled by measurement rather than assumption:

    **Linux** - yes. ``IP_RECVERR`` plus ``recvmsg(..., MSG_ERRQUEUE)`` deliver
    the router's address in ``SO_EE_OFFENDER``.

    **Windows** - yes. ``IcmpSendEcho`` reports ``IP_TTL_EXPIRED_TRANSIT`` with
    the router in the reply's address field.

    **macOS - no.** Measured on a macOS runner: ``MSG_ERRQUEUE`` is not defined
    there, and a plain receive on the ICMP socket returns nothing at all. So
    traceroute raises :class:`~ipscout.errors.IPScoutUnsupportedError` on macOS
    rather than returning a column of silent hops that would look like a broken
    network instead of a missing capability.

Note:
    The decision is taken from the transport's own ``supports_ttl_discovery``
    rather than from ``sys.platform``, so a transport that cannot observe
    expiry - the TCP probe, for instance - is refused for the same reason and
    through the same code path.

"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from .errors import IPScoutUnsupportedError
from .factory import make_async_transport, make_transport
from .models import TraceHop
from .resolve import resolve_one, reverse_dns
from .service import DEFAULT_TIMEOUT

if TYPE_CHECKING:
    from .models import AddressFamily
    from .ports import AsyncEchoTransport, EchoResult, EchoTransport

__all__ = ["atrace_path", "atraceroute", "trace_path", "traceroute"]

#: Hop limit beyond which a path is treated as not terminating. Matches the
#: conventional traceroute default.
DEFAULT_MAX_HOPS = 30

_UNSUPPORTED = (
    "traceroute needs to observe ICMP Time Exceeded, which this platform does not expose to an "
    "unprivileged process. Measured on macOS: neither MSG_ERRQUEUE nor a plain receive surfaces it. "
    "Linux and Windows are supported."
)


def _require_walkable(max_hops: int, *, supports_ttl_discovery: bool) -> None:
    """Refuse a walk that could never report a hop, before any probe is sent.

    One check for both walks, so the sync and async entry points cannot drift
    apart on what they refuse or how they word it.

    Raises:
        ValueError: ``max_hops`` is below 1.
        IPScoutUnsupportedError: Expired hops cannot be observed on this
            transport.
    """

    if max_hops < 1:
        msg = f"max_hops must be at least 1, got {max_hops}"
        raise ValueError(msg)
    if not supports_ttl_discovery:
        raise IPScoutUnsupportedError(_UNSUPPORTED)


def _name_to_look_up(result: EchoResult, *, resolve_names: bool) -> str | None:
    """Return the hop address whose reverse-DNS name is wanted, or None."""

    if resolve_names and result.answered and result.source:
        return result.source
    return None


def _to_hop(ttl: int, result: EchoResult, *, hostname: str | None) -> TraceHop:
    """Turn one probe outcome into the hop it represents.

    A router reporting Time Exceeded is an intermediate hop; anything else that
    answered is the target itself and ends the walk. Silence is recorded as a
    hop with no address rather than dropped, because a firewall that ignores
    one hop in the middle of an otherwise complete path is information.
    """

    if not result.answered:
        return TraceHop(ttl=ttl)
    return TraceHop(
        ttl=ttl,
        address=result.source,
        rtt_ms=result.rtt_ms,
        reached=not result.ttl_expired,
        hostname=hostname,
    )


def trace_path(
    transport: EchoTransport,
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
    timeout: float = DEFAULT_TIMEOUT,
    resolve_names: bool = False,
) -> list[TraceHop]:
    """Walk the hop limit upward over ``transport`` until the target answers.

    Args:
        transport: The transport to probe with. Ownership stays with the caller.
        max_hops: Highest hop limit to try before giving up.
        timeout: Seconds to wait at each hop.
        resolve_names: Look up a reverse-DNS name per responding hop. Off by
            default because it can add a DNS round trip per hop.

    Returns:
        One :class:`~ipscout.models.TraceHop` per hop attempted, in order. The
        walk stops at the first hop that is the target itself.

    Raises:
        IPScoutUnsupportedError: This transport cannot observe expired hops.
        ValueError: ``max_hops`` is below 1.

    Examples:
        >>> from ipscout.ports import EchoResult
        >>> class TwoHops:
        ...     supports_ttl = True
        ...     supports_ttl_discovery = True
        ...     def probe(self, *, sequence, timeout, ttl=None):
        ...         if ttl == 1:
        ...             return EchoResult(rtt_ms=1.0, source="10.0.0.1", ttl_expired=True)
        ...         return EchoResult(rtt_ms=2.0, source="10.0.0.9")
        ...     def close(self): pass
        >>> hops = trace_path(TwoHops())
        >>> [(h.ttl, h.address, h.reached) for h in hops]
        [(1, '10.0.0.1', False), (2, '10.0.0.9', True)]

    """

    _require_walkable(max_hops, supports_ttl_discovery=transport.supports_ttl_discovery)

    hops: list[TraceHop] = []
    for ttl in range(1, max_hops + 1):
        result = transport.probe(sequence=ttl, timeout=timeout, ttl=ttl)
        source = _name_to_look_up(result, resolve_names=resolve_names)
        hop = _to_hop(ttl, result, hostname=reverse_dns(source) if source else None)
        hops.append(hop)
        if hop.reached:
            break
    return hops


async def atrace_path(
    transport: AsyncEchoTransport,
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
    timeout: float = DEFAULT_TIMEOUT,
    resolve_names: bool = False,
) -> list[TraceHop]:
    """Walk the hop limit upward over an async transport.

    Hops stay sequential rather than concurrent: the walk has to stop at the
    hop that answers, and firing all thirty at once would probe far past the
    target on every short path.

    Args:
        transport: The transport to probe with.
        max_hops: Highest hop limit to try.
        timeout: Seconds to wait at each hop.
        resolve_names: Look up a reverse-DNS name per responding hop.

    Returns:
        One hop record per hop attempted, in order.

    Raises:
        IPScoutUnsupportedError: This transport cannot observe expired hops.
        ValueError: ``max_hops`` is below 1.

    """

    _require_walkable(max_hops, supports_ttl_discovery=transport.supports_ttl_discovery)

    hops: list[TraceHop] = []
    for ttl in range(1, max_hops + 1):
        result = await transport.probe(sequence=ttl, timeout=timeout, ttl=ttl)
        source = _name_to_look_up(result, resolve_names=resolve_names)
        # gethostbyaddr blocks for as long as the name server takes, once per
        # hop; on the loop thread that stalls every other task for the walk.
        hostname = await asyncio.to_thread(reverse_dns, source) if source else None
        hop = _to_hop(ttl, result, hostname=hostname)
        hops.append(hop)
        if hop.reached:
            break
    return hops


def traceroute(
    target: str,
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
    timeout: float = DEFAULT_TIMEOUT,
    family: AddressFamily | None = None,
    resolve_names: bool = False,
) -> list[TraceHop]:
    """Report the path packets take to a target.

    Args:
        target: Hostname or IP address literal.
        max_hops: Highest hop limit to try before giving up.
        timeout: Seconds to wait at each hop.
        family: Force IPv4 or IPv6.
        resolve_names: Look up a reverse-DNS name per responding hop.

    Returns:
        One hop record per hop, in order, ending at the target when it answers.

    Raises:
        IPScoutResolutionError: The target does not resolve.
        IPScoutPermissionError: ICMP is unavailable to this process.
        IPScoutUnsupportedError: This platform cannot observe expired hops.
        ValueError: ``max_hops`` is below 1.

    """

    resolved = resolve_one(target, family=family)
    with make_transport(resolved.address, resolved.family) as transport:
        return trace_path(transport, max_hops=max_hops, timeout=timeout, resolve_names=resolve_names)


async def atraceroute(
    target: str,
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
    timeout: float = DEFAULT_TIMEOUT,
    family: AddressFamily | None = None,
    resolve_names: bool = False,
) -> list[TraceHop]:
    """Report the path to a target without blocking the event loop.

    Takes the same arguments as :func:`traceroute`.

    Returns:
        One hop record per hop, in order.

    """

    resolved = await asyncio.to_thread(resolve_one, target, family=family)
    transport = make_async_transport(resolved.address, resolved.family)
    async with transport:
        return await atrace_path(transport, max_hops=max_hops, timeout=timeout, resolve_names=resolve_names)
