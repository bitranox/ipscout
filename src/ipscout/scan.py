"""Sweeping a subnet to learn hardware addresses, and searching by one.

Contents:
    arp_scan: Sweep a network, then read what the kernel learned.
    find_ip_by_mac: Which address currently holds a hardware address.
    local_networks: The subnets a default sweep covers.
    sweep_scope: Which of them a sweep would reach, and which it would not.

Note:
    **There is no protocol that asks "who has this MAC".** RARP is long dead
    and modern hosts do not answer it. The only way to answer the reverse
    question is to populate the neighbour cache and search it, which is
    exactly what these two do: an ordinary unprivileged ping sweep, then a
    passive cache read. Nothing here needs elevation.

    A hardware address can legitimately be held by several addresses - dual
    stack, or several addresses on one interface - so the search returns every
    match rather than the first.

    **Coverage is reported, never assumed.** The default set comes from this
    host's own interfaces, and one of those is routinely a container bridge on
    a /16 - far more addresses than a sweep can reasonably probe. Such a
    network is left out and named in a :class:`~ipscout.models.SweepScope`
    rather than failing the whole call, because a sweep of the /24 the caller
    actually cares about is the useful thing to do. The bound is on the sweep
    as a whole, so a host attached to many subnets cannot quietly probe their
    sum either. What that costs is stated instead of hidden: a search that
    matched nothing over partial ground raises rather than answering "not
    found", which would be the stronger claim the sweep did not earn.

"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Annotated

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from .api import ping_many
from .arp import require_mac
from .errors import IPScoutSweepIncompleteError, IPScoutSweepTooWideError, refused_arguments
from .interfaces import local_interfaces
from .models import AddressFamily, SweepScope, Timeout
from .neighbours import neighbours, normalise_mac, of_family
from .pool import Concurrency

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .models import Interface, IPNetwork, Neighbour

__all__ = [
    "DEFAULT_CONCURRENCY",
    "MAX_SWEEP_HOSTS",
    "SweepSettings",
    "arp_scan",
    "find_ip_by_mac",
    "local_networks",
    "refuse_a_partial_scope",
    "sweep_argument_refusal",
    "sweep_scope",
]

#: The most addresses one sweep covers, counted across every network in it.
#: A sweep wider than this is a scan of somebody else's network, not of a
#: local subnet, and would take long enough that the cache entries from the
#: start of it are stale before the end. Bounding each network separately
#: would miss exactly that: a host attached to several subnets would probe
#: their sum, which is the number that decides both.
MAX_SWEEP_HOSTS = 4096

#: Enough for a /22 sweep to finish quickly without exhausting file handles.
DEFAULT_CONCURRENCY = 64

#: Seconds to wait for each probe in a sweep. Most addresses in a subnet are
#: unused, so this is mostly spent waiting for silence.
DEFAULT_SWEEP_TIMEOUT = 1.0

#: Prefix length at which a network stops holding anybody but this host and,
#: on a /31, its single point-to-point peer.
POINT_TO_POINT_PREFIX = 31

#: A sweep's address budget: below one it could cover nothing, and every
#: network would be reported as skipped for being too wide.
_LIMIT: TypeAdapter[int] = TypeAdapter(Annotated[int, Field(ge=1, strict=True)])


class SweepSettings(BaseModel):
    """How long a sweep waits per probe and how many it keeps in flight, checked once.

    The bounds are declared on the fields, so the check and its documentation
    cannot drift apart, and the command line reads these same declarations for
    its options. Strict: ``"1"`` is not a timeout.

    Examples:
        >>> SweepSettings().concurrency == DEFAULT_CONCURRENCY
        True
        >>> SweepSettings(timeout=0)
        Traceback (most recent call last):
        ...
        pydantic_core._pydantic_core.ValidationError: ...

    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    #: Seconds to wait for each probe, under the library's one timeout rule.
    #: Zero would refuse every probe, and the cache as it already stood would
    #: come back as though it were the sweep's.
    timeout: Timeout = DEFAULT_SWEEP_TIMEOUT
    #: Probes in flight at once, under the pool's one concurrency rule.
    concurrency: Concurrency = DEFAULT_CONCURRENCY


def _settings(*, timeout: float, concurrency: int) -> SweepSettings:
    """Return the checked settings, or raise one ``ValueError`` naming every bad argument."""

    try:
        return SweepSettings(timeout=timeout, concurrency=concurrency)
    except ValidationError as exc:
        raise refused_arguments("sweep", exc) from exc


def _limit(limit: int) -> int:
    """Return ``limit`` if a sweep can be bounded by it, or raise saying why not."""

    try:
        return _LIMIT.validate_python(limit)
    except ValidationError as exc:
        raise refused_arguments("sweep", exc, field="limit") from exc


def local_networks(interfaces: Sequence[Interface] | None = None) -> tuple[ipaddress.IPv4Network, ...]:
    """Return the IPv4 subnets a default sweep covers.

    Args:
        interfaces: The interfaces to read, for a caller that already has them
            or is describing a host other than this one. Defaults to this
            host's own. A real argument rather than something a test patches:
            the whole default path hangs off this list, so it has to be
            possible to state it.

    Returns:
        One network per IPv4 address this host holds, deduplicated, minus the
        ones a sweep has no business probing: loopback, where it would find
        only this host, and any /31 or /32, which hold this host plus at most
        one point-to-point peer.

    Note:
        This is the *sweep* view, not the full picture: a /32 tunnel address
        is a real fact about the host and :func:`~ipscout.subnet.subnet_info`
        still reports it. Naming such a network explicitly still sweeps it.

    Examples:
        >>> all(network.version == 4 for network in local_networks())
        True
        >>> all(network.prefixlen < 31 for network in local_networks())
        True

    """

    found: list[ipaddress.IPv4Network] = []
    for interface in local_interfaces() if interfaces is None else interfaces:
        if interface.is_loopback:
            continue
        for entry in interface.ipv4:
            network = entry.network
            if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen >= POINT_TO_POINT_PREFIX:
                continue
            if network not in found:
                found.append(network)
    return tuple(found)


def _targets(network: str | None, interfaces: Sequence[Interface] | None) -> list[str | IPNetwork]:
    """Return the networks to sweep, from an explicit CIDR or the local ones.

    An explicit CIDR is passed on as text: :meth:`SweepScope.from_networks`
    is the one parser of a network a caller wrote, so it is not parsed here
    as well.
    """

    if network is not None:
        return [network]
    return list(local_networks(interfaces))


def sweep_scope(network: str | None = None, *, limit: int = MAX_SWEEP_HOSTS, interfaces: Sequence[Interface] | None = None) -> SweepScope:
    """Return what a sweep would cover, and what it would leave out.

    Args:
        network: The CIDR that would be swept. Defaults to the subnets this
            host is attached to, as :func:`local_networks` reports them.
        limit: The most addresses the sweep may cover in total. At least 1.
        interfaces: The interfaces the default set comes from. Ignored when
            ``network`` names one.

    Returns:
        The candidates split into covered and skipped, the budget going to the
        ones reported first. Asking before sweeping is what lets a caller
        decide with the same facts the sweep will use, rather than inferring
        coverage from the result.

    Raises:
        ValueError: ``limit`` is below 1, or ``network`` is not a network.

    Note:
        The result is what :func:`arp_scan` and :func:`find_ip_by_mac` accept as
        ``scope=``, so a caller can inspect a plan and then run exactly that
        one - including one built under a different ``limit``.

    Examples:
        >>> sweep_scope("192.168.1.0/24").networks
        (IPv4Network('192.168.1.0/24'),)
        >>> sweep_scope("172.17.0.0/16").skipped
        (IPv4Network('172.17.0.0/16'),)

    """

    return SweepScope.from_networks(_targets(network, interfaces), limit=_limit(limit))


def _plan(network: str | None, scope: SweepScope | None) -> SweepScope:
    """Return the scope to sweep, from a ready plan or from the CIDR given.

    Saying both is refused rather than resolved by precedence: whichever won
    silently, the caller would be reading a result about ground they did not
    ask for.
    """

    if scope is None:
        return sweep_scope(network)
    if network is not None:
        msg = "network and scope are mutually exclusive; a scope already names the networks to sweep"
        raise ValueError(msg)
    return scope


def sweep_argument_refusal(*, scan: bool, named: str | None, scan_flag: str = "scan=True") -> str | None:
    """Return why ground to sweep was named without a sweep, or None when that is not the case.

    Ignoring the argument would answer from the cache alone while the caller
    believes that ground was covered - the same wrong confidence this module
    refuses everywhere else, and harder to notice, because nothing conflicts
    and nothing is printed. One rule and one wording for every surface; each
    names the argument and the flag in its own vocabulary.

    Args:
        scan: Whether a sweep was asked for.
        named: The name of the argument that names ground to sweep, as the
            caller spelled it, or None when no such argument was given.
        scan_flag: How the caller asks for a sweep.

    Returns:
        The refusal to raise, or None when the call is fine.

    Examples:
        >>> sweep_argument_refusal(scan=False, named="--network", scan_flag="--scan")
        '--network applies only with --scan; without it only the existing neighbour cache is searched'
        >>> sweep_argument_refusal(scan=True, named="network") is None
        True

    """

    if scan or named is None:
        return None
    return f"{named} applies only with {scan_flag}; without it only the existing neighbour cache is searched"


def _too_wide(candidates: Sequence[IPNetwork], limit: int) -> IPScoutSweepTooWideError:
    """Return the refusal naming each network and its size against the budget.

    The sizes are named because passing a narrower network is the remedy and
    it cannot be chosen blind.
    """

    sizes = ", ".join(f"{item} holds {item.num_addresses} addresses" for item in candidates)
    return IPScoutSweepTooWideError(f"{sizes}, more than the {limit} this will sweep; pass a narrower network")


def _refuse_an_empty_scope(scope: SweepScope) -> None:
    """Raise when the bound left nothing to sweep at all.

    Every candidate being too wide is not a partial sweep, it is no sweep, and
    silently reading the cache instead would answer a question nobody asked.
    """

    if scope.networks or not scope.skipped:
        return
    raise _too_wide(scope.skipped, scope.limit)


def refuse_a_partial_scope(scope: SweepScope) -> None:
    """Raise unless ``scope`` covers every network it was built from.

    For a caller that cannot use part of what was asked for - one that probes
    each named network's hosts directly rather than reporting coverage - a
    skipped network is not a gap to note but a request it cannot carry out.

    Args:
        scope: The plan, as :meth:`SweepScope.from_networks` or
            :func:`sweep_scope` built it.

    Raises:
        IPScoutSweepTooWideError: A network was left out. The message names
            every network and its size, with the budget, in the same words a
            sweep with nothing left to cover uses.

    Examples:
        >>> refuse_a_partial_scope(SweepScope.from_networks(["192.0.2.0/24"], limit=4096))
        >>> refuse_a_partial_scope(SweepScope.from_networks(["198.18.0.0/15"], limit=4096))
        Traceback (most recent call last):
        ...
        ipscout.errors.IPScoutSweepTooWideError: 198.18.0.0/15 holds 131072 addresses, more than the 4096 this will sweep; pass a narrower network

    """

    if not scope.skipped:
        return
    raise _too_wide((*scope.networks, *scope.skipped), scope.limit)


def _refuse_a_partial_miss(mac: str, scope: SweepScope) -> None:
    """Raise when a sweep that left a network out matched nothing in the rest.

    A complete sweep that finds nothing has established that the address is not
    here; a partial one has only established that it is not in the part it
    reached. Returning the same empty list for both would present the weaker
    finding as the stronger one, which is the whole reason this refuses instead.
    """

    if not scope.skipped:
        return
    # A scope with nothing covered was already refused as too wide, so there is
    # always something to name here. The wording stays neutral about why a
    # network was left out: too wide on its own, or the budget already spent.
    swept = ", ".join(str(item) for item in scope.networks)
    left_out = ", ".join(str(item) for item in scope.skipped)
    msg = f"{mac} holds no address in {swept}, and {left_out} fell outside what one sweep covers, so it cannot be reported as not found; name it to sweep it"
    raise IPScoutSweepIncompleteError(msg)


def _hosts_of(scope: SweepScope) -> list[str]:
    """Return every address the covered networks contain."""

    return [str(address) for item in scope.networks for address in item.hosts()]


def _matching(entries: tuple[Neighbour, ...], wanted: str) -> list[str]:
    """Return the addresses among ``entries`` held by one hardware address.

    Each address appears once, in the order first seen. One hardware address
    can sit on several interfaces - a synthetic NIC and its VF present the
    same one - so the cache holds an entry per interface, and listing an
    address once per entry would make the length of this list a count of
    interfaces rather than of addresses.

    Addresses come out in the form a probe accepts, which for a link-local
    entry means carrying the interface it was learned on: handing back the
    bare address would return something this library's own probes refuse,
    having thrown away the missing piece on the way out.
    """

    found = (entry.scoped for entry in entries if entry.mac and normalise_mac(entry.mac) == wanted)
    return list(dict.fromkeys(found))


def _sweep(scope: SweepScope, *, concurrency: int, timeout: float) -> tuple[Neighbour, ...]:
    """Probe every address the scope covers, then read what the kernel learned."""

    hosts = _hosts_of(scope)
    if hosts:
        # Failures are the normal case here - most addresses in a subnet are
        # unused - so the sweep must not raise on them.
        ping_many(hosts, concurrency=concurrency, times=1, timeout=timeout, interval=0.0, raise_on_error=False)

    return tuple(entry for entry in neighbours() if any(entry.address in item for item in scope.networks))


def arp_scan(
    network: str | None = None,
    *,
    scope: SweepScope | None = None,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_SWEEP_TIMEOUT,
    family: AddressFamily | None = None,
) -> tuple[Neighbour, ...]:
    """Sweep a network, then return what the neighbour cache learned from it.

    Args:
        network: The CIDR to sweep. Defaults to every subnet this host is
            directly attached to that fits the sweep's address budget.
        scope: A plan from :func:`sweep_scope` to run exactly as it stands,
            for a caller who wants to inspect coverage before probing or to
            sweep under a different bound. Mutually exclusive with ``network``.
        concurrency: How many probes are in flight at once.
        timeout: Seconds to wait for each reply.
        family: Restrict the RESULT to one address family. The sweep itself is
            IPv4 either way - there is no IPv6 sweep - but the cache it then
            reads holds both, so the choice belongs on the way out.

    Returns:
        Every cache entry that falls inside the swept networks. Hosts that
        ignore ICMP still appear when they answered the address resolution the
        probe provoked, which is most of the point of sweeping rather than
        just reading the cache.

    Raises:
        IPScoutSweepTooWideError: No candidate network fits in the addresses
            this will sweep, so there is nothing left to probe. Also a
            ``ValueError``, as this has always raised.
        ValueError: Both ``network`` and ``scope`` were given, which would
            leave a silent precedence rule deciding what got swept, or
            ``timeout`` is not above 0 and at most ``MAX_TIMEOUT``, or ``concurrency`` is
            below 1. The arguments are checked before anything is probed.

    Note:
        The sweep is what makes this different from :func:`neighbours`, which
        only reports hosts already spoken to. Both are unprivileged.

        A result assembled from a partial sweep is a partial result. Ask
        :func:`sweep_scope` with the same argument to learn which networks were
        left out; the entries themselves carry no mark.

    """

    settings = _settings(timeout=timeout, concurrency=concurrency)
    plan = _plan(network, scope)
    _refuse_an_empty_scope(plan)
    return of_family(_sweep(plan, concurrency=settings.concurrency, timeout=settings.timeout), family)


def find_ip_by_mac(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    mac: str,
    *,
    scan: bool = False,
    network: str | None = None,
    scope: SweepScope | None = None,
    concurrency: int = DEFAULT_CONCURRENCY,
    family: AddressFamily | None = None,
) -> list[str]:
    """Return the addresses currently holding a hardware address.

    Args:
        mac: The address to search for, in any common written form.
        scan: Sweep the subnet first, so hosts that have not been talked to
            recently are found too. Without it only the existing cache is
            searched, which is instant but only knows what it already knew.
            Naming ``network`` or ``scope`` without this is refused rather than
            ignored.
        network: The CIDR to sweep, when sweeping. Defaults to the local ones.
        scope: A plan from :func:`sweep_scope` to sweep exactly as it stands.
            Mutually exclusive with ``network``.
        concurrency: How many probes are in flight at once.
        family: Restrict to one address family. Worth asking for whenever the
            answer is going to be connected to: one hardware address commonly
            holds an IPv4 AND an IPv6 link-local, and they come out in the
            order the cache learned them, so taking the first of an unfiltered
            list is decided by that order rather than by what the caller can
            use. Unlike :func:`resolve`, a family this hardware does not hold
            is an empty list, not an error - empty already means "not known
            here" for this call, and "holds no IPv6" is an ordinary finding.

    Returns:
        Every address holding that hardware address, which can legitimately be
        more than one, each listed once. Empty when it is not known here. When
        the sweep skipped a network - see :func:`sweep_scope` - a non-empty
        list can still be short an address that hardware holds on the network
        left out.

    Raises:
        ValueError: The hardware address is not one, both ``network`` and
            ``scope`` were given, one of them was given without ``scan``,
            where it would have been ignored, or ``concurrency`` is below 1.
        IPScoutSweepTooWideError: Nothing was left to sweep at all.
        IPScoutSweepIncompleteError: The sweep skipped a network and matched
            nothing in what it did cover, so no answer can be given: "not
            found" would claim ground the sweep never reached. Both are
            ``ValueError`` too, as this has always raised.

    Examples:
        >>> find_ip_by_mac("aa:bb:cc:dd:ee:ff")
        []

    """

    wanted = require_mac(mac)
    settings = _settings(timeout=DEFAULT_SWEEP_TIMEOUT, concurrency=concurrency)
    named = None if network is None and scope is None else "network" if scope is None else "scope"
    refusal = sweep_argument_refusal(scan=scan, named=named)
    if refusal is not None:
        raise ValueError(refusal)
    if not scan:
        return _matching(of_family(neighbours(), family), wanted)

    plan = _plan(network, scope)
    _refuse_an_empty_scope(plan)
    swept = of_family(_sweep(plan, concurrency=settings.concurrency, timeout=settings.timeout), family)
    found = _matching(swept, wanted)
    if not found:
        _refuse_a_partial_miss(mac, plan)
    return found
