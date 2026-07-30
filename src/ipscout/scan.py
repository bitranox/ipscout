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
from typing import TYPE_CHECKING

from .api import ping_many
from .errors import IPScoutSweepIncompleteError, IPScoutSweepTooWideError
from .interfaces import local_interfaces
from .models import SweepScope
from .neighbours import neighbours, normalise_mac

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .models import Interface, IPNetwork, Neighbour

__all__ = ["arp_scan", "find_ip_by_mac", "local_networks", "sweep_scope"]

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
            try:
                network = ipaddress.ip_network(f"{entry.address}/{entry.prefix_len}", strict=False)
            except ValueError:  # pragma: no cover - the OS does not report these
                continue
            if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen >= POINT_TO_POINT_PREFIX:
                continue
            if network not in found:
                found.append(network)
    return tuple(found)


def _targets(network: str | None, interfaces: Sequence[Interface] | None) -> list[IPNetwork]:
    """Return the networks to sweep, from an explicit CIDR or the local ones."""

    if network is not None:
        return [ipaddress.ip_network(network, strict=False)]
    return list(local_networks(interfaces))


def sweep_scope(network: str | None = None, *, limit: int = MAX_SWEEP_HOSTS, interfaces: Sequence[Interface] | None = None) -> SweepScope:
    """Return what a sweep would cover, and what it would leave out.

    Args:
        network: The CIDR that would be swept. Defaults to the subnets this
            host is attached to, as :func:`local_networks` reports them.
        limit: The most addresses the sweep may cover in total.
        interfaces: The interfaces the default set comes from. Ignored when
            ``network`` names one.

    Returns:
        The candidates split into covered and skipped, the budget going to the
        ones reported first. Asking before sweeping is what lets a caller
        decide with the same facts the sweep will use, rather than inferring
        coverage from the result.

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

    return SweepScope.from_networks(_targets(network, interfaces), limit=limit)


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


def _refuse_a_sweep_argument_without_a_sweep(*, scan: bool, network: str | None, scope: SweepScope | None) -> None:
    """Raise when ground to sweep was named but no sweep was asked for.

    Ignoring the argument would answer from the cache alone while the caller
    believes that ground was covered - the same wrong confidence this module
    refuses everywhere else, and harder to notice, because nothing conflicts
    and nothing is printed.
    """

    if scan or (network is None and scope is None):
        return
    named = "network" if scope is None else "scope"
    msg = f"{named} applies only with scan=True; without it only the existing neighbour cache is searched"
    raise ValueError(msg)


def _refuse_an_empty_scope(scope: SweepScope) -> None:
    """Raise when the bound left nothing to sweep at all.

    Every candidate being too wide is not a partial sweep, it is no sweep, and
    silently reading the cache instead would answer a question nobody asked.
    The message names each refused network and its size, because passing a
    narrower one is the remedy and it cannot be chosen blind.
    """

    if scope.networks or not scope.skipped:
        return
    sizes = ", ".join(f"{item} holds {item.num_addresses} addresses" for item in scope.skipped)
    msg = f"{sizes}, more than the {scope.limit} this will sweep; pass a narrower network"
    raise IPScoutSweepTooWideError(msg)


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
    """Return the addresses among ``entries`` held by one hardware address."""

    return [entry.ip for entry in entries if entry.mac and normalise_mac(entry.mac) == wanted]


def _sweep(scope: SweepScope, *, concurrency: int, timeout: float) -> tuple[Neighbour, ...]:
    """Probe every address the scope covers, then read what the kernel learned."""

    hosts = _hosts_of(scope)
    if hosts:
        # Failures are the normal case here - most addresses in a subnet are
        # unused - so the sweep must not raise on them.
        ping_many(hosts, concurrency=concurrency, times=1, timeout=timeout, interval=0.0, raise_on_error=False)

    found: list[Neighbour] = []
    for entry in neighbours():
        try:
            address = ipaddress.ip_address(entry.ip)
        except ValueError:  # pragma: no cover - the kernel does not emit these
            continue
        if any(address in item for item in scope.networks):
            found.append(entry)
    return tuple(found)


def arp_scan(
    network: str | None = None,
    *,
    scope: SweepScope | None = None,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_SWEEP_TIMEOUT,
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
            leave a silent precedence rule deciding what got swept.

    Note:
        The sweep is what makes this different from :func:`neighbours`, which
        only reports hosts already spoken to. Both are unprivileged.

        A result assembled from a partial sweep is a partial result. Ask
        :func:`sweep_scope` with the same argument to learn which networks were
        left out; the entries themselves carry no mark.

    """

    plan = _plan(network, scope)
    _refuse_an_empty_scope(plan)
    return _sweep(plan, concurrency=concurrency, timeout=timeout)


def find_ip_by_mac(
    mac: str,
    *,
    scan: bool = False,
    network: str | None = None,
    scope: SweepScope | None = None,
    concurrency: int = DEFAULT_CONCURRENCY,
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

    Returns:
        Every address holding that hardware address, which can legitimately be
        more than one. Empty when it is not known here. When the sweep skipped
        a network - see :func:`sweep_scope` - a non-empty list can still be
        short an address that hardware holds on the network left out.

    Raises:
        ValueError: The hardware address is not one, both ``network`` and
            ``scope`` were given, or one of them was given without ``scan``,
            where it would have been ignored.
        IPScoutSweepTooWideError: Nothing was left to sweep at all.
        IPScoutSweepIncompleteError: The sweep skipped a network and matched
            nothing in what it did cover, so no answer can be given: "not
            found" would claim ground the sweep never reached. Both are
            ``ValueError`` too, as this has always raised.

    Examples:
        >>> find_ip_by_mac("aa:bb:cc:dd:ee:ff")
        []

    """

    wanted = normalise_mac(mac)
    if wanted is None:
        msg = f"not a hardware address: {mac!r}"
        raise ValueError(msg)

    _refuse_a_sweep_argument_without_a_sweep(scan=scan, network=network, scope=scope)
    if not scan:
        return _matching(neighbours(), wanted)

    plan = _plan(network, scope)
    _refuse_an_empty_scope(plan)
    found = _matching(_sweep(plan, concurrency=concurrency, timeout=DEFAULT_SWEEP_TIMEOUT), wanted)
    if not found:
        _refuse_a_partial_miss(mac, plan)
    return found
