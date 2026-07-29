"""Sweeping a subnet to learn hardware addresses, and searching by one.

Contents:
    arp_scan: Sweep a network, then read what the kernel learned.
    find_ip_by_mac: Which address currently holds a hardware address.
    local_networks: The subnets this host is directly attached to.

Note:
    **There is no protocol that asks "who has this MAC".** RARP is long dead
    and modern hosts do not answer it. The only way to answer the reverse
    question is to populate the neighbour cache and search it, which is
    exactly what these two do: an ordinary unprivileged ping sweep, then a
    passive cache read. Nothing here needs elevation.

    A hardware address can legitimately be held by several addresses - dual
    stack, or several addresses on one interface - so the search returns every
    match rather than the first.

"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from .api import ping_many
from .interfaces import local_interfaces
from .neighbours import neighbours, normalise_mac

if TYPE_CHECKING:
    from .models import Neighbour

__all__ = ["arp_scan", "find_ip_by_mac", "local_networks"]

#: A sweep wider than this is a scan of somebody else's network, not of a
#: local subnet, and would take long enough that the cache entries from the
#: start of it are stale before the end.
MAX_SWEEP_HOSTS = 4096

#: Enough for a /22 sweep to finish quickly without exhausting file handles.
DEFAULT_CONCURRENCY = 64


def local_networks() -> tuple[ipaddress.IPv4Network, ...]:
    """Return the IPv4 subnets this host is directly attached to.

    Returns:
        One network per non-loopback IPv4 address, deduplicated. Loopback is
        excluded because sweeping it finds only this host.

    Examples:
        >>> all(network.version == 4 for network in local_networks())
        True

    """

    found: list[ipaddress.IPv4Network] = []
    for interface in local_interfaces():
        if interface.is_loopback:
            continue
        for entry in interface.ipv4:
            try:
                network = ipaddress.ip_network(f"{entry.address}/{entry.prefix_len}", strict=False)
            except ValueError:  # pragma: no cover - the OS does not report these
                continue
            if isinstance(network, ipaddress.IPv4Network) and network not in found:
                found.append(network)
    return tuple(found)


def _targets(network: str | None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Return the networks to sweep, from an explicit CIDR or the local ones."""

    if network is not None:
        return [ipaddress.ip_network(network, strict=False)]
    return list(local_networks())


def _hosts_of(networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> list[str]:
    """Return every address to probe, refusing a sweep that is too wide.

    The bound is checked per network and names the one that broke it, because
    the default set comes from the host's own interfaces: a container bridge
    on a /16 is enough to make a bare ``arp_scan()`` unreasonable, and an error
    that does not say which network is at fault leaves the caller guessing.
    """

    for item in networks:
        if item.num_addresses > MAX_SWEEP_HOSTS:
            msg = f"{item} holds {item.num_addresses} addresses, more than the {MAX_SWEEP_HOSTS} this will sweep; pass a narrower network"
            raise ValueError(msg)
    return [str(address) for item in networks for address in item.hosts()]


def arp_scan(network: str | None = None, *, concurrency: int = DEFAULT_CONCURRENCY, timeout: float = 1.0) -> tuple[Neighbour, ...]:
    """Sweep a network, then return what the neighbour cache learned from it.

    Args:
        network: The CIDR to sweep. Defaults to every subnet this host is
            directly attached to.
        concurrency: How many probes are in flight at once.
        timeout: Seconds to wait for each reply.

    Returns:
        Every cache entry that falls inside the swept networks. Hosts that
        ignore ICMP still appear when they answered the address resolution the
        probe provoked, which is most of the point of sweeping rather than
        just reading the cache.

    Raises:
        ValueError: The sweep would cover more addresses than is reasonable.

    Note:
        The sweep is what makes this different from :func:`neighbours`, which
        only reports hosts already spoken to. Both are unprivileged.

    """

    wanted = _targets(network)
    hosts = _hosts_of(wanted)
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
        if any(address in item for item in wanted):
            found.append(entry)
    return tuple(found)


def find_ip_by_mac(mac: str, *, scan: bool = False, network: str | None = None, concurrency: int = DEFAULT_CONCURRENCY) -> list[str]:
    """Return the addresses currently holding a hardware address.

    Args:
        mac: The address to search for, in any common written form.
        scan: Sweep the subnet first, so hosts that have not been talked to
            recently are found too. Without it only the existing cache is
            searched, which is instant but only knows what it already knew.
        network: The CIDR to sweep, when sweeping. Defaults to the local ones.
        concurrency: How many probes are in flight at once.

    Returns:
        Every address holding that hardware address, which can legitimately be
        more than one. Empty when it is not known here.

    Raises:
        ValueError: The hardware address is not one, or the sweep would be
            unreasonably wide.

    Examples:
        >>> find_ip_by_mac("aa:bb:cc:dd:ee:ff")
        []

    """

    wanted = normalise_mac(mac)
    if wanted is None:
        msg = f"not a hardware address: {mac!r}"
        raise ValueError(msg)

    entries = arp_scan(network, concurrency=concurrency) if scan else neighbours()
    return [entry.ip for entry in entries if entry.mac and normalise_mac(entry.mac) == wanted]
