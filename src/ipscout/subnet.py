"""Everything this host knows about the subnets it sits on.

Contents:
    subnet_info: Addressing, gateway and DHCP facts per interface.

Note:
    **No DHCP traffic is sent.** The addressing half comes from the same
    system calls the interface listing already makes, the gateway from the
    route lookup, and the DHCP half from the lease store the OS's own client
    wrote. Everything here is a read, and nothing needs privileges.

    macOS and Windows are honestly weaker on the DHCP half: the lease store is
    read on Linux, while elsewhere those fields may come back unset. The
    addressing fields work everywhere. That is stated rather than papered over
    with a guess.

"""

from __future__ import annotations

import ipaddress
import sys

from .interfaces import local_interfaces
from .models import AddressFamily, LeaseInfo, SubnetInfo
from .routes import default_gateway

__all__ = ["subnet_info"]

IS_LINUX = sys.platform.startswith("linux")


def _lease_for(interface: str) -> LeaseInfo:
    """Return the stored lease for one interface, where a store is readable."""

    if IS_LINUX:
        from .leases_linux import lease_for  # noqa: PLC0415 - Linux-only import

        return lease_for(interface)
    # macOS keeps this behind SCDynamicStore and `ipconfig getpacket`, a
    # subprocess this library does not spawn; Windows carries it on the
    # adapter structures, which the interface layer does not read today.
    return LeaseInfo()


def subnet_info(interface: str | None = None) -> tuple[SubnetInfo, ...]:
    """Return the subnets this host is attached to, with what is known of each.

    Args:
        interface: Report only this interface. ``None`` reports all of them,
            loopback included, since a loopback subnet is a fact about the
            host rather than an omission.

    Returns:
        One record per address, not per interface: an interface with several
        addresses sits on several subnets, and collapsing them would lose the
        distinction.

    Note:
        The gateway is the host's default route, attributed to the interface
        that route leaves by. An interface that is not the default route's
        gets no gateway rather than being given one it does not use.

    Examples:
        >>> subnets = subnet_info()
        >>> all(item.network for item in subnets)
        True

    """

    route = default_gateway()
    found: list[SubnetInfo] = []

    for item in local_interfaces():
        if interface is not None and item.name != interface:
            continue

        lease = _lease_for(item.name)
        gateway = route.gateway if route and route.interface == item.name else None

        for family, entries in ((AddressFamily.IPV4, item.ipv4), (AddressFamily.IPV6, item.ipv6)):
            for entry in entries:
                try:
                    network = ipaddress.ip_network(f"{entry.address}/{entry.prefix_len}", strict=False)
                except ValueError:  # pragma: no cover - the OS does not report these
                    continue

                broadcast: str | None = None
                if isinstance(network, ipaddress.IPv4Network) and network.num_addresses > 1:
                    # IPv6 has no broadcast address at all, and a /32 has no
                    # room for one, so neither gets invented.
                    broadcast = str(network.broadcast_address)

                found.append(
                    SubnetInfo(
                        interface=item.name,
                        address=entry.address,
                        prefix_len=entry.prefix_len,
                        network=str(network),
                        family=family,
                        broadcast=broadcast,
                        gateway=gateway if family is AddressFamily.IPV4 else None,
                        dns_servers=lease.dns_servers,
                        domain=lease.domain,
                        dhcp_server=lease.dhcp_server,
                        lease_obtained=lease.obtained,
                        lease_expires=lease.expires,
                        mtu=item.mtu,
                    )
                )
    return tuple(found)
