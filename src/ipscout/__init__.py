"""ipscout - network reachability and local-network inspection, without admin rights.

Probes hosts and inspects the local network entirely in-process: no subprocess
is ever spawned, and no administrator or root privileges are required for the
default paths.

How that is possible:
    On Linux and macOS ICMP goes over ``SOCK_DGRAM``/``IPPROTO_ICMP``, the
    unprivileged "ping socket", where the kernel handles the privileged part.
    On Windows it goes through ``iphlpapi.dll`` via ctypes, which likewise
    needs no elevation - unlike raw sockets, which do.

The error contract:
    Setup problems raise; network conditions do not. A down host, a timeout, or
    total packet loss all return a ``ResponseObject`` with ``reached=False``.
    Missing permission, an unresolvable name, or an invalid argument raise.
    ``is_reachable`` is the deliberate exception - it never raises.

Examples:
    >>> import ipscout
    >>> result = ipscout.ping("127.0.0.1", 2, interval=0)
    >>> result.reached
    True
    >>> ipscout.is_reachable("127.0.0.1")
    True

"""

from __future__ import annotations

from .__init__conf__ import print_info
from .api import (
    ais_reachable,
    aping,
    aping_many,
    is_reachable,
    ping,
    ping_many,
)
from .errors import (
    IPScoutError,
    IPScoutPermissionError,
    IPScoutResolutionError,
    IPScoutUnsupportedError,
)
from .factory import icmp_available
from .interfaces import local_interfaces
from .models import (
    AddressFamily,
    CapabilityReport,
    CommandName,
    Interface,
    InterfaceAddress,
    MacLookup,
    MacScope,
    Neighbour,
    NeighbourState,
    PackageInfo,
    ProbeMethod,
    ReachabilityReport,
    ResolveReport,
    ResponseObject,
    ReverseDnsReport,
    RouteInfo,
    SubnetInfo,
    TraceHop,
)
from .neighbours import get_mac_address, lookup_mac, neighbours, normalise_mac
from .resolve import resolve, reverse_dns
from .routes import default_gateway, query_route
from .scan import arp_scan, find_ip_by_mac, local_networks
from .traceroute import atrace_path, atraceroute, trace_path, traceroute

__all__ = [
    "AddressFamily",
    "CapabilityReport",
    "CommandName",
    "IPScoutError",
    "IPScoutPermissionError",
    "IPScoutResolutionError",
    "IPScoutUnsupportedError",
    "Interface",
    "InterfaceAddress",
    "MacLookup",
    "MacScope",
    "Neighbour",
    "NeighbourState",
    "PackageInfo",
    "ProbeMethod",
    "ReachabilityReport",
    "ResolveReport",
    "ResponseObject",
    "ReverseDnsReport",
    "RouteInfo",
    "SubnetInfo",
    "TraceHop",
    "ais_reachable",
    "aping",
    "aping_many",
    "arp_scan",
    "atrace_path",
    "atraceroute",
    "default_gateway",
    "find_ip_by_mac",
    "get_mac_address",
    "icmp_available",
    "is_reachable",
    "local_interfaces",
    "local_networks",
    "lookup_mac",
    "neighbours",
    "normalise_mac",
    "ping",
    "ping_many",
    "print_info",
    "query_route",
    "resolve",
    "reverse_dns",
    "trace_path",
    "traceroute",
]
