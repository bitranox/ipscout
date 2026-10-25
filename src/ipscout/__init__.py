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
from .banner import agrab_banners, grab_banners
from .dhcp import (
    DhcpSession,
    dhcp_capture_available,
    observe_dhcp,
    observe_dhcp_first_reachable,
    observe_dhcp_session,
)
from .errors import (
    IPScoutError,
    IPScoutPermissionError,
    IPScoutResolutionError,
    IPScoutSweepError,
    IPScoutSweepIncompleteError,
    IPScoutSweepTooWideError,
    IPScoutUnsupportedError,
)
from .factory import icmp_available
from .interfaces import local_interfaces
from .models import (
    AddressFamily,
    Banner,
    BannerState,
    CapabilityReport,
    CommandName,
    Interface,
    InterfaceAddress,
    LeaseInfo,
    MacLookup,
    MacScope,
    Neighbour,
    NeighbourState,
    PackageInfo,
    PortState,
    ProbeMethod,
    ReachabilityReport,
    ResolveReport,
    ResponseObject,
    ReverseDnsReport,
    RouteInfo,
    ScanMethod,
    SnmpState,
    SnmpSystem,
    SnmpVersion,
    SubnetInfo,
    SweepScope,
    TraceHop,
)
from .mtu import path_mtu
from .neighbours import get_mac_address, lookup_mac, neighbours, normalise_mac
from .portscan import ascan_ports, parse_ports, scan_ports
from .resolve import resolve, reverse_dns
from .routes import default_gateway, query_route
from .scan import arp_scan, find_ip_by_mac, local_networks, sweep_scope
from .snmp import aread_snmp_system, read_snmp_system
from .static_neighbours import remove_neighbour, set_neighbour
from .subnet import subnet_info
from .traceroute import atrace_path, atraceroute, trace_path, traceroute
from .wol import wake_on_lan

__all__ = [
    "AddressFamily",
    "Banner",
    "BannerState",
    "CapabilityReport",
    "CommandName",
    "DhcpSession",
    "IPScoutError",
    "IPScoutPermissionError",
    "IPScoutResolutionError",
    "IPScoutSweepError",
    "IPScoutSweepIncompleteError",
    "IPScoutSweepTooWideError",
    "IPScoutUnsupportedError",
    "Interface",
    "InterfaceAddress",
    "LeaseInfo",
    "MacLookup",
    "MacScope",
    "Neighbour",
    "NeighbourState",
    "PackageInfo",
    "PortState",
    "ProbeMethod",
    "ReachabilityReport",
    "ResolveReport",
    "ResponseObject",
    "ReverseDnsReport",
    "RouteInfo",
    "ScanMethod",
    "SnmpState",
    "SnmpSystem",
    "SnmpVersion",
    "SubnetInfo",
    "SweepScope",
    "TraceHop",
    "agrab_banners",
    "ais_reachable",
    "aping",
    "aping_many",
    "aread_snmp_system",
    "arp_scan",
    "ascan_ports",
    "atrace_path",
    "atraceroute",
    "default_gateway",
    "dhcp_capture_available",
    "find_ip_by_mac",
    "get_mac_address",
    "grab_banners",
    "icmp_available",
    "is_reachable",
    "local_interfaces",
    "local_networks",
    "lookup_mac",
    "neighbours",
    "normalise_mac",
    "observe_dhcp",
    "observe_dhcp_first_reachable",
    "observe_dhcp_session",
    "parse_ports",
    "path_mtu",
    "ping",
    "ping_many",
    "print_info",
    "query_route",
    "read_snmp_system",
    "remove_neighbour",
    "resolve",
    "reverse_dns",
    "scan_ports",
    "set_neighbour",
    "subnet_info",
    "sweep_scope",
    "trace_path",
    "traceroute",
    "wake_on_lan",
]
