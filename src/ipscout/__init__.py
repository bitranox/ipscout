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

Compatibility:
    ``ping(target, times=4)`` and every attribute of ``ResponseObject`` keep the
    names and semantics of the pre-1.0 ``lib_ping``, so existing calls and
    attribute access continue to work.

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
from .models import (
    AddressFamily,
    Interface,
    MacLookup,
    MacScope,
    ProbeMethod,
    ResponseObject,
    SubnetInfo,
    TraceHop,
)
from .resolve import resolve, reverse_dns
from .traceroute import atrace_path, atraceroute, trace_path, traceroute

__all__ = [
    "AddressFamily",
    "IPScoutError",
    "IPScoutPermissionError",
    "IPScoutResolutionError",
    "IPScoutUnsupportedError",
    "Interface",
    "MacLookup",
    "MacScope",
    "ProbeMethod",
    "ResponseObject",
    "SubnetInfo",
    "TraceHop",
    "ais_reachable",
    "aping",
    "aping_many",
    "atrace_path",
    "atraceroute",
    "icmp_available",
    "is_reachable",
    "ping",
    "ping_many",
    "print_info",
    "resolve",
    "reverse_dns",
    "trace_path",
    "traceroute",
]
