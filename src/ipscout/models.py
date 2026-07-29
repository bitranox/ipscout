"""Immutable result types and the enums that label them.

Every public callable in this package returns one of these rather than a dict,
so a caller reading a field gets a checked attribute and an IDE gets a type.
All result types are frozen: a probe result is a record of something that
already happened, and mutating it can only make it disagree with reality.

Contents:
    AddressFamily: IPv4 / IPv6 selector, used for both input and output.
    ProbeMethod: Which protocol actually produced a result (ICMP or TCP).
    MacScope: Whether a MAC belongs to the target itself or to a router.
    ResponseObject: The ping result. Backward compatible with the old library.
    TraceHop: One hop of a traceroute.
    Interface: One local network interface.
    MacLookup: A MAC answer that carries its own scope.
    SubnetInfo: Addressing plus whatever the OS stored from DHCP.

Note:
    The enums are plain ``enum.Enum`` rather than ``StrEnum`` deliberately.
    ``StrEnum`` arrived in 3.11 and this package supports 3.10, so it is still
    out of reach even after the floor moved up from 3.9.

    Every record here is ``slots=True``, which needs 3.10. A sweep can build
    thousands of results, and slots drop the per-instance dict.

"""

from __future__ import annotations

import enum
import statistics
from dataclasses import dataclass, field

__all__ = [
    "AddressFamily",
    "Interface",
    "MacLookup",
    "MacScope",
    "ProbeMethod",
    "ResponseObject",
    "SubnetInfo",
    "TraceHop",
]

#: Value the old library used for "no timing data available".
NO_TIME_MS = -1.0

#: Value the old library used for "no address determined".
UNKNOWN_IP = "0.0.0.0"  # noqa: S104  # nosec B104 - reported as a value for compatibility, never bound to


class AddressFamily(enum.Enum):
    """Address family for a probe, both as a request and as a result."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"


class ProbeMethod(enum.Enum):
    """Which protocol actually produced a result.

    Recorded on every result so that a TCP-fallback answer can never be
    mistaken for an ICMP one. The two are not comparable: TCP round-trip time
    includes handshake overhead, and a filtered port reads as unreachable on a
    perfectly healthy host.
    """

    ICMP = "icmp"
    TCP = "tcp"


class MacScope(enum.Enum):
    """Whose MAC address an answer actually refers to.

    A MAC address does not survive a router hop, so for any routed destination
    the only observable hardware address is the next-hop router's. Carrying
    that distinction in the result type - rather than in documentation - is
    what stops a gateway MAC being read as the destination's own.
    """

    #: The address is on the local segment; the MAC belongs to the target.
    DIRECT = "direct"
    #: The target is routed; the MAC belongs to the next-hop router.
    NEXT_HOP = "next_hop"
    #: Neither could be determined.
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ResponseObject:
    """The result of pinging one target.

    Every attribute the pre-1.0 library exposed is still present, with the same
    name, the same type and the same sentinel values, so existing attribute
    access keeps working unchanged. Two things did change, both deliberately:
    the class is now frozen, and ``n_packets_lost`` now counts lost packets.
    The old implementation set it to the number of regex matches it found in
    the system ``ping`` output, which was not a packet count at all.

    Attributes:
        target: The target exactly as the caller supplied it, hostname or IP.
        reached: Whether at least one reply came back.
        ip: The resolved address probed, or ``"0.0.0.0"`` if none was resolved.
        number_of_pings: How many echoes the caller asked for.
        time_min_ms: Fastest round trip, or ``-1.0`` when nothing came back.
        time_avg_ms: Mean round trip, or ``-1.0`` when nothing came back.
        time_max_ms: Slowest round trip, or ``-1.0`` when nothing came back.
        n_packets_lost: Packets sent that produced no reply.
        packets_lost_percentage: Loss as a rounded integer percentage.
        rtts_ms: Per-packet round trip, ``None`` in the slot of a lost packet.
        packets_sent: Echoes actually put on the wire.
        packets_received: Replies matched back to those echoes.
        jitter_ms: Population standard deviation of the replies received.
        family: Which address family was used.
        method: Which protocol produced this result.
        error: Populated only when ``raise_on_error=False`` suppressed a raise.

    Examples:
        >>> r = ResponseObject(target="example.test", reached=True, ip="10.0.0.1",
        ...                    number_of_pings=2, rtts_ms=(1.0, 3.0),
        ...                    packets_sent=2, packets_received=2)
        >>> r.time_min_ms, r.time_avg_ms, r.time_max_ms
        (1.0, 2.0, 3.0)
        >>> r.n_packets_lost, r.packets_lost_percentage
        (0, 0)

        A result with nothing received keeps the old sentinels:

        >>> down = ResponseObject(target="10.0.0.9", number_of_pings=1,
        ...                       rtts_ms=(None,), packets_sent=1)
        >>> down.reached, down.ip, down.time_avg_ms, down.packets_lost_percentage
        (False, '0.0.0.0', -1.0, 100)

    """

    target: str
    reached: bool = False
    ip: str = UNKNOWN_IP
    number_of_pings: int = 0
    rtts_ms: tuple[float | None, ...] = ()
    packets_sent: int = 0
    packets_received: int = 0
    family: AddressFamily = AddressFamily.IPV4
    method: ProbeMethod = ProbeMethod.ICMP
    error: str | None = None

    @property
    def _received(self) -> tuple[float, ...]:
        """Return only the round trips that actually came back."""

        return tuple(rtt for rtt in self.rtts_ms if rtt is not None)

    @property
    def time_min_ms(self) -> float:
        """Return the fastest round trip, or the no-data sentinel."""

        received = self._received
        return min(received) if received else NO_TIME_MS

    @property
    def time_avg_ms(self) -> float:
        """Return the mean round trip, or the no-data sentinel."""

        received = self._received
        return sum(received) / len(received) if received else NO_TIME_MS

    @property
    def time_max_ms(self) -> float:
        """Return the slowest round trip, or the no-data sentinel."""

        received = self._received
        return max(received) if received else NO_TIME_MS

    @property
    def jitter_ms(self) -> float:
        """Return the spread of received round trips, or the no-data sentinel.

        Population standard deviation, which needs at least two samples; a
        single reply has no spread to report and yields the sentinel rather
        than a misleading ``0.0``.
        """

        received = self._received
        return statistics.pstdev(received) if len(received) > 1 else NO_TIME_MS

    @property
    def n_packets_lost(self) -> int:
        """Return how many sent packets produced no reply."""

        return self.packets_sent - self.packets_received

    @property
    def packets_lost_percentage(self) -> int:
        """Return loss as a rounded integer percentage.

        Sending nothing counts as total loss rather than as a division by
        zero, matching what the old library reported for a failed run.
        """

        if self.packets_sent <= 0:
            return 100
        return round(100 * self.n_packets_lost / self.packets_sent)

    @property
    def str_result(self) -> str:
        """Return the one-line summary in the pre-1.0 format, unchanged.

        Kept byte-for-byte compatible because callers log it, and some of them
        parse it.

        Examples:
            >>> ResponseObject(target="t", ip="1.1.1.1", number_of_pings=1,
            ...                rtts_ms=(2.5,), packets_sent=1,
            ...                packets_received=1).str_result
            '[1.1.1.1] pinged 1 times, min: 2.50ms, avg: 2.50ms, max: 2.50ms, 0% Packet loss'

        """

        return (
            f"[{self.ip}] pinged {self.number_of_pings} times, "
            f"min: {self.time_min_ms:.2f}ms, "
            f"avg: {self.time_avg_ms:.2f}ms, "
            f"max: {self.time_max_ms:.2f}ms, "
            f"{self.packets_lost_percentage:.0f}% Packet loss"
        )


@dataclass(frozen=True, slots=True)
class TraceHop:
    """One hop on the path to a target.

    Attributes:
        ttl: The hop number, which is the TTL that elicited this response.
        address: The responding router, or ``None`` if the hop stayed silent.
        rtt_ms: Round trip to that router, or ``None`` if it stayed silent.
        reached: Whether this hop is the final target rather than a router.
        hostname: Reverse-DNS name, only when the caller asked to resolve it.

    """

    ttl: int
    address: str | None = None
    rtt_ms: float | None = None
    reached: bool = False
    hostname: str | None = None


@dataclass(frozen=True, slots=True)
class Interface:
    """One local network interface.

    Attributes:
        name: OS interface name, for example ``eth0`` or ``Ethernet``.
        ipv4: IPv4 addresses bound to it, as ``(address, prefix_len)`` pairs.
        ipv6: IPv6 addresses bound to it, as ``(address, prefix_len)`` pairs.
        mac: Hardware address, or ``None`` for interfaces that have none.
        is_up: Whether the OS reports the link as up.
        is_loopback: Whether this is the loopback interface.
        mtu: Link MTU, or ``None`` where the platform did not report one.

    """

    name: str
    ipv4: tuple[tuple[str, int], ...] = ()
    ipv6: tuple[tuple[str, int], ...] = ()
    mac: str | None = None
    is_up: bool = False
    is_loopback: bool = False
    mtu: int | None = None


@dataclass(frozen=True, slots=True)
class MacLookup:
    """A hardware-address answer that states what it is an answer *about*.

    Returned by ``lookup_mac``. The ``scope`` field is the reason this type
    exists: for a routed destination the only MAC obtainable is the next-hop
    router's, and a bare string could not say so.

    Attributes:
        ip: The address that was asked about.
        mac: The hardware address found, or ``None``.
        scope: Whether ``mac`` belongs to ``ip`` itself or to a router.
        via_ip: The next-hop router, set only when scope is ``NEXT_HOP``.
        interface: Outgoing interface, where the platform reported one.

    Examples:
        >>> far = MacLookup(ip="8.8.8.8", mac="aa:bb:cc:dd:ee:ff",
        ...                 scope=MacScope.NEXT_HOP, via_ip="192.168.1.1")
        >>> far.scope is MacScope.NEXT_HOP, far.via_ip
        (True, '192.168.1.1')

    """

    ip: str
    mac: str | None = None
    scope: MacScope = MacScope.UNKNOWN
    via_ip: str | None = None
    interface: str | None = None


@dataclass(frozen=True, slots=True)
class SubnetInfo:
    """Addressing for one interface, plus whatever DHCP data the OS stored.

    No DHCP traffic is sent to build this. The addressing half comes from the
    same system calls the interface listing already makes, and the DHCP half is
    read from the lease store the OS's own client wrote.

    Attributes:
        interface: OS interface name.
        address: The address this record describes.
        prefix_len: Network prefix length in bits.
        network: The network in CIDR form.
        broadcast: Broadcast address, ``None`` for IPv6 which has none.
        gateway: Next-hop router for this network, if one is known.
        dns_servers: Resolvers the OS associates with this interface.
        domain: DNS domain or search suffix.
        dhcp_server: The server that issued the lease, if recorded.
        lease_obtained: When the lease was taken, if recorded.
        lease_expires: When the lease runs out, if recorded.
        mtu: Link MTU, where the platform reported one.

    Note:
        The DHCP-specific fields are frequently ``None`` on macOS, where the
        lease is only exposed through a subprocess this library will not spawn.
        The addressing fields are populated on every supported platform.

    """

    interface: str
    address: str
    prefix_len: int
    network: str
    family: AddressFamily = AddressFamily.IPV4
    broadcast: str | None = None
    gateway: str | None = None
    dns_servers: tuple[str, ...] = field(default_factory=tuple)
    domain: str | None = None
    dhcp_server: str | None = None
    lease_obtained: str | None = None
    lease_expires: str | None = None
    mtu: int | None = None
