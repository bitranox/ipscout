"""Immutable result models and the enums that label them.

Every public callable returns one of these rather than a dict, so a caller
reading a field gets a validated attribute and a checker gets a type. All are
frozen: a probe result records something that already happened, and mutating it
can only make it disagree with reality.

Contents:
    AddressFamily / ProbeMethod / MacScope / CommandName: fixed value sets.
    ResponseObject: the ping result.
    TraceHop / Interface / MacLookup / SubnetInfo: the other result records.
    CapabilityReport / ReachabilityReport / ResolveReport / ReverseDnsReport /
    PackageInfo: the CLI's own payloads.
    JsonError / JsonEnvelope: the machine-readable output envelope.

Two decisions worth knowing:

    **Computed values are ``@computed_field``, not plain properties.** The
    average round trip, the loss percentage and the summary line are derived,
    and a plain ``@property`` is invisible to serialisation - ``asdict`` and an
    ordinary model dump both drop it, producing a payload that looks complete
    while missing exactly the numbers a caller wants. Declaring them as
    computed fields puts them in ``model_dump()`` by construction, so they
    cannot be forgotten again.

    **The enums subclass ``str``.** Their members *are* strings, so the wire
    bytes are unchanged and no conversion is needed at the boundary.
    ``StrEnum`` would be the modern spelling but arrived in 3.11, and this
    package supports 3.10.

"""

from __future__ import annotations

import enum
import statistics

from pydantic import BaseModel, ConfigDict, computed_field

__all__ = [
    "AddressFamily",
    "CapabilityReport",
    "CommandName",
    "Interface",
    "InterfaceAddress",
    "JsonEnvelope",
    "JsonError",
    "MacLookup",
    "MacScope",
    "PackageInfo",
    "ProbeMethod",
    "ReachabilityReport",
    "ResolveReport",
    "ResponseObject",
    "ReverseDnsReport",
    "RouteInfo",
    "SubnetInfo",
    "TraceHop",
]

#: Reported for "no timing data available". A distinct sentinel rather than
#: 0.0, which would average into a summary as a real measurement.
NO_TIME_MS = -1.0

#: Reported for "no address determined". A placeholder in the result only;
#: nothing is ever bound to it.
UNKNOWN_IP = "0.0.0.0"  # noqa: S104  # nosec B104


class _Frozen(BaseModel):
    """Base for every result record: immutable, and strict about extra keys."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class AddressFamily(str, enum.Enum):
    """Address family for a probe, both as a request and as a result."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"


class ProbeMethod(str, enum.Enum):
    """Which protocol actually produced a result.

    Recorded on every result so a TCP-fallback answer can never be mistaken for
    an ICMP one. The two are not comparable: TCP round-trip time includes
    handshake overhead, and a filtered port reads as unreachable on a perfectly
    healthy host.
    """

    ICMP = "icmp"
    TCP = "tcp"


class MacScope(str, enum.Enum):
    """Whose MAC address an answer actually refers to.

    A MAC does not survive a router hop, so for any routed destination the only
    observable hardware address is the next-hop router's. Carrying that in the
    type - rather than in documentation - is what stops a gateway MAC being
    read as the destination's own.
    """

    #: On the local segment; the MAC belongs to the target itself.
    DIRECT = "direct"
    #: Routed; the MAC belongs to the next-hop router.
    NEXT_HOP = "next_hop"
    #: Neither could be determined.
    UNKNOWN = "unknown"


class CommandName(str, enum.Enum):
    """The subcommands, as they appear in the JSON envelope.

    A fixed set that crosses the boundary as a string, so it is an enum rather
    than a literal repeated at each call site.
    """

    PING = "ping"
    PING_MANY = "ping-many"
    REACHABLE = "reachable"
    TRACEROUTE = "traceroute"
    RESOLVE = "resolve"
    REVERSE_DNS = "reverse-dns"
    INTERFACES = "interfaces"
    GATEWAY = "gateway"
    CAPABILITIES = "capabilities"
    INFO = "info"


class ResponseObject(_Frozen):
    """The result of pinging one target.

    The record is frozen, and every derived statistic is a computed field
    rather than a plain property, so a dump carries the numbers a caller
    actually wants rather than silently omitting them.

    Examples:
        >>> result = ResponseObject(target="example.test", reached=True, ip="10.0.0.1",
        ...                         number_of_pings=2, rtts_ms=(1.0, 3.0),
        ...                         packets_sent=2, packets_received=2)
        >>> result.time_min_ms, result.time_avg_ms, result.time_max_ms
        (1.0, 2.0, 3.0)
        >>> result.n_packets_lost, result.packets_lost_percentage
        (0, 0)

        A result with nothing received reports the sentinels:

        >>> down = ResponseObject(target="10.0.0.9", number_of_pings=1,
        ...                       rtts_ms=(None,), packets_sent=1)
        >>> down.reached, down.ip, down.time_avg_ms, down.packets_lost_percentage
        (False, '0.0.0.0', -1.0, 100)

        The derived values are real fields, so a dump carries them:

        >>> "time_avg_ms" in ResponseObject(target="t").model_dump()
        True

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

    @computed_field
    @property
    def time_min_ms(self) -> float:
        """Return the fastest round trip, or the no-data sentinel."""

        received = self._received
        return min(received) if received else NO_TIME_MS

    @computed_field
    @property
    def time_avg_ms(self) -> float:
        """Return the mean round trip, or the no-data sentinel."""

        received = self._received
        return sum(received) / len(received) if received else NO_TIME_MS

    @computed_field
    @property
    def time_max_ms(self) -> float:
        """Return the slowest round trip, or the no-data sentinel."""

        received = self._received
        return max(received) if received else NO_TIME_MS

    @computed_field
    @property
    def jitter_ms(self) -> float:
        """Return the spread of received round trips, or the no-data sentinel.

        Population standard deviation, which needs at least two samples; a
        single reply has no spread and yields the sentinel rather than a
        misleading ``0.0``.
        """

        received = self._received
        return statistics.pstdev(received) if len(received) > 1 else NO_TIME_MS

    @computed_field
    @property
    def n_packets_lost(self) -> int:
        """Return how many sent packets produced no reply."""

        return self.packets_sent - self.packets_received

    @computed_field
    @property
    def packets_lost_percentage(self) -> int:
        """Return loss as a rounded integer percentage.

        Sending nothing counts as total loss rather than raising a division
        by zero.
        """

        if self.packets_sent <= 0:
            return 100
        return round(100 * self.n_packets_lost / self.packets_sent)

    @computed_field
    @property
    def str_result(self) -> str:
        """Return the one-line summary of the result.

        The exact format is a contract: callers log this string, and some
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


class TraceHop(_Frozen):
    """One hop on the path to a target.

    A silent hop is recorded with no address rather than dropped: a firewall
    ignoring one hop in an otherwise complete path is information, and omitting
    it would misnumber every hop after it.
    """

    ttl: int
    address: str | None = None
    rtt_ms: float | None = None
    reached: bool = False
    hostname: str | None = None


class InterfaceAddress(_Frozen):
    """One address bound to an interface.

    A named record rather than an ``(address, prefix)`` pair, because a
    two-element array on the wire makes the reader know the ordering.
    """

    address: str
    prefix_len: int


class Interface(_Frozen):
    """One local network interface."""

    name: str
    ipv4: tuple[InterfaceAddress, ...] = ()
    ipv6: tuple[InterfaceAddress, ...] = ()
    mac: str | None = None
    is_up: bool = False
    is_loopback: bool = False
    mtu: int | None = None


class RouteInfo(_Frozen):
    """How this host would reach one destination.

    Attributes:
        gateway: The next-hop router, or ``None`` when the destination is
            on-link. That distinction is the whole point of the lookup: it is
            what separates a MAC this host can learn from one it cannot.
        interface: Outgoing interface name, where one could be resolved.
        source: The source address the kernel would use.

    """

    gateway: str | None = None
    interface: str | None = None
    source: str | None = None


class MacLookup(_Frozen):
    """A hardware-address answer that states what it is an answer *about*.

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


class SubnetInfo(_Frozen):
    """Addressing for one interface, plus whatever DHCP data the OS stored.

    No DHCP traffic is sent to build this: the addressing half comes from the
    same system calls the interface listing already makes, and the DHCP half is
    read from the lease store the OS's own client wrote.
    """

    interface: str
    address: str
    prefix_len: int
    network: str
    family: AddressFamily = AddressFamily.IPV4
    broadcast: str | None = None
    gateway: str | None = None
    dns_servers: tuple[str, ...] = ()
    domain: str | None = None
    dhcp_server: str | None = None
    lease_obtained: str | None = None
    lease_expires: str | None = None
    mtu: int | None = None


class CapabilityReport(_Frozen):
    """What this host can actually do.

    The machine-readable form of every "unsupported here" message, so a caller
    can find out without provoking an error first.
    """

    icmp_ipv4: bool
    icmp_ipv6: bool
    traceroute: bool


class ReachabilityReport(_Frozen):
    """Whether one target answered, by any means."""

    target: str
    reachable: bool


class ResolveReport(_Frozen):
    """The addresses a name resolved to."""

    target: str
    addresses: tuple[str, ...]


class ReverseDnsReport(_Frozen):
    """The name an address resolved back to, if any."""

    ip: str
    hostname: str | None


class PackageInfo(_Frozen):
    """Static package metadata, as the ``info`` command reports it."""

    name: str
    version: str
    title: str
    homepage: str
    author: str
    shell_command: str


class JsonError(_Frozen):
    """A failure, rendered as data rather than as a traceback."""

    type: str
    message: str


class JsonEnvelope(_Frozen):
    """The machine-readable wrapper around any command's result.

    Carries a boolean the reader can always see, rather than making them infer
    failure from an exit code they may not have captured, and the command name
    so a transcript of several calls stays unambiguous.

    Examples:
        >>> JsonEnvelope(ok=True, command=CommandName.INFO, data={"a": 1}).ok
        True

    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool
    command: CommandName | None = None
    data: object | None = None
    error: JsonError | None = None
