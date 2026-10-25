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
import re
import socket
import statistics
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from typing import TYPE_CHECKING, Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, computed_field, model_validator

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = [
    "DEFAULT_TIMEOUT",
    "DISCARD_PORT",
    "MAX_HOP_LIMIT",
    "MAX_PORT",
    "MAX_TIMEOUT",
    "MAX_TIMES",
    "MAX_UPTIME_SECONDS",
    "MIN_PORT",
    "AddressFamily",
    "Banner",
    "BannerState",
    "CapabilityReport",
    "CommandName",
    "FindIpReport",
    "IPNetwork",
    "Interface",
    "InterfaceAddress",
    "JsonEnvelope",
    "JsonError",
    "LeaseInfo",
    "MacLookup",
    "MacScope",
    "MtuReport",
    "Neighbour",
    "NeighbourChange",
    "NeighbourState",
    "ObserveDhcpReport",
    "PackageInfo",
    "Port",
    "PortResult",
    "PortScanReport",
    "PortState",
    "ProbeMethod",
    "ReachabilityReport",
    "RemoveNeighbourReport",
    "ResolveReport",
    "ResponseObject",
    "ReverseDnsReport",
    "RoundTrip",
    "RouteInfo",
    "ScanMethod",
    "SnmpState",
    "SnmpSystem",
    "SnmpVersion",
    "SubnetInfo",
    "SweepScope",
    "Timeout",
    "TraceHop",
    "WakeReport",
    "needs_zone",
    "parse_address",
    "require_address",
    "require_port",
    "require_timeout",
]

#: An IPv4 or IPv6 network, as the standard library models it. Carried as the
#: parsed type rather than as CIDR text: a sweep asks these objects for their
#: size and membership, and Pydantic still writes them to the wire as the same
#: CIDR string while rejecting one that is not a network at all.
IPNetwork = IPv4Network | IPv6Network

#: Reported for "no timing data available". A distinct sentinel rather than
#: 0.0, which would average into a summary as a real measurement.
NO_TIME_MS = -1.0

#: Reported for "no address determined". A placeholder in the result only;
#: nothing is ever bound to it.
UNKNOWN_IP = "0.0.0.0"  # noqa: S104  # nosec B104

#: The lowest and highest TCP/UDP port numbers. Port 0 is excluded: it asks
#: the OS to pick one, so it never names a port on a remote host.
MIN_PORT = 1
MAX_PORT = 65535

#: The largest hop limit an IP header can carry: the IPv4 TTL and the IPv6
#: hop limit are both one byte.
MAX_HOP_LIMIT = 255

#: The discard service's port. A UDP socket ``connect()``-ed to any port makes
#: the kernel pick a route and a source address without sending a packet;
#: this one is used because nothing should be listening on it.
DISCARD_PORT = 9

#: Default seconds to wait for one reply, whatever asked for it: an echo, a
#: hop, a neighbour solicitation or a kernel table query. Defined here, in the
#: lowest layer, so every backend can share it.
DEFAULT_TIMEOUT = 2.0

#: The longest wait, in seconds, any probe accepts. Windows stores a socket
#: timeout as a signed 32-bit count of milliseconds, and past that the
#: interpreter's own clock type overflows on every platform: measured here,
#: ``settimeout(1e10)`` raises ``OverflowError`` mid-probe rather than a
#: refusal before it. The bound is the smallest of those limits.
MAX_TIMEOUT = 2147483.0

#: The largest uptime SNMP can express: TimeTicks is an unsigned 32-bit count of hundredths
#: of a second (RFC 2578), so an agent's uptime wraps to 0 after about 497 days.
MAX_UPTIME_SECONDS = (2**32 - 1) / 100

#: The most echoes one ping sends. Each echo carries its own sequence number,
#: counting from 1, in a 16-bit ICMP header field, so one more would fail
#: half-way through the run instead of before it.
MAX_TIMES = 0xFFFF


def require_port(value: int) -> int:
    """Return ``value`` if it is a usable port number, or raise saying why not.

    The one check every entry point taking a port number applies, so a port
    list, a specification string and a single port are refused alike.

    Args:
        value: The candidate port number.

    Returns:
        ``value`` unchanged.

    Raises:
        ValueError: ``value`` is outside ``MIN_PORT``-``MAX_PORT``.

    Examples:
        >>> require_port(22)
        22
        >>> require_port(0)
        Traceback (most recent call last):
        ...
        ValueError: port out of range 1-65535: 0

    """

    if not MIN_PORT <= value <= MAX_PORT:
        msg = f"port out of range {MIN_PORT}-{MAX_PORT}: {value}"
        raise ValueError(msg)
    return value


def require_timeout(value: float) -> float:
    """Return ``value`` if it is a usable wait in seconds, or raise saying why not.

    The one check every probe taking a timeout applies, so a ping and a
    traceroute refuse the same mistake in the same words. Zero or less would
    never wait, and ``nan`` fails every comparison, so neither is a wait at all.

    Args:
        value: The candidate number of seconds.

    Returns:
        ``value`` unchanged.

    Raises:
        ValueError: ``value`` is not above zero, or is above ``MAX_TIMEOUT``.

    Examples:
        >>> require_timeout(2.0)
        2.0
        >>> require_timeout(0)
        Traceback (most recent call last):
        ...
        ValueError: timeout must be above 0 and at most 2147483 seconds, got 0

    """

    if not 0 < value <= MAX_TIMEOUT:
        msg = f"timeout must be above 0 and at most {MAX_TIMEOUT:.0f} seconds, got {value!r}"
        raise ValueError(msg)
    return value


def parse_address(text: str) -> IPv4Address | IPv6Address:
    """Return ``text`` parsed as an IP address literal of either family, or raise.

    An RFC 4007 ``%zone`` is accepted on an IPv6 address only.

    Raises:
        ValueError: ``text`` is not an address literal.

    Examples:
        >>> parse_address("192.0.2.1")
        IPv4Address('192.0.2.1')
        >>> parse_address("192.0.2.1%eth0")
        Traceback (most recent call last):
        ...
        ValueError: '192.0.2.1%eth0' is not an IP address literal

    """

    try:
        return ip_address(text)
    except ValueError as exc:
        msg = f"{text!r} is not an IP address literal"
        raise ValueError(msg) from exc


def require_address(text: str, family: AddressFamily) -> IPv4Address | IPv6Address:
    """Return ``text`` parsed as an address of ``family``, or raise saying why not.

    The one check for "an address literal of this family", so a request, a
    result and a route lookup refuse a name, a malformed literal and a literal
    of the other family alike. An RFC 4007 ``%zone`` is accepted on an IPv6
    address, the form a link-local target is carried in.

    Args:
        text: The candidate literal.
        family: The family it must belong to.

    Returns:
        The parsed address.

    Raises:
        ValueError: ``text`` is not an address literal, or is one of the other
            family.

    Examples:
        >>> require_address("fe80::1%eth0", AddressFamily.IPV6)
        IPv6Address('fe80::1%eth0')
        >>> require_address("example.test", AddressFamily.IPV4)
        Traceback (most recent call last):
        ...
        ValueError: 'example.test' is not an IP address literal
        >>> require_address("::1", AddressFamily.IPV4)
        Traceback (most recent call last):
        ...
        ValueError: '::1' is not an ipv4 address

    """

    parsed = parse_address(text)
    if parsed.version != family.ip_version:
        msg = f"{text!r} is not an {family.value} address"
        raise ValueError(msg)
    return parsed


def _require_prefix_len(prefix_len: int, address: IPv4Address | IPv6Address) -> None:
    """Raise unless ``prefix_len`` fits the address it belongs to (0-32 or 0-128)."""

    if not 0 <= prefix_len <= address.max_prefixlen:
        msg = f"prefix_len must be 0-{address.max_prefixlen} for {address}, got {prefix_len}"
        raise ValueError(msg)


def needs_zone(address: IPv4Address | IPv6Address) -> bool:
    """Return whether ``address`` is only usable together with an interface (zone).

    Only IPv6 link-local addresses are: they are unique on one link alone, so
    a probe needs the RFC 4007 ``%interface`` suffix to know where to send.

    Examples:
        >>> needs_zone(ip_address("fe80::1"))
        True
        >>> needs_zone(ip_address("169.254.1.1"))
        False

    """

    return address.version == AddressFamily.IPV6.ip_version and address.is_link_local


#: A port number a remote host can be asked about. Every record carrying one
#: refuses anything else, so a reader never meets a port no producer could
#: have probed. The check is ``require_port`` itself rather than a field bound,
#: so a record and a port list refuse the same mistake in the same words.
Port = Annotated[int, AfterValidator(require_port)]

#: Seconds to wait, bounded by ``require_timeout`` for the reason ``Port`` is
#: bounded by ``require_port``: a request field and a plain argument refuse
#: the same value in the same words.
Timeout = Annotated[float, AfterValidator(require_timeout)]

#: One measured round trip in milliseconds. A clock difference, so never
#: negative, and never infinite or ``nan``: a reply that did not come back is
#: ``None``, not a number. Public because a transport's own outcome record is
#: bounded by it too, so a value no clock produces is refused where it is
#: made rather than in the hop record built from it later.
RoundTrip = Annotated[float, Field(ge=0, allow_inf_nan=False)]

#: The largest MTU any record carries. Every OS stores an MTU as a 32-bit
#: count (Windows reports its loopback as ``0xFFFFFFFF``, Linux its own as
#: 65536), so the IP length field is not the bound: an interface MTU and a
#: loopback path MTU both legitimately exceed 65535.
_MAX_MTU = 0xFFFFFFFF

#: Bytes, never zero (an OS that does not know says nothing rather than 0).
_Mtu = Annotated[int, Field(gt=0, le=_MAX_MTU)]

#: The octets of an Ethernet address, and the most any interface's hardware
#: address holds: Linux's ``MAX_ADDR_LEN``, the longest a kernel stores.
_MAC_OCTETS = 6
_MAX_HARDWARE_OCTETS = 32

#: One octet as every producer writes it: two lowercase hex digits.
_OCTET = re.compile(r"[0-9a-f]{2}")


def _octets(text: str) -> list[str] | None:
    """Return the octets of colon-separated lowercase hex, or None if it is not that."""

    parts = text.split(":")
    return parts if all(_OCTET.fullmatch(part) for part in parts) else None


def _require_mac(text: str) -> str:
    """Return ``text`` if it is an Ethernet address in canonical form, or raise.

    The canonical form is the one ``ipscout.arp.normalise_mac`` writes and every
    producer reports: six lowercase two-digit octets joined by colons. A record
    refuses any other spelling so that two records naming one address compare
    equal as text.

    Examples:
        >>> _require_mac("02:00:5e:10:00:00")
        '02:00:5e:10:00:00'
        >>> _require_mac("02-00-5E-10-00-00")
        Traceback (most recent call last):
        ...
        ValueError: '02-00-5E-10-00-00' is not a hardware address in the aa:bb:cc:dd:ee:ff form

    """

    octets = _octets(text)
    if octets is None or len(octets) != _MAC_OCTETS:
        msg = f"{text!r} is not a hardware address in the aa:bb:cc:dd:ee:ff form"
        raise ValueError(msg)
    return text


def _require_hardware_address(text: str) -> str:
    """Return ``text`` if it is an interface hardware address, or raise.

    Wider than :func:`_require_mac`: an interface may carry a link-layer
    address that is not six bytes (a tunnel, an InfiniBand port), written as
    ``ipscout.arp.format_hardware_address`` writes it. All zeros is refused,
    as that formatter reports an all-zero address as no address at all.

    Examples:
        >>> _require_hardware_address("00:11:22:33:44:55:66:77")
        '00:11:22:33:44:55:66:77'
        >>> _require_hardware_address("00:00:00:00:00:00")
        Traceback (most recent call last):
        ...
        ValueError: '00:00:00:00:00:00' is not a hardware address: 1-32 lowercase hex octets, not all zero

    """

    octets = _octets(text)
    if octets is None or len(octets) > _MAX_HARDWARE_OCTETS or not any(int(octet, 16) for octet in octets):
        msg = f"{text!r} is not a hardware address: 1-{_MAX_HARDWARE_OCTETS} lowercase hex octets, not all zero"
        raise ValueError(msg)
    return text


def _require_literal(text: str) -> str:
    """Return ``text`` if it is an IP address literal of either family, or raise."""

    parse_address(text)
    return text


#: An Ethernet address in canonical ``aa:bb:cc:dd:ee:ff`` form.
_Mac = Annotated[str, AfterValidator(_require_mac)]

#: An IP address literal of either family; an IPv6 one may carry its zone.
_IpLiteral = Annotated[str, AfterValidator(_require_literal)]


class _Frozen(BaseModel):
    """Base for every result record: immutable, and strict about extra keys."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class AddressFamily(str, enum.Enum):
    """Address family for a probe, both as a request and as a result."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"

    @property
    def socket_family(self) -> socket.AddressFamily:
        """Return the ``socket.AF_*`` constant a socket of this family is opened with.

        Examples:
            >>> AddressFamily.IPV6.socket_family is socket.AF_INET6
            True

        """

        return socket.AF_INET6 if self is AddressFamily.IPV6 else socket.AF_INET

    @property
    def ip_option_level(self) -> int:
        """Return the ``setsockopt`` level for IP-layer options of this family.

        Examples:
            >>> AddressFamily.IPV6.ip_option_level == socket.IPPROTO_IPV6
            True

        """

        return socket.IPPROTO_IPV6 if self is AddressFamily.IPV6 else socket.IPPROTO_IP

    @property
    def ip_version(self) -> int:
        """Return the number ``ipaddress`` reports as ``.version`` for this family.

        Examples:
            >>> AddressFamily.IPV6.ip_version
            6

        """

        return 6 if self is AddressFamily.IPV6 else 4

    @property
    def unspecified_address(self) -> str:
        """Return the all-zero address of this family in its canonical text form.

        Examples:
            >>> AddressFamily.IPV6.unspecified_address
            '::'

        """

        return "::" if self is AddressFamily.IPV6 else UNKNOWN_IP

    @classmethod
    def of_version(cls, version: int) -> AddressFamily:
        """Return the family whose ``ip_version`` is ``version``.

        Args:
            version: An ``ip_address().version`` value.

        Returns:
            The matching family.

        Raises:
            ValueError: ``version`` is neither 4 nor 6.

        Examples:
            >>> AddressFamily.of_version(4) is AddressFamily.IPV4
            True

        """

        for family in cls:
            if family.ip_version == version:
                return family
        msg = f"no address family has IP version {version}"
        raise ValueError(msg)


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


class PortState(str, enum.Enum):
    """What a scan learned about one port.

    Three states rather than a boolean, because "nothing came back" is a real
    and different answer from "something refused". A connect scan cannot tell
    FILTERED from CLOSED; a SYN scan can, which is most of the reason to use
    one.
    """

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class BannerState(str, enum.Enum):
    """What one banner grab got back from one host.

    Four states rather than "a line or None": a host that accepted the
    connection and said nothing is up, a host that refused is up and has
    nothing on that port, and only an unreachable host is unaccounted for.
    A caller that retries wants the second, and a caller that inventories
    wants the first, so neither may be folded into "no banner".
    """

    #: Connected, and the server sent at least one byte before the deadline.
    GREETED = "greeted"
    #: Connected, but nothing arrived before the deadline or the close.
    SILENT = "silent"
    #: The host actively refused the connection.
    REFUSED = "refused"
    #: No connection: timed out, unroutable, or the name did not resolve.
    UNREACHABLE = "unreachable"


class SnmpVersion(str, enum.Enum):
    """The SNMP version a read speaks.

    The caller chooses: an agent that speaks only one of them ignores the
    other's request entirely, and silence cannot be told apart from a host
    that is down, so falling back automatically would double every timeout.
    """

    V1 = "v1"
    V2C = "v2c"

    @property
    def wire_number(self) -> int:
        """The message's version field: 0 for SNMPv1 (RFC 1157), 1 for SNMPv2c (RFC 1901)."""

        return 0 if self is SnmpVersion.V1 else 1


class SnmpState(str, enum.Enum):
    """How one SNMP read of one host went.

    SILENT is everything SNMP itself cannot tell apart: a host that is down,
    a host with no agent that drops the datagram, and a wrong community, which
    an agent answers with silence. REFUSED is the one absence the network does
    report: the host sent ICMP port unreachable, so it is up with no agent.
    """

    #: The agent replied. Each value may still be None when the agent lacks it.
    ANSWERED = "answered"
    #: Nothing usable arrived before the deadline.
    SILENT = "silent"
    #: ICMP port unreachable: the host is up and nothing listens on the port.
    REFUSED = "refused"
    #: The agent replied with an error status, or with something that is not a valid reply.
    ERROR = "error"
    #: The name did not resolve, or the network reported no route to the host.
    UNREACHABLE = "unreachable"


class ScanMethod(str, enum.Enum):
    """How a port scan asked its question.

    Carried on the result because the two methods do not measure the same
    thing: a full connect completes the handshake and lands in the target's
    logs, while a SYN scan never finishes it and needs a raw socket.
    """

    CONNECT = "connect"
    SYN = "syn"


class NeighbourState(str, enum.Enum):
    """How much the kernel currently trusts a neighbour-cache entry.

    Worth reporting rather than flattening to present/absent: a STALE entry
    holds a real address the kernel has not confirmed lately, while an
    INCOMPLETE one is an unanswered query with no address at all.
    """

    REACHABLE = "reachable"
    STALE = "stale"
    PERMANENT = "permanent"
    INCOMPLETE = "incomplete"
    FAILED = "failed"
    OTHER = "other"


class NeighbourChange(str, enum.Enum):
    """The change a static neighbour write asks the kernel to make.

    Names the request in the error raised when a platform refuses it ("the
    kernel refused to add the neighbour entry"). Render a member with
    ``.value``, never by formatting the member itself: on 3.11 and later an
    f-string of a ``str`` enum member gives ``NeighbourChange.ADD``, not
    ``add``, so the message would change with the interpreter.

    Examples:
        >>> f"refused to {NeighbourChange.REMOVE.value} the entry"
        'refused to remove the entry'

    """

    ADD = "add"
    REMOVE = "remove"


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
    NEIGHBOURS = "neighbours"
    MAC = "mac"
    FIND_IP = "find-ip"
    ARP_SCAN = "arp-scan"
    SET_NEIGHBOUR = "set-neighbour"
    REMOVE_NEIGHBOUR = "remove-neighbour"
    SUBNET = "subnet"
    SCAN_PORTS = "scan-ports"
    BANNERS = "banners"
    SNMP_SYSTEM = "snmp-system"
    MTU = "mtu"
    WAKE = "wake"
    OBSERVE_DHCP = "observe-dhcp"
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

        The counts must agree with each other, as every producer's do:

        >>> ResponseObject(target="t", number_of_pings=1, rtts_ms=(1.0,), packets_sent=1)
        Traceback (most recent call last):
        ...
        pydantic_core._pydantic_core.ValidationError: ...

    Note:
        ``target`` may be empty: it is the caller's input echoed back, and a
        sweep with ``raise_on_error=False`` reports a blank target as a result
        keyed by that blank rather than raising for the whole sweep.

    """

    #: The target exactly as the caller wrote it, so results key back to the input.
    target: str
    #: True exactly when at least one reply came back.
    reached: bool = False
    #: The address probed, of ``family``; the family's unspecified address
    #: (``0.0.0.0`` or ``::``) when no address was determined.
    ip: str = UNKNOWN_IP
    #: Echoes sent. A run sends every echo it asks for, and a refused or
    #: unresolved request sends none, so this always equals ``packets_sent``.
    number_of_pings: int = Field(default=0, ge=0, le=MAX_TIMES)
    #: One entry per echo sent, ``None`` for an echo nothing answered.
    rtts_ms: tuple[RoundTrip | None, ...] = ()
    packets_sent: int = Field(default=0, ge=0, le=MAX_TIMES)
    packets_received: int = Field(default=0, ge=0, le=MAX_TIMES)
    family: AddressFamily = AddressFamily.IPV4
    method: ProbeMethod = ProbeMethod.ICMP
    #: Why nothing was sent, set only by ``raise_on_error=False``. Never
    #: empty: a reason that says nothing is no reason.
    error: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _counts_agree(self) -> ResponseObject:
        require_address(self.ip, self.family)
        answered = sum(1 for rtt in self.rtts_ms if rtt is not None)
        problems = (
            (self.packets_sent != self.number_of_pings, "packets_sent must equal number_of_pings: a run sends every echo it asks for"),
            (len(self.rtts_ms) != self.packets_sent, "rtts_ms must hold one entry per packet sent"),
            (answered != self.packets_received, "packets_received must count the round trips in rtts_ms that came back"),
            (self.reached != (self.packets_received > 0), "reached must be True exactly when a packet was received"),
            (self.error is not None and self.packets_sent > 0, "error is set only on a result that sent nothing"),
        )
        for broken, msg in problems:
            if broken:
                raise ValueError(msg)
        return self

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
            >>> ResponseObject(target="t", reached=True, ip="1.1.1.1", number_of_pings=1,
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

    A hop either answered, and then carries both who answered and how long it
    took, or was silent and carries neither; a name is looked up only for an
    address that answered, and only the answering target ends a walk. Any
    other combination is refused, so a reader can test one field.

    Examples:
        >>> TraceHop(ttl=1, address="192.0.2.1", rtt_ms=1.5).reached
        False
        >>> TraceHop(ttl=2, reached=True)
        Traceback (most recent call last):
        ...
        pydantic_core._pydantic_core.ValidationError: ...

    """

    #: The hop limit the probe carried: 1 for the first router, never past
    #: what the one-byte IP header field can hold.
    ttl: int = Field(ge=1, le=MAX_HOP_LIMIT)
    #: Who answered, as an address literal; ``None`` for a silent hop.
    address: _IpLiteral | None = None
    rtt_ms: RoundTrip | None = None
    reached: bool = False
    #: The answering address's reverse-DNS name. Never empty: no name is
    #: ``None``.
    hostname: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _answered_or_silent(self) -> TraceHop:
        silent = self.address is None
        problems = (
            ((self.rtt_ms is None) != silent, "address and rtt_ms are set together: a hop either answered or was silent"),
            (self.reached and silent, "reached needs the address that answered"),
            (self.hostname is not None and silent, "hostname needs the address it names"),
        )
        for broken, msg in problems:
            if broken:
                raise ValueError(msg)
        return self


class InterfaceAddress(_Frozen):
    """One address bound to an interface.

    A named record rather than an ``(address, prefix)`` pair, because a
    two-element array on the wire makes the reader know the ordering.
    """

    address: str
    #: 0-32 for an IPv4 address, 0-128 for an IPv6 one.
    prefix_len: int

    @model_validator(mode="after")
    def _prefix_fits_the_address(self) -> InterfaceAddress:
        try:
            parsed = ip_address(self.address)
        except ValueError as exc:
            msg = f"{self.address!r} is not an IP address literal"
            raise ValueError(msg) from exc
        _require_prefix_len(self.prefix_len, parsed)
        return self


class Interface(_Frozen):
    """One local network interface.

    Attributes:
        index: The interface index the kernel knows it by, which is the one
            spelling usable as an IPv6 zone on every platform: Windows reports
            a friendly ``name`` here that neither ``getaddrinfo`` nor
            ``if_nametoindex`` recognises. ``None`` only where the OS declined
            to report one.

    """

    #: Never empty: a record that names no interface names nothing a caller
    #: can pass back.
    name: str = Field(min_length=1)
    #: Kernel interface indexes start at 1; 0 means "no interface" everywhere.
    index: int | None = Field(default=None, ge=1)
    #: IPv4 addresses only.
    ipv4: tuple[InterfaceAddress, ...] = ()
    #: IPv6 addresses only.
    ipv6: tuple[InterfaceAddress, ...] = ()
    #: The link-layer address; not always six bytes (a tunnel, InfiniBand).
    mac: Annotated[str, AfterValidator(_require_hardware_address)] | None = None
    is_up: bool = False
    is_loopback: bool = False
    #: Bytes; ``None`` where the OS did not say, never zero.
    mtu: _Mtu | None = None

    @model_validator(mode="after")
    def _addresses_sit_in_their_family(self) -> Interface:
        for family, entries in ((AddressFamily.IPV4, self.ipv4), (AddressFamily.IPV6, self.ipv6)):
            for entry in entries:
                if ip_address(entry.address).version != family.ip_version:
                    msg = f"{entry.address!r} is not an {family.value} address"
                    raise ValueError(msg)
        return self


class LeaseInfo(_Frozen):
    """What the OS's own DHCP client recorded about a lease.

    Every field is optional because lease stores differ in what they keep, and
    a host with a static address has no lease at all. An absent field means
    the store did not say, which is different from a value of zero.
    """

    dhcp_server: str | None = None
    router: str | None = None
    dns_servers: tuple[str, ...] = ()
    domain: str | None = None
    obtained: str | None = None
    expires: str | None = None


class Neighbour(_Frozen):
    """One entry in this host's neighbour cache.

    A record rather than an ``ip -> mac`` pair, because the interface and the
    entry's state both change what the answer means, and a bare mapping would
    force every caller to look them up again.
    """

    #: A bare address literal of ``family``. Bare because the link it was
    #: learned on is ``interface``; :attr:`scoped` joins the two.
    ip: str
    mac: _Mac | None = None
    interface: str | None = None
    state: NeighbourState = NeighbourState.OTHER
    family: AddressFamily = AddressFamily.IPV4

    @model_validator(mode="after")
    def _ip_is_a_bare_address_of_family(self) -> Neighbour:
        if "%" in self.ip:
            msg = f"{self.ip!r} carries a zone; the link is the interface field"
            raise ValueError(msg)
        require_address(self.ip, self.family)
        return self

    @computed_field
    @property
    def scoped(self) -> str:
        """Return ``ip`` in the form a probe accepts.

        A link-local address is only unique on the link it was learned on, so
        it is not a usable target without one and every probe refuses it
        written bare. The interface is already in this record, so the joined
        RFC 4007 form is offered here rather than left for each caller to
        rebuild - and to get wrong for the addresses where a zone is
        meaningless, which is all of them but IPv6 link-local.

        Examples:
            >>> Neighbour(ip="fe80::1", interface="eth0", family=AddressFamily.IPV6).scoped
            'fe80::1%eth0'
            >>> Neighbour(ip="192.168.1.1", interface="eth0").scoped
            '192.168.1.1'

        """

        if self.interface is None or not needs_zone(ip_address(self.ip)):
            return self.ip
        return f"{self.ip}%{self.interface}"


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

        The router is named exactly when the answer is the router's:

        >>> MacLookup(ip="192.0.2.5", mac="aa:bb:cc:dd:ee:ff", scope=MacScope.DIRECT, via_ip="192.0.2.1")
        Traceback (most recent call last):
        ...
        pydantic_core._pydantic_core.ValidationError: ...

    """

    #: The address asked about, as the caller wrote it (a zone included).
    ip: _IpLiteral
    mac: _Mac | None = None
    scope: MacScope = MacScope.UNKNOWN
    #: The next-hop router, set exactly when ``scope`` is NEXT_HOP.
    via_ip: _IpLiteral | None = None
    interface: str | None = None

    @model_validator(mode="after")
    def _fields_agree_with_scope(self) -> MacLookup:
        problems = (
            ((self.via_ip is not None) != (self.scope is MacScope.NEXT_HOP), "via_ip is set exactly when scope is NEXT_HOP"),
            (self.scope is MacScope.DIRECT and self.mac is None, "a DIRECT answer carries the hardware address it found"),
            (self.scope is MacScope.UNKNOWN and self.mac is not None, "an UNKNOWN answer carries no hardware address"),
        )
        for broken, msg in problems:
            if broken:
                raise ValueError(msg)
        return self


class SubnetInfo(_Frozen):
    """Addressing for one interface, plus whatever DHCP data the OS stored.

    No DHCP traffic is sent to build this: the addressing half comes from the
    same system calls the interface listing already makes, and the DHCP half is
    read from the lease store the OS's own client wrote.
    """

    interface: str
    #: An address of ``family``.
    address: str
    #: 0-32 for IPv4, 0-128 for IPv6.
    prefix_len: int
    #: The network ``address/prefix_len`` sits on, and nothing else. Parsed,
    #: so a reader can ask it for size and membership; written to JSON as the
    #: same CIDR text.
    network: IPNetwork
    family: AddressFamily = AddressFamily.IPV4
    #: The IPv4 network's broadcast address; IPv6 has none.
    broadcast: _IpLiteral | None = None
    #: A router of ``family``.
    gateway: _IpLiteral | None = None
    dns_servers: tuple[str, ...] = ()
    domain: str | None = None
    dhcp_server: str | None = None
    lease_obtained: str | None = None
    lease_expires: str | None = None
    #: Bytes; ``None`` where the OS did not say, never zero.
    mtu: _Mtu | None = None

    @model_validator(mode="after")
    def _addressing_agrees(self) -> SubnetInfo:
        _require_prefix_len(self.prefix_len, require_address(self.address, self.family))
        expected = ip_network(f"{self.address}/{self.prefix_len}", strict=False)
        if self.network != expected:
            msg = f"network must be {expected} for {self.address}/{self.prefix_len}, got {self.network}"
            raise ValueError(msg)
        if self.broadcast is not None and (not isinstance(expected, IPv4Network) or ip_address(self.broadcast) != expected.broadcast_address):
            msg = f"broadcast must be the broadcast address of {expected}, got {self.broadcast!r}"
            raise ValueError(msg)
        if self.gateway is not None:
            require_address(self.gateway, self.family)
        return self


class PortResult(_Frozen):
    """One port and what the scan found it to be."""

    port: Port
    state: PortState


class PortScanReport(_Frozen):
    """The result of scanning one host.

    Carries the method because the two do not measure the same thing: a
    connect scan completed a handshake, a SYN scan did not.
    """

    host: str
    method: ScanMethod = ScanMethod.CONNECT
    ports: tuple[PortResult, ...] = ()


class Banner(_Frozen):
    """The first line one host sent on one TCP port, and how the attempt went.

    ``line`` is set exactly when the state is GREETED, and ``error`` exactly
    when it is UNREACHABLE; any other pairing is refused at construction, so a
    reader can trust the state alone instead of re-checking both fields.

    Examples:
        >>> Banner(host="printer.test", port=21, state=BannerState.GREETED, line="220 ready").line
        '220 ready'
        >>> Banner(host="printer.test", port=21, state=BannerState.REFUSED).line is None
        True

    """

    #: The host exactly as the caller gave it, so results key back to the input.
    host: str
    port: Port
    state: BannerState
    #: The decoded first line, terminator and surrounding whitespace removed.
    line: str | None = None
    #: Why the host was unreachable, in the resolver's or the OS's words.
    #: Never empty: the reason column prints it, and an empty one says nothing.
    error: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _fields_agree_with_state(self) -> Banner:
        if (self.line is not None) != (self.state is BannerState.GREETED):
            msg = "line is set exactly when state is GREETED"
            raise ValueError(msg)
        if (self.error is not None) != (self.state is BannerState.UNREACHABLE):
            msg = "error is set exactly when state is UNREACHABLE"
            raise ValueError(msg)
        return self


class SnmpSystem(_Frozen):
    """The SNMP system group of one host, and how the read went.

    The four values are set only when the state is ANSWERED, each None when
    the agent does not have it; ``error`` is set exactly when the state is
    ERROR or UNREACHABLE. Any other pairing is refused at construction, so a
    reader can trust the state alone.

    Examples:
        >>> SnmpSystem(host="printer.test", state=SnmpState.ANSWERED, uptime_seconds=12.5).uptime_seconds
        12.5
        >>> SnmpSystem(host="printer.test", state=SnmpState.SILENT).name is None
        True

    """

    #: The host exactly as the caller gave it, so results key back to the input.
    host: str
    state: SnmpState
    #: sysUpTime.0 in seconds: how long the agent has run, which falls when the host restarts.
    uptime_seconds: float | None = Field(default=None, ge=0, le=MAX_UPTIME_SECONDS)
    #: sysName.0, the name an administrator gave the device.
    name: str | None = None
    #: sysDescr.0, the agent's free-text description of the device.
    description: str | None = None
    #: sysObjectID.0 in dotted form: the vendor's identifier for the device model.
    object_id: str | None = Field(default=None, pattern=r"\A[0-2](\.[0-9]+)+\z")
    #: Why the read failed. Never empty, and never contains the community.
    error: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _fields_agree_with_state(self) -> SnmpSystem:
        values = (self.uptime_seconds, self.name, self.description, self.object_id)
        if self.state is not SnmpState.ANSWERED and any(value is not None for value in values):
            msg = "values are set only when state is ANSWERED"
            raise ValueError(msg)
        if (self.error is not None) != (self.state in {SnmpState.ERROR, SnmpState.UNREACHABLE}):
            msg = "error is set exactly when state is ERROR or UNREACHABLE"
            raise ValueError(msg)
        return self


class MtuReport(_Frozen):
    """The path MTU to one target, where it could be determined."""

    target: str
    #: Bytes; ``None`` when the path MTU could not be determined, never zero.
    #: Can exceed 65535: the loopback path's is the loopback interface's.
    mtu: _Mtu | None = None


class RemoveNeighbourReport(_Frozen):
    """The outcome of asking to delete a neighbour entry.

    ``removed`` is ``False`` when there was no entry to delete, which is an
    answer rather than a failure.
    """

    ip: str
    interface: str | None = None
    removed: bool


class WakeReport(_Frozen):
    """A magic packet that was sent.

    ``sent`` is not ``woken``. Nothing acknowledges a magic packet, so this
    records only that it left this host.
    """

    mac: _Mac
    #: The IPv4 address it went to; never ``0.0.0.0``, which is this host.
    broadcast: str
    port: Port
    sent: bool = True

    @model_validator(mode="after")
    def _broadcast_is_a_destination(self) -> WakeReport:
        if require_address(self.broadcast, AddressFamily.IPV4).is_unspecified:
            msg = f"broadcast must be an IPv4 address other than 0.0.0.0, got {self.broadcast!r}"
            raise ValueError(msg)
        return self


class SweepScope(_Frozen):
    """Which networks a sweep covers, and which it had to leave out.

    Coverage is data rather than a comment, because a sweep that skipped a
    network answers a smaller question than the caller asked: "nothing found"
    over part of the ground is not "nothing there". Both fields hold parsed
    networks, which is what a sweep needs to ask for their size and membership,
    and which cross the output boundary as the same CIDR text.

    Examples:
        >>> scope = SweepScope(networks=("192.168.1.0/24",), skipped=("172.17.0.0/16",), limit=4096)
        >>> scope.complete
        False
        >>> scope.model_dump(mode="json")["skipped"]
        ['172.17.0.0/16']

    """

    #: The most addresses the sweep may cover, which is what decided the split.
    #: Recorded rather than assumed, so a message or a reader can state the
    #: budget a scope was built under instead of naming a default that may not
    #: be the one that applied.
    limit: int = Field(ge=1)
    #: The networks the sweep probes.
    networks: tuple[IPNetwork, ...] = ()
    #: The networks left out for not fitting in what the sweep bound allows.
    skipped: tuple[IPNetwork, ...] = ()

    @model_validator(mode="after")
    def _networks_fit_the_limit(self) -> SweepScope:
        covered = sum(network.num_addresses for network in self.networks)
        if covered > self.limit:
            msg = f"networks cover {covered} addresses, more than the limit of {self.limit}"
            raise ValueError(msg)
        return self

    @classmethod
    def from_networks(cls, networks: Iterable[str | IPNetwork], *, limit: int) -> SweepScope:
        """Return the scope a sweep of ``networks`` bounded by ``limit`` covers.

        Args:
            networks: The candidate networks, as CIDR text or network objects.
            limit: The most addresses the sweep may cover in total, across every
                network in it.

        Returns:
            The candidates split in two, each side keeping the order it came
            in, so a message naming them reads in the order the caller sees
            elsewhere.

        Note:
            The bound is on the sweep, not on each network in it: a candidate is
            covered while the budget has room for all of it, and skipped once it
            does not. Checking each network against the full limit instead would
            let a host attached to several subnets probe their sum, which is the
            number that decides how long the sweep takes and whether the cache
            entries from the start of it are still fresh at the end.

            Candidates are taken in the order given, so the budget goes to the
            networks the host reports first rather than to whichever happens to
            be smallest. That keeps the result stable for one host instead of
            reshuffling when an interface changes size.

        Examples:
            >>> scope = SweepScope.from_networks(["192.168.1.0/24", "172.17.0.0/16"], limit=4096)
            >>> scope.networks, scope.skipped
            ((IPv4Network('192.168.1.0/24'),), (IPv4Network('172.17.0.0/16'),))

            A network that would fit on its own is still left out once the
            budget is spent:

            >>> spent = SweepScope.from_networks(["10.0.0.0/20", "10.1.0.0/24"], limit=4096)
            >>> spent.networks, spent.skipped
            ((IPv4Network('10.0.0.0/20'),), (IPv4Network('10.1.0.0/24'),))

        """

        # A str is an iterable of str: without this, one network written as text
        # is split into characters and each is refused as a network of its own.
        if isinstance(networks, (str, bytes)):
            msg = f"networks must be a collection of networks, not one network as text; pass [{networks!r}]"
            raise ValueError(msg)
        covered: list[IPNetwork] = []
        skipped: list[IPNetwork] = []
        room = limit
        for candidate in networks:
            # Text is parsed once here; a network object arrives parsed already.
            network = candidate if isinstance(candidate, (IPv4Network, IPv6Network)) else ip_network(candidate, strict=False)
            if network.num_addresses <= room:
                covered.append(network)
                room -= network.num_addresses
            else:
                skipped.append(network)
        return cls(limit=limit, networks=tuple(covered), skipped=tuple(skipped))

    @computed_field
    @property
    def complete(self) -> bool:
        """Return whether every candidate network was covered.

        A computed field rather than a plain property so it survives into
        ``model_dump()``: a consumer reading only the JSON would otherwise have
        to rediscover the rule that an empty ``skipped`` means full coverage.

        This answers "was anything left out", not "was anything covered": a
        scope with no candidates at all is trivially complete. Read ``networks``
        when the difference matters, which it does on a host with no sweepable
        subnet - there, an empty answer is honest but it rests on nothing.
        """

        return not self.skipped


class FindIpReport(_Frozen):
    """The addresses found holding one hardware address.

    Attributes:
        scope: What the sweep covered, or ``None`` when no sweep was asked for
            and only the existing cache was read. With a non-empty
            ``scope.skipped`` the address list can be short one address, since
            the same hardware address may hold one on a network left out.

    """

    mac: _Mac
    addresses: tuple[str, ...] = ()
    #: Whether a sweep ran first; exactly when ``scope`` says what it covered.
    scanned: bool = False
    scope: SweepScope | None = None

    @model_validator(mode="after")
    def _scope_exactly_when_scanned(self) -> FindIpReport:
        if self.scanned != (self.scope is not None):
            msg = "scope is set exactly when scanned is True"
            raise ValueError(msg)
        return self


class ObserveDhcpReport(_Frozen):
    """The addresses a DHCP server was seen offering to one machine.

    Attributes:
        timeout: The window that was watched, and ``settle`` the quiet period
            that ended it. Both are recorded for the reason :class:`SweepScope`
            records its limit: an empty list after sixty seconds and an empty
            list after a fifth of a second are different facts, and a reader
            has no other way to tell them apart.
        interface: Which interface was watched. An empty answer from the wrong
            one means nothing at all.

    """

    mac: _Mac
    interface: str | None = None
    addresses: tuple[str, ...] = ()
    timeout: Timeout
    #: Zero is a real setting: answer on the first address seen. Bounded like
    #: a timeout, since it is one: a wait in seconds.
    settle: float = Field(ge=0, le=MAX_TIMEOUT, allow_inf_nan=False)


class CapabilityReport(_Frozen):
    """What this host can actually do.

    The machine-readable form of every "unsupported here" message, so a caller
    can find out without provoking an error first.
    """

    icmp_ipv4: bool
    icmp_ipv6: bool
    traceroute: bool
    dhcp_capture: bool


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

    #: The exception class name, which a reader can branch on.
    type: str = Field(min_length=1)
    #: The sentence a person reads. Never empty: an empty one says nothing.
    message: str = Field(min_length=1)


class JsonEnvelope(_Frozen):
    """The machine-readable wrapper around any command's result.

    Carries a boolean the reader can always see, rather than making them infer
    failure from an exit code they may not have captured, and the command name
    so a transcript of several calls stays unambiguous.

    Attributes:
        skipped: Networks a sweeping command could not cover. It sits on the
            envelope rather than only inside ``data`` because a command whose
            payload is a bare list - ``arp-scan`` - has nowhere to carry it,
            and a reader must be able to tell full coverage from partial in
            every command that can have either.

    Examples:
        >>> JsonEnvelope(ok=True, command=CommandName.INFO, data={"a": 1}).ok
        True

    """

    #: True exactly when ``error`` is None: a failure always says why, and a
    #: success never carries a reason for failing.
    ok: bool
    command: CommandName | None = None
    data: object | None = None
    error: JsonError | None = None
    skipped: tuple[IPNetwork, ...] = ()

    @model_validator(mode="after")
    def _ok_exactly_without_error(self) -> JsonEnvelope:
        if self.ok != (self.error is None):
            msg = "ok is True exactly when error is None"
            raise ValueError(msg)
        return self
