"""SNMP system reads: the uptime, name, description and object id of many hosts.

Contents:
    read_snmp_system / aread_snmp_system: One GET of the system group per host.
    SnmpSettings: The arguments, checked once.

Note:
    Each host is read on a CONNECTED UDP socket. The operating system then
    drops datagrams from any other sender, and reports an ICMP port
    unreachable from the host, which is how a host that is up with no agent
    (REFUSED) is told apart from silence.

    One deadline per host covers name resolution and the whole exchange,
    including the re-asks below, so ``timeout`` bounds how long any host takes.

    SNMPv1 fails a whole GET when one OID is unknown (``noSuchName`` with its
    index). The read then asks again without that OID and reports it as None,
    so an agent lacking sysObjectID still yields its uptime.

    The community string is a password in SNMPv1 and v2c: no error text built
    here contains it.

"""

from __future__ import annotations

import asyncio
import enum
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .api import require_host_names
from .deadline import failure_reason, within
from .errors import IPScoutError, refused_arguments
from .models import MAX_UPTIME_SECONDS, AddressFamily, Port, SnmpState, SnmpSystem, SnmpVersion, Timeout
from .pool import Concurrency, gather_bounded
from .resolve import resolve_one
from .snmpber import (
    EXCEPTION_TAGS,
    GET_RESPONSE,
    OBJECT_IDENTIFIER,
    OCTET_STRING,
    TIMETICKS,
    BerError,
    SnmpMessage,
    VarBind,
    decode_oid,
    encode_get_request,
    parse_message,
)
from .sockerr import is_refusal

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

__all__ = ["DEFAULT_COMMUNITY", "DEFAULT_CONCURRENCY", "DEFAULT_PORT", "DEFAULT_TIMEOUT", "SnmpSettings", "aread_snmp_system", "read_snmp_system"]

#: The standard SNMP agent port.
DEFAULT_PORT = 161
#: Seconds per host. The same as the banner grab's: a slow embedded agent with
#: many requests in flight answers late rather than not at all.
DEFAULT_TIMEOUT = 3.0
#: Hosts read at once.
DEFAULT_CONCURRENCY = 64
#: The factory read community of most agents.
DEFAULT_COMMUNITY = "public"

#: Request ids are drawn from 1 to this: positive, inside the signed 32-bit INTEGER every agent parses.
_MAX_REQUEST_ID = 2**31 - 1
#: TimeTicks per second (RFC 2578).
_TICKS_PER_SECOND = 100
#: A TimeTicks body is at most 5 octets: 4 for the value plus a leading 0 when its top bit is set.
_MAX_TIMETICKS_OCTETS = 5
#: The octets of the 32-bit value itself. Some embedded agents send exactly these with the top
#: bit set and no leading 0; X.690 reads that as negative, which TimeTicks never is, so a body
#: of this length is read unsigned, as net-snmp reads it.
_TIMETICKS_VALUE_OCTETS = 4
#: SNMPv1 error status for an OID the agent does not know (RFC 1157).
_NO_SUCH_NAME = 2
#: Windows ERROR_PORT_UNREACHABLE: how its default (proactor) event loop hands a datagram
#: endpoint the ICMP port unreachable, as a bare OSError rather than a ConnectionError.
_ERROR_PORT_UNREACHABLE = 1234
#: Error status names, RFC 1157 and RFC 3416, for error text a person can read.
_ERROR_STATUS: Final = {
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    6: "noAccess",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "inconsistentValue",
    13: "resourceUnavailable",
    14: "commitFailed",
    15: "undoFailed",
    16: "authorizationError",
    17: "notWritable",
    18: "inconsistentName",
}


class _SystemValue(str, enum.Enum):
    """The four system-group values, by OID, in the order they are asked for."""

    DESCRIPTION = "1.3.6.1.2.1.1.1.0"
    OBJECT_ID = "1.3.6.1.2.1.1.2.0"
    UPTIME = "1.3.6.1.2.1.1.3.0"
    NAME = "1.3.6.1.2.1.1.5.0"


#: The BER type each value must arrive as.
_TAG: Final = {
    _SystemValue.DESCRIPTION: OCTET_STRING,
    _SystemValue.OBJECT_ID: OBJECT_IDENTIFIER,
    _SystemValue.UPTIME: TIMETICKS,
    _SystemValue.NAME: OCTET_STRING,
}


class SnmpSettings(BaseModel):
    """The arguments of one SNMP system read, checked once so every host is read the same way.

    Strict: ``True`` is not a port, ``"3"`` is not a timeout and ``"v1"`` is
    not a version, so a caller's mistake is refused rather than coerced.

    Examples:
        >>> SnmpSettings().port
        161
        >>> SnmpSettings(community="")
        Traceback (most recent call last):
        ...
        pydantic_core._pydantic_core.ValidationError: ...

    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    #: The SNMP version every request is sent in.
    version: SnmpVersion = SnmpVersion.V1
    #: The read community. Bounded so a mistake cannot build an oversized datagram.
    community: str = Field(default=DEFAULT_COMMUNITY, min_length=1, max_length=255)
    #: The agent's UDP port on every host.
    port: Port = DEFAULT_PORT
    #: Seconds per host for resolving and the whole exchange together.
    timeout: Timeout = DEFAULT_TIMEOUT
    #: Hosts read at once, under the pool's one concurrency rule.
    concurrency: Concurrency = DEFAULT_CONCURRENCY
    #: Use only IPv4 or IPv6 addresses for every host.
    family: AddressFamily | None = None


class _BadReplyError(Exception):
    """A reply to our request that is not a usable answer; its message says why."""


@dataclass(frozen=True)
class _Heard:
    """What came back for one request before the deadline. At most one field is set."""

    reply: SnmpMessage | None = None
    refused: bool = False
    #: The network's reason when it reported the host unreachable.
    unreachable: str | None = None
    #: The last reason a datagram was set aside, when one was.
    discarded: str | None = None


class _Inbox(asyncio.DatagramProtocol):
    """Queues every datagram and every socket error, in the order they arrive."""

    def __init__(self) -> None:
        self.arrivals: asyncio.Queue[bytes | OSError] = asyncio.Queue()

    def datagram_received(self, data: bytes, addr: object) -> None:
        del addr  # the socket is connected: only the target's datagrams arrive
        self.arrivals.put_nowait(data)

    def error_received(self, exc: Exception) -> None:
        if isinstance(exc, OSError):
            self.arrivals.put_nowait(exc)


def _is_port_unreachable(exc: OSError) -> bool:
    """Return whether a datagram socket error is the host's ICMP port unreachable.

    The one ICMP message arrives in three spellings, measured: Linux reports a
    refusal (ECONNREFUSED); on Windows the proactor event loop reports
    ERROR_PORT_UNREACHABLE and the selector loop a connection reset
    (WSAECONNRESET), which on a datagram socket means exactly that ICMP
    message (Microsoft's ``recvfrom`` reference; an expired TTL is
    WSAENETRESET instead, a different exception this does not match). Kept
    here rather than in ``is_refusal`` because a reset on a TCP stream means
    something different.

    Examples:
        >>> _is_port_unreachable(ConnectionRefusedError())
        True
        >>> _is_port_unreachable(OSError(113, "No route to host"))
        False

    """

    return is_refusal(exc) or isinstance(exc, ConnectionResetError) or getattr(exc, "winerror", None) == _ERROR_PORT_UNREACHABLE


async def _listen(inbox: _Inbox, request_id: int, deadline: float) -> _Heard:
    """Wait for the reply to ``request_id``, setting aside anything else, until the deadline."""

    discarded: str | None = None
    while True:
        try:
            arrival = await within(deadline, inbox.arrivals.get())
        except TimeoutError:
            return _Heard(discarded=discarded)
        if isinstance(arrival, OSError):
            if _is_port_unreachable(arrival):
                return _Heard(refused=True)
            return _Heard(unreachable=failure_reason(arrival))
        try:
            reply = parse_message(arrival)
        except BerError as exc:
            discarded = f"a malformed reply ({exc})"
            continue
        if reply.request_id != request_id:
            discarded = "a reply to another request"
            continue
        return _Heard(reply=reply)


def _ticks(body: bytes) -> float:
    if not 1 <= len(body) <= _MAX_TIMETICKS_OCTETS:
        msg = f"uptime: TimeTicks of {len(body)} octets"
        raise _BadReplyError(msg)
    signed = len(body) != _TIMETICKS_VALUE_OCTETS
    seconds = int.from_bytes(body, "big", signed=signed) / _TICKS_PER_SECOND
    if not 0 <= seconds <= MAX_UPTIME_SECONDS:
        msg = "uptime: TimeTicks outside 0 to 2**32-1"
        raise _BadReplyError(msg)
    return seconds


def _body(kind: _SystemValue, bindings: Mapping[_SystemValue, VarBind], version: SnmpVersion) -> bytes | None:
    """Return one value's octets once its tag is checked, or None when it was not read or a v2c agent does not have it."""

    binding = bindings.get(kind)
    if binding is None or (binding.tag in EXCEPTION_TAGS and version is SnmpVersion.V2C):
        return None
    if binding.tag != _TAG[kind]:
        msg = f"{kind.name.lower()}: arrived as tag 0x{binding.tag:02x}, expected 0x{_TAG[kind]:02x}"
        raise _BadReplyError(msg)
    return binding.value


def _text(body: bytes | None) -> str | None:
    return None if body is None else body.decode("utf-8", errors="replace")


def _object_id(body: bytes | None) -> str | None:
    if body is None:
        return None
    try:
        return decode_oid(body)
    except BerError as exc:
        msg = f"object_id: {exc}"
        raise _BadReplyError(msg) from exc


def _check(reply: SnmpMessage, wanted: tuple[_SystemValue, ...], version: SnmpVersion) -> None:
    """Refuse a reply that carries our request id but is not an answer to our request."""

    if reply.pdu_tag != GET_RESPONSE:
        msg = f"the reply is not a response (PDU tag 0x{reply.pdu_tag:02x})"
        raise _BadReplyError(msg)
    if reply.version != version.wire_number:
        msg = f"the reply is in protocol version {reply.version}, not {version.wire_number}"
        raise _BadReplyError(msg)
    if reply.error_status != 0:
        name = _ERROR_STATUS.get(reply.error_status, str(reply.error_status))
        msg = f"the agent answered error status {name} (index {reply.error_index})"
        raise _BadReplyError(msg)
    if [binding.oid for binding in reply.bindings] != [kind.value for kind in wanted]:
        msg = "the reply names other values than were asked for"
        raise _BadReplyError(msg)


def _answered(host: str, reply: SnmpMessage, wanted: tuple[_SystemValue, ...], version: SnmpVersion) -> SnmpSystem:
    try:
        _check(reply, wanted, version)
        bindings = dict(zip(wanted, reply.bindings, strict=True))
        # Decoded in the order they are asked for, so a reply with two bad
        # values is refused naming the first one.
        description = _text(_body(_SystemValue.DESCRIPTION, bindings, version))
        object_id = _object_id(_body(_SystemValue.OBJECT_ID, bindings, version))
        uptime = _body(_SystemValue.UPTIME, bindings, version)
        uptime_seconds = None if uptime is None else _ticks(uptime)
        name = _text(_body(_SystemValue.NAME, bindings, version))
    except _BadReplyError as exc:
        return SnmpSystem(host=host, state=SnmpState.ERROR, error=str(exc))
    return SnmpSystem(host=host, state=SnmpState.ANSWERED, description=description, object_id=object_id, uptime_seconds=uptime_seconds, name=name)


def _unanswered(host: str, heard: _Heard, settings: SnmpSettings) -> SnmpSystem:
    if heard.refused:
        return SnmpSystem(host=host, state=SnmpState.REFUSED)
    if heard.unreachable is not None:
        return SnmpSystem(host=host, state=SnmpState.UNREACHABLE, error=heard.unreachable)
    if heard.discarded is not None:
        error = f"no valid reply within {settings.timeout:g} s; the last datagram was {heard.discarded}"
        return SnmpSystem(host=host, state=SnmpState.ERROR, error=error)
    return SnmpSystem(host=host, state=SnmpState.SILENT)


def _unknown_in_v1(reply: SnmpMessage, wanted: tuple[_SystemValue, ...], version: SnmpVersion) -> _SystemValue | None:
    """Return the value an SNMPv1 ``noSuchName`` names, when the reply is exactly that."""

    if version is not SnmpVersion.V1 or reply.error_status != _NO_SUCH_NAME or reply.pdu_tag != GET_RESPONSE:
        return None
    if not 1 <= reply.error_index <= len(wanted):
        return None
    return wanted[reply.error_index - 1]


async def _converse(host: str, transport: asyncio.DatagramTransport, inbox: _Inbox, settings: SnmpSettings, deadline: float) -> SnmpSystem:
    """Ask for the system group, dropping each value an SNMPv1 agent says it lacks."""

    wanted = tuple(_SystemValue)
    community = settings.community.encode("utf-8")
    while wanted:
        request_id = secrets.randbelow(_MAX_REQUEST_ID) + 1
        oids = [kind.value for kind in wanted]
        transport.sendto(encode_get_request(version=settings.version.wire_number, community=community, request_id=request_id, oids=oids))
        heard = await _listen(inbox, request_id, deadline)
        if heard.reply is None:
            return _unanswered(host, heard, settings)
        unknown = _unknown_in_v1(heard.reply, wanted, settings.version)
        if unknown is None:
            return _answered(host, heard.reply, wanted, settings.version)
        wanted = tuple(kind for kind in wanted if kind is not unknown)
    return SnmpSystem(host=host, state=SnmpState.ANSWERED)


async def _read_one(host: str, settings: SnmpSettings) -> SnmpSystem:
    """Read one host. Every failure is a result, never a raise."""

    loop = asyncio.get_running_loop()
    deadline = loop.time() + settings.timeout

    def unreachable(reason: str) -> SnmpSystem:
        return SnmpSystem(host=host, state=SnmpState.UNREACHABLE, error=reason)

    try:
        # In a thread: a slow DNS answer for one name must not stall every other host.
        target = await within(deadline, asyncio.to_thread(resolve_one, host, family=settings.family))
        endpoint = loop.create_datagram_endpoint(_Inbox, remote_addr=(target.address, settings.port), family=target.family.socket_family)
        transport, inbox = await within(deadline, endpoint)
    except IPScoutError as exc:
        return unreachable(failure_reason(exc))
    except TimeoutError:
        return unreachable(f"no address and socket within {settings.timeout:g} s")
    except OSError as exc:
        return unreachable(failure_reason(exc))
    try:
        return await _converse(host, transport, inbox, settings, deadline)
    finally:
        transport.close()


async def aread_snmp_system(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    hosts: Iterable[str],
    *,
    version: SnmpVersion = SnmpVersion.V1,
    community: str = DEFAULT_COMMUNITY,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    family: AddressFamily | None = None,
) -> dict[str, SnmpSystem]:
    """Read the SNMP system group (uptime, name, description, object id) of many hosts at once.

    Args:
        hosts: Hostnames or address literals; a link-local IPv6 address needs
            its ``%zone``. Any collection or iterator of ``str``, never one
            bare string. Duplicates are collapsed.
        version: ``SnmpVersion.V1`` or ``SnmpVersion.V2C``. An agent that
            speaks only the other one stays silent.
        community: The read community. Never echoed in an error.
        port: The agent's UDP port.
        timeout: Seconds per host for resolving and the whole exchange.
        concurrency: Hosts read at once.
        family: Use only IPv4 or IPv6 addresses for every host.

    Returns:
        A mapping of host, exactly as given, to its :class:`SnmpSystem`, in
        the order the hosts were given. Every host has an entry: silence, a
        refusal and a name that does not resolve are results, never exceptions.

    Raises:
        ValueError: ``port`` is outside 1-65535, ``timeout`` is not above 0
            and at most ``MAX_TIMEOUT``, ``concurrency`` is below 1, ``version``
            is not an ``SnmpVersion`` member, or ``community`` is empty or
            longer than 255 characters. One message names every bad argument
            as ``<argument>: <reason>``, raised before anything is sent.
            ``hosts`` being one bare string or holding a non-``str`` entry is
            refused the same way, checked after the other arguments so a bad
            one is reported before any host is taken from ``hosts``.

    Examples:
        >>> import asyncio
        >>> asyncio.run(aread_snmp_system(["nothing.invalid"]))["nothing.invalid"].state
        <SnmpState.UNREACHABLE: 'unreachable'>

    """

    try:
        settings = SnmpSettings(version=version, community=community, port=port, timeout=timeout, concurrency=concurrency, family=family)
    except ValidationError as refused:
        raise refused_arguments("SNMP read", refused) from refused
    unique = require_host_names(hosts, operation="SNMP read", argument="hosts")

    async def one(host: str) -> tuple[str, SnmpSystem]:
        # Paired with its host: the pool completes out of order.
        return host, await _read_one(host, settings)

    completed = dict(await gather_bounded(unique, one, settings.concurrency))
    return {host: completed[host] for host in unique}


def read_snmp_system(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    hosts: Iterable[str],
    *,
    version: SnmpVersion = SnmpVersion.V1,
    community: str = DEFAULT_COMMUNITY,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    family: AddressFamily | None = None,
) -> dict[str, SnmpSystem]:
    """Read the SNMP system group of many hosts, from synchronous code.

    Takes the same arguments as :func:`aread_snmp_system`.

    Returns:
        A mapping of host to :class:`SnmpSystem`, in the order the hosts were given.

    Raises:
        ValueError: As :func:`aread_snmp_system`.
        RuntimeError: Called from inside a running event loop, where it would
            deadlock. Await :func:`aread_snmp_system` there instead.

    Examples:
        >>> read_snmp_system(["nothing.invalid"])["nothing.invalid"].state
        <SnmpState.UNREACHABLE: 'unreachable'>

    """

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        msg = "read_snmp_system() cannot run inside an event loop; await aread_snmp_system() instead"
        raise RuntimeError(msg)

    return asyncio.run(aread_snmp_system(hosts, version=version, community=community, port=port, timeout=timeout, concurrency=concurrency, family=family))
