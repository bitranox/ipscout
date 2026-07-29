"""Turns result records into JSON-ready dictionaries.

Exists because ``dataclasses.asdict`` is wrong for these types in two separate
ways, both verified against the real models rather than assumed:

    **It drops every computed field.** ``ResponseObject`` exposes
    ``str_result``, ``n_packets_lost``, ``packets_lost_percentage``,
    ``time_min_ms``, ``time_avg_ms``, ``time_max_ms`` and ``jitter_ms`` as
    properties, so none of them appear in ``asdict`` output. A payload built
    that way would omit precisely the values a consumer most wants - the
    average round trip and the loss percentage - while looking complete.

    **Its output is not serialisable.** ``json.dumps(asdict(result))`` raises
    ``Object of type AddressFamily is not JSON serializable``, because the
    family and method fields are ``enum.Enum``.

Contents:
    to_json_dict: Convert any result record to a JSON-ready dictionary.
    dumps: Serialise a payload with the enum encoder applied.

Note:
    The conversion is explicit per type rather than generic reflection, so
    adding a field to a model without deciding how it should appear in the
    public JSON is a visible omission rather than a silent one.

"""

from __future__ import annotations

import dataclasses
import enum
import json
from typing import TYPE_CHECKING, Any, cast

from .models import Interface, MacLookup, ResponseObject, SubnetInfo, TraceHop

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

__all__ = ["dumps", "to_json_dict"]


def _plain(value: Any) -> Any:
    """Return a value with enums flattened and tuples turned into lists."""

    if isinstance(value, enum.Enum):
        return value.value
    # isinstance narrows to the bare container type, whose element type is then
    # unknown to a strict checker. The casts say what these actually hold; they
    # are type-only and cost nothing at runtime.
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in cast("Iterable[Any]", value)]
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in cast("dict[Any, Any]", value).items()}
    return value


def _response_to_dict(result: ResponseObject) -> dict[str, Any]:
    """Return a ping result with its computed statistics included.

    The computed fields are listed explicitly because they are properties and
    would otherwise be absent - see this module's docstring.
    """

    return {
        "target": result.target,
        "reached": result.reached,
        "ip": result.ip,
        "number_of_pings": result.number_of_pings,
        "packets_sent": result.packets_sent,
        "packets_received": result.packets_received,
        "n_packets_lost": result.n_packets_lost,
        "packets_lost_percentage": result.packets_lost_percentage,
        "time_min_ms": result.time_min_ms,
        "time_avg_ms": result.time_avg_ms,
        "time_max_ms": result.time_max_ms,
        "jitter_ms": result.jitter_ms,
        "rtts_ms": list(result.rtts_ms),
        "family": result.family.value,
        "method": result.method.value,
        "error": result.error,
        "str_result": result.str_result,
    }


def _hop_to_dict(hop: TraceHop) -> dict[str, Any]:
    """Return one traceroute hop."""

    return {
        "ttl": hop.ttl,
        "address": hop.address,
        "rtt_ms": hop.rtt_ms,
        "reached": hop.reached,
        "hostname": hop.hostname,
    }


def _interface_to_dict(interface: Interface) -> dict[str, Any]:
    """Return one local interface, with addresses as objects rather than pairs.

    A ``(address, prefix)`` tuple would serialise as a two-element array, which
    a reader has to know the ordering of. Naming the fields removes that.
    """

    return {
        "name": interface.name,
        "ipv4": [{"address": address, "prefix_len": prefix} for address, prefix in interface.ipv4],
        "ipv6": [{"address": address, "prefix_len": prefix} for address, prefix in interface.ipv6],
        "mac": interface.mac,
        "is_up": interface.is_up,
        "is_loopback": interface.is_loopback,
        "mtu": interface.mtu,
    }


def _mac_to_dict(lookup: MacLookup) -> dict[str, Any]:
    """Return a MAC answer with the scope that makes it interpretable."""

    return {
        "ip": lookup.ip,
        "mac": lookup.mac,
        "scope": lookup.scope.value,
        "via_ip": lookup.via_ip,
        "interface": lookup.interface,
    }


def _subnet_to_dict(subnet: SubnetInfo) -> dict[str, Any]:
    """Return one subnet record."""

    return {
        "interface": subnet.interface,
        "address": subnet.address,
        "prefix_len": subnet.prefix_len,
        "network": subnet.network,
        "family": subnet.family.value,
        "broadcast": subnet.broadcast,
        "gateway": subnet.gateway,
        "dns_servers": list(subnet.dns_servers),
        "domain": subnet.domain,
        "dhcp_server": subnet.dhcp_server,
        "lease_obtained": subnet.lease_obtained,
        "lease_expires": subnet.lease_expires,
        "mtu": subnet.mtu,
    }


#: Explicit per-type conversion. Reflection would silently accept a model whose
#: new field nobody decided how to expose; a missing entry here is visible.
_CONVERTERS: dict[type[Any], Callable[[Any], dict[str, Any]]] = {
    ResponseObject: _response_to_dict,
    TraceHop: _hop_to_dict,
    Interface: _interface_to_dict,
    MacLookup: _mac_to_dict,
    SubnetInfo: _subnet_to_dict,
}


def to_json_dict(value: Any) -> Any:
    """Return ``value`` as something ``json.dumps`` accepts.

    Args:
        value: A result record, or any container of them.

    Returns:
        The same data as dictionaries, lists and scalars, with computed fields
        included and enums flattened to their values.

    Examples:
        >>> from ipscout.models import ResponseObject
        >>> payload = to_json_dict(ResponseObject(target="t", ip="10.0.0.1",
        ...                                       number_of_pings=1, rtts_ms=(2.0,),
        ...                                       packets_sent=1, packets_received=1,
        ...                                       reached=True))
        >>> payload["family"], payload["method"]
        ('ipv4', 'icmp')

        The computed statistics are present, which ``asdict`` would have dropped:

        >>> payload["time_avg_ms"], payload["packets_lost_percentage"]
        (2.0, 0)
        >>> "str_result" in payload
        True

        Containers are converted through:

        >>> to_json_dict({"a": [1, 2]})
        {'a': [1, 2]}

    """

    # type(value) on an Any is type[Unknown] to a strict checker.
    converter = _CONVERTERS.get(cast("type[Any]", type(value)))
    if converter is not None:
        return converter(value)
    if isinstance(value, dict):
        return {str(key): to_json_dict(item) for key, item in cast("dict[Any, Any]", value).items()}
    if isinstance(value, (list, tuple, set)):
        return [to_json_dict(item) for item in cast("Iterable[Any]", value)]
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _plain(dataclasses.asdict(value))
    return _plain(value)


def dumps(payload: Any, *, indent: int | None = 2) -> str:
    """Return ``payload`` as JSON text.

    Args:
        payload: Anything :func:`to_json_dict` can convert.
        indent: Pretty-printing indent, or ``None`` for one compact line.

    Returns:
        JSON text.

    Examples:
        >>> dumps({"ok": True}, indent=None)
        '{"ok": true}'

    """

    return json.dumps(to_json_dict(payload), indent=indent, default=_plain)
