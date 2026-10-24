"""Each probing default has one value, and every signature that offers it agrees with that one constant.

A default restated as a literal in a second place drifts the first time
someone changes only one of them, and nothing fails: the two callables simply
start disagreeing about what "the default" is. These tests pin the value
itself, so a change is deliberate, and that every signature offering the knob
agrees with the one constant, so changing the constant moves all of them.
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING

import pytest

import ipscout
from ipscout import factory
from ipscout.packet import DEFAULT_PAYLOAD_SIZE
from ipscout.service import DEFAULT_INTERVAL, DEFAULT_TIMEOUT, DEFAULT_TIMES, PingRequest
from ipscout.transport_tcp import DEFAULT_TCP_PORT, AsyncTcpEchoTransport, TcpEchoTransport
from ipscout.transport_windows import AsyncWindowsEchoTransport, WindowsEchoTransport

if TYPE_CHECKING:
    from collections.abc import Callable

pytestmark = pytest.mark.os_agnostic


def test_the_default_values_are_the_documented_ones() -> None:
    # Four echoes, the size the system ping sends, HTTPS, two seconds, a fifth of one.
    assert (DEFAULT_TIMES, DEFAULT_PAYLOAD_SIZE, DEFAULT_TCP_PORT, DEFAULT_TIMEOUT, DEFAULT_INTERVAL) == (4, 56, 443, 2.0, 0.2)


def _default(function: Callable[..., object], name: str) -> object:
    return inspect.signature(function).parameters[name].default


_PAYLOAD_SIZE_OFFERED_BY = [ipscout.ping, ipscout.aping, ipscout.ping_many, ipscout.aping_many, factory.make_transport, factory.make_async_transport]
_TCP_PORT_OFFERED_BY = [*_PAYLOAD_SIZE_OFFERED_BY, ipscout.is_reachable, ipscout.ais_reachable]
_TIMEOUT_OFFERED_BY = [ipscout.ping, ipscout.aping, ipscout.ping_many, ipscout.aping_many, ipscout.is_reachable, ipscout.ais_reachable]
_INTERVAL_OFFERED_BY = [ipscout.ping, ipscout.aping, ipscout.ping_many, ipscout.aping_many]
_TIMES_OFFERED_BY = _INTERVAL_OFFERED_BY


@pytest.mark.parametrize("function", _PAYLOAD_SIZE_OFFERED_BY, ids=lambda f: f.__name__)
def test_every_payload_size_default_is_the_packet_constant(function: Callable[..., object]) -> None:
    assert _default(function, "payload_size") == DEFAULT_PAYLOAD_SIZE


@pytest.mark.parametrize("function", _TCP_PORT_OFFERED_BY, ids=lambda f: f.__name__)
def test_every_tcp_port_default_is_the_transport_constant(function: Callable[..., object]) -> None:
    assert _default(function, "tcp_port") == DEFAULT_TCP_PORT


@pytest.mark.parametrize("transport", [TcpEchoTransport, AsyncTcpEchoTransport], ids=lambda t: t.__name__)
def test_the_tcp_transports_default_to_the_same_port(transport: Callable[..., object]) -> None:
    assert _default(transport, "port") == DEFAULT_TCP_PORT


@pytest.mark.parametrize("transport", [WindowsEchoTransport, AsyncWindowsEchoTransport], ids=lambda t: t.__name__)
def test_the_windows_transports_default_to_the_same_payload_size(transport: Callable[..., object]) -> None:
    # Read from the signature, so this holds on every platform, not only where
    # the transport can be constructed.
    assert _default(transport, "payload_size") == DEFAULT_PAYLOAD_SIZE


@pytest.mark.parametrize("function", _TIMEOUT_OFFERED_BY, ids=lambda f: f.__name__)
def test_every_timeout_default_is_the_service_constant(function: Callable[..., object]) -> None:
    assert _default(function, "timeout") == DEFAULT_TIMEOUT


@pytest.mark.parametrize("function", _TIMES_OFFERED_BY, ids=lambda f: f.__name__)
def test_every_times_default_is_the_service_constant(function: Callable[..., object]) -> None:
    assert _default(function, "times") == DEFAULT_TIMES


@pytest.mark.parametrize("function", _INTERVAL_OFFERED_BY, ids=lambda f: f.__name__)
def test_every_interval_default_is_the_service_constant(function: Callable[..., object]) -> None:
    assert _default(function, "interval") == DEFAULT_INTERVAL


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("times", DEFAULT_TIMES),
        ("timeout", DEFAULT_TIMEOUT),
        ("interval", DEFAULT_INTERVAL),
        ("payload_size", DEFAULT_PAYLOAD_SIZE),
        ("tcp_port", DEFAULT_TCP_PORT),
    ],
)
def test_the_request_model_defaults_to_the_same_constants(field: str, expected: object) -> None:
    assert PingRequest.model_fields[field].default == expected
