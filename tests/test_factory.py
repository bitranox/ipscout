"""Which transport the factory builds for a probe method. Real objects, no mocks."""

from __future__ import annotations

import asyncio
import inspect
from typing import TYPE_CHECKING

import pytest

from ipscout.factory import make_async_transport, make_transport
from ipscout.models import AddressFamily, ProbeMethod
from ipscout.transport_tcp import AsyncTcpEchoTransport, TcpEchoTransport

if TYPE_CHECKING:
    from collections.abc import Callable

pytestmark = pytest.mark.os_agnostic


def test_a_tcp_method_builds_the_tcp_transport() -> None:
    with make_transport("127.0.0.1", AddressFamily.IPV4, method=ProbeMethod.TCP) as transport:
        assert isinstance(transport, TcpEchoTransport)


def test_a_tcp_method_builds_the_async_tcp_transport() -> None:
    async def build() -> object:
        transport = make_async_transport("127.0.0.1", AddressFamily.IPV4, method=ProbeMethod.TCP)
        async with transport:
            return transport

    assert isinstance(asyncio.run(build()), AsyncTcpEchoTransport)


@pytest.mark.parametrize("factory", [make_transport, make_async_transport])
def test_the_factories_choose_the_method_by_enum_with_icmp_as_the_default(factory: Callable[..., object]) -> None:
    # Pins the 2.0 signature: the method is the ProbeMethod enum, and the old
    # use_tcp flag is gone rather than kept beside it as a second spelling.
    parameters = inspect.signature(factory).parameters
    assert "use_tcp" not in parameters
    assert parameters["method"].default is ProbeMethod.ICMP
    assert parameters["method"].kind is inspect.Parameter.KEYWORD_ONLY
