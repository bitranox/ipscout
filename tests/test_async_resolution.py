"""Async entry points resolve names off the event-loop thread.

``getaddrinfo`` blocks for as long as the name server takes, seconds for a
slow or unreachable one. Called on the loop thread it stalls every other task
in the loop, so in ``aping_many`` one slow name holds up the whole sweep. The
resolver is the stdlib's, an external edge, so it is replaced at
``socket.getaddrinfo`` with a fake that records which thread asked.
"""

from __future__ import annotations

import asyncio
import socket
import threading
from typing import TYPE_CHECKING

import pytest

from ipscout import ais_reachable, aping, aping_many, atraceroute
from ipscout.errors import IPScoutResolutionError

if TYPE_CHECKING:
    from collections.abc import Coroutine

pytestmark = pytest.mark.os_agnostic

_SLOW_NAME = "slow-resolver.invalid"


class ResolverSpy:
    """Stands in for ``socket.getaddrinfo`` and records the calling thread.

    The name under test fails to resolve, so no probe is ever sent and the
    tests need no network. Every other name goes to the real resolver.
    """

    def __init__(self) -> None:
        self._real = socket.getaddrinfo
        self.threads: list[int] = []

    def __call__(self, host: object, *args: object, **kwargs: object) -> object:
        if host != _SLOW_NAME:
            return self._real(host, *args, **kwargs)  # type: ignore[arg-type]
        self.threads.append(threading.get_ident())
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> ResolverSpy:
    recorder = ResolverSpy()
    monkeypatch.setattr(socket, "getaddrinfo", recorder)
    return recorder


def _run_recording_loop_thread(coro: Coroutine[object, object, object]) -> tuple[object, int]:
    """Run a coroutine and return its result plus the loop thread's id."""

    async def wrapper() -> tuple[object, int]:
        return await coro, threading.get_ident()

    return asyncio.run(wrapper())


def test_aping_resolves_off_the_event_loop_thread(spy: ResolverSpy) -> None:
    result, loop_thread = _run_recording_loop_thread(aping(_SLOW_NAME, 1, raise_on_error=False))

    assert spy.threads, "the resolver was never asked, so the test proves nothing"
    assert loop_thread not in spy.threads
    assert result.error is not None  # type: ignore[attr-defined]


def test_aping_still_raises_an_unresolvable_name(spy: ResolverSpy) -> None:
    with pytest.raises(IPScoutResolutionError):
        asyncio.run(aping(_SLOW_NAME, 1))

    assert spy.threads


def test_aping_many_resolves_every_name_off_the_event_loop_thread(spy: ResolverSpy) -> None:
    results, loop_thread = _run_recording_loop_thread(aping_many([_SLOW_NAME], times=1))

    assert spy.threads
    assert loop_thread not in spy.threads
    assert results[_SLOW_NAME].error is not None  # type: ignore[index]


def test_ais_reachable_resolves_off_the_event_loop_thread_in_both_tries(spy: ResolverSpy) -> None:
    reachable, loop_thread = _run_recording_loop_thread(ais_reachable(_SLOW_NAME))

    # Two lookups: the ICMP try, then the TCP fallback. One recorded call
    # would mean the fallback was never reached.
    assert len(spy.threads) == 2
    assert loop_thread not in spy.threads
    assert reachable is False


def test_atraceroute_resolves_off_the_event_loop_thread(spy: ResolverSpy) -> None:
    loop_threads: list[int] = []

    async def trace() -> None:
        loop_threads.append(threading.get_ident())
        await atraceroute(_SLOW_NAME, max_hops=1)

    with pytest.raises(IPScoutResolutionError):
        asyncio.run(trace())

    assert spy.threads
    assert loop_threads[0] not in spy.threads
