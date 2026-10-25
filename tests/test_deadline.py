"""The shared deadline helpers: one deadline across several awaits, and a failure's reason."""

from __future__ import annotations

import asyncio

import pytest

from ipscout.deadline import failure_reason, within
from ipscout.errors import IPScoutError

pytestmark = pytest.mark.os_agnostic


def test_an_await_that_finishes_in_time_returns_its_value() -> None:
    async def run() -> int:
        deadline = asyncio.get_running_loop().time() + 5.0
        return await within(deadline, asyncio.sleep(0, result=7))

    assert asyncio.run(run()) == 7


def test_an_await_past_the_deadline_raises_the_builtin_timeout() -> None:
    async def run() -> None:
        deadline = asyncio.get_running_loop().time() + 0.05
        await within(deadline, asyncio.sleep(5))

    with pytest.raises(TimeoutError):
        asyncio.run(run())


def test_a_deadline_already_passed_raises_without_awaiting() -> None:
    started: list[bool] = []

    async def never() -> None:
        started.append(True)

    async def run() -> None:
        deadline = asyncio.get_running_loop().time() - 1.0
        await within(deadline, never())

    with pytest.raises(TimeoutError):
        asyncio.run(run())
    assert started == []


def test_a_reason_is_the_message_or_else_the_class_name() -> None:
    assert failure_reason(OSError("Network is unreachable")) == "Network is unreachable"
    assert failure_reason(IPScoutError()) == "IPScoutError"
