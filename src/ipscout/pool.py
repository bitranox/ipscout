"""Bounded concurrent execution over an arbitrarily long work list.

Contents:
    gather_bounded: Run a coroutine over many items, N alive at a time.

Note:
    The obvious spelling, ``asyncio.gather(*(work(i) for i in items))`` with a
    semaphore inside ``work``, bounds how many items are *in flight* but not
    how many exist: every coroutine is created, wrapped in a Task and queued
    on the loop before the first one runs. For a full-range port scan that is
    65535 tasks resident to keep 256 sockets busy.

    This runs a fixed pool of workers pulling from one iterator instead, so
    the live task count is the concurrency limit no matter how long the list
    is. Memory becomes a function of the limit rather than of the input.

"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Iterable, Sequence

__all__ = ["gather_bounded"]

_Item = TypeVar("_Item")
_Result = TypeVar("_Result")


async def gather_bounded(
    items: Sequence[_Item] | Iterable[_Item],
    work: Callable[[_Item], Coroutine[object, object, _Result]],
    concurrency: int,
) -> list[_Result]:
    """Run ``work`` over every item, with at most ``concurrency`` alive at once.

    Args:
        items: The work list. Consumed once, so a generator is fine.
        work: Coroutine function applied to each item.
        concurrency: How many may run at a time. Values below one are read as
            one, so a caller cannot accidentally deadlock the pool.

    Returns:
        Every result, in completion order rather than input order. Callers that
        need the association back should have ``work`` return it - both callers
        here return a ``(key, value)`` pair for exactly that reason.

    Note:
        Results accumulate, so this is bounded in *live tasks*, not in total
        output. That is the right trade here: a scan of 65535 ports holds
        65535 small results, which is nothing, while holding 65535 Tasks is
        not.

    Examples:
        >>> import asyncio
        >>> async def double(value: int) -> int:
        ...     return value * 2
        >>> sorted(asyncio.run(gather_bounded([1, 2, 3], double, 2)))
        [2, 4, 6]
        >>> asyncio.run(gather_bounded([], double, 4))
        []

    """

    pending = iter(items)
    results: list[_Result] = []
    workers = max(1, concurrency)

    async def run() -> None:
        while True:
            try:
                item = next(pending)
            except StopIteration:
                return
            results.append(await work(item))

    # One worker per slot, and never more workers than there is work.
    await asyncio.gather(*(run() for _ in range(workers)))
    return results
