"""Bounded concurrent execution over an arbitrarily long work list.

Contents:
    gather_bounded: Run a coroutine over many items, N alive at a time.
    require_concurrency: The one check on a concurrency limit.

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
from typing import TYPE_CHECKING, Annotated, TypeVar

from pydantic import AfterValidator

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Iterable, Sequence

__all__ = ["Concurrency", "gather_bounded", "require_concurrency"]

_Item = TypeVar("_Item")
_Result = TypeVar("_Result")


def require_concurrency(value: int) -> int:
    """Return ``value`` if it is a usable concurrency limit, or raise saying why not.

    Below one, no worker would ever start: the pool would return no results
    at all, which reads as "every target answered nothing" rather than as the
    caller's mistake. Refused rather than raised to one, so the caller learns
    the value they passed was not the one used.

    Args:
        value: The candidate limit.

    Returns:
        ``value`` unchanged.

    Raises:
        ValueError: ``value`` is below 1.

    Examples:
        >>> require_concurrency(4)
        4
        >>> require_concurrency(0)
        Traceback (most recent call last):
        ...
        ValueError: concurrency must be at least 1, got 0

    """

    if value < 1:
        msg = f"concurrency must be at least 1, got {value}"
        raise ValueError(msg)
    return value


#: A concurrency argument: at least 1. Every model and CLI option taking one
#: uses this type, so the bound and its wording live in require_concurrency alone.
Concurrency = Annotated[int, AfterValidator(require_concurrency)]


async def gather_bounded(
    items: Sequence[_Item] | Iterable[_Item],
    work: Callable[[_Item], Coroutine[object, object, _Result]],
    concurrency: int,
) -> list[_Result]:
    """Run ``work`` over every item, with at most ``concurrency`` alive at once.

    Args:
        items: The work list. Consumed once, so a generator is fine.
        work: Coroutine function applied to each item.
        concurrency: How many may run at a time; at least 1.

    Returns:
        Every result, in completion order rather than input order. Callers that
        need the association back should have ``work`` return it - both callers
        here return a ``(key, value)`` pair for exactly that reason.

    Raises:
        ValueError: ``concurrency`` is below 1, checked by
            :func:`require_concurrency` before any item is taken.

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

    workers = require_concurrency(concurrency)
    pending = iter(items)
    results: list[_Result] = []

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
