"""One deadline across several awaits, and the words for why one failed.

Contents:
    within: Await something with whatever is left until a deadline.
    failure_reason: Why something failed, never an empty string.

"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Coroutine

__all__ = ["failure_reason", "within"]

_T = TypeVar("_T")


def failure_reason(exc: BaseException) -> str:
    """Return why something failed, in the exception's own words or by its name.

    An exception can carry an empty message, and a failed result must name a
    reason, so the class name stands in rather than an empty string.

    Args:
        exc: The exception that ended the attempt.

    Returns:
        ``str(exc)``, or the exception's class name when that is empty.

    Examples:
        >>> failure_reason(OSError("Network is unreachable"))
        'Network is unreachable'
        >>> failure_reason(ValueError())
        'ValueError'

    """

    return str(exc) or type(exc).__name__


async def within(deadline: float, awaitable: Coroutine[object, object, _T]) -> _T:
    """Await ``awaitable`` with whatever is left until ``deadline``.

    Args:
        deadline: A time on the running loop's clock (``loop.time()``).
        awaitable: The coroutine to run. Closed unawaited when the deadline
            has already passed, so it never warns about a missing await.

    Returns:
        What ``awaitable`` returned.

    Raises:
        TimeoutError: The deadline has passed or passes while waiting. Raised
            as the builtin on every version, so callers need not also catch
            ``asyncio.TimeoutError``, which is a different class before 3.11.

    """

    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        awaitable.close()
        raise TimeoutError
    try:
        return await asyncio.wait_for(awaitable, remaining)
    except asyncio.TimeoutError as exc:
        raise TimeoutError from exc
