"""One deadline across several awaits, and the words for why one failed.

Contents:
    within: Await something with whatever is left until a deadline.
    seconds_left: The wait a blocking read may take before a deadline.
    MIN_WAIT: The shortest wait seconds_left ever gives.
    failure_reason: Why something failed, never an empty string.

"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Coroutine

__all__ = ["MIN_WAIT", "blocking_wait", "failure_reason", "seconds_left", "within"]

_T = TypeVar("_T")

#: The shortest wait a blocking read before a deadline is given. A deadline
#: about to pass would otherwise become settimeout(0), which turns the socket
#: non-blocking (and makes select return at once), or a negative timeout, which
#: raises - so "no time left" still waits this long rather than changing the
#: socket's mode or failing.
MIN_WAIT = 0.001


def blocking_wait(seconds: float) -> float:
    """Return ``seconds`` as a blocking read's timeout, never under MIN_WAIT.

    The floor for a wait given as a duration, where :func:`seconds_left` takes
    a deadline; both apply the one rule.

    Examples:
        >>> blocking_wait(0) == MIN_WAIT
        True
        >>> blocking_wait(2.5)
        2.5

    """

    return max(MIN_WAIT, seconds)


def seconds_left(deadline: float) -> float:
    """Return how long a blocking read may wait before ``deadline``, never under MIN_WAIT.

    Args:
        deadline: A time on the ``time.monotonic()`` clock.

    Returns:
        The seconds until ``deadline``, or :data:`MIN_WAIT` once that is less,
        so the result is always a valid blocking timeout.

    Examples:
        >>> seconds_left(time.monotonic() - 5) == MIN_WAIT
        True
        >>> start = time.monotonic()
        >>> 9 < seconds_left(start + 10) <= (start + 10) - start
        True

    """

    return blocking_wait(deadline - time.monotonic())


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
