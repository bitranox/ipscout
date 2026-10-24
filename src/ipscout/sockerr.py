"""What a socket error means, read the same way on every platform.

Contents:
    is_refusal: Whether an error means the target actively refused.

Note:
    Every module that connects needs the same answer to "was that a refusal?",
    and each platform spells it differently. Keeping one reading here stops the
    spellings drifting apart between callers - a caller that knows only the
    exception class silently calls a refused Windows port unreachable.

"""

from __future__ import annotations

import errno

__all__ = ["is_refusal"]

#: How Windows numbers a refused connection: the sockets layer and the
#: overlapped layer disagree, and neither matches the POSIX errno.
_WSAECONNREFUSED = 10061
_ERROR_CONNECTION_REFUSED = 1225

_REFUSAL_CODES = frozenset({errno.ECONNREFUSED, _WSAECONNREFUSED, _ERROR_CONNECTION_REFUSED})


def is_refusal(exc: OSError) -> bool:
    """Return whether an error means the target actively refused.

    A refusal is an answer - something is there to send the reset - so it must
    be told apart from silence. The exception class carries that on most
    platforms, but not dependably enough to rely on alone: the same condition
    can arrive as a bare OSError with the errno set, and Windows numbers it
    differently again (WSAECONNREFUSED, and 1225 from the overlapped layer).
    Checking all three is cheaper than being wrong about a firewall.

    Args:
        exc: The error a connect attempt raised.

    Returns:
        True when the error is a refusal in any of its spellings.

    Examples:
        >>> is_refusal(ConnectionRefusedError())
        True
        >>> is_refusal(OSError(errno.ECONNREFUSED, "refused"))
        True
        >>> is_refusal(TimeoutError("timed out"))
        False

    """

    if isinstance(exc, ConnectionRefusedError):
        return True
    if exc.errno in _REFUSAL_CODES:
        return True
    return getattr(exc, "winerror", None) in _REFUSAL_CODES
