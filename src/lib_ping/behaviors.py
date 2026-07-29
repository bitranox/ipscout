"""Domain-level behaviors supporting the minimal CLI transport.

Collect the placeholder behaviors that the CLI adapter exposes so that each
concern remains self-contained. Keeping these helpers together makes it easy to
swap in richer logging logic later without touching the transport surface.

Contents:
    emit_greeting: Success-path helper that writes the canonical scaffold
        message.
    raise_intentional_failure: Deterministic error hook used by tests and
        CLI flows to validate traceback handling.
    noop_main: Placeholder entry used when callers expect a ``main``
        callable despite the domain layer being stubbed today.

Note:
    Acts as the temporary domain surface for this template. Other modules import
    from here instead of duplicating literals so the public API stays coherent
    as features evolve.

"""

from __future__ import annotations

import sys
from typing import Protocol


class WritableStream(Protocol):
    """Protocol for streams that accept text via ``write()``.

    Only requires the ``write`` method. The ``flush`` method is optional
    and checked at runtime via duck-typing in :func:`_flush_if_possible`.
    """

    def write(self, s: str, /) -> object: ...


CANONICAL_GREETING = "Hello World"


def _target_stream(preferred: WritableStream | None) -> WritableStream:
    """Return the stream that should hear the greeting."""

    return preferred if preferred is not None else sys.stdout


def _greeting_line() -> str:
    """Return the greeting exactly as it should appear."""

    return f"{CANONICAL_GREETING}\n"


def _flush_if_possible(stream: WritableStream) -> None:
    """Flush the stream when the stream knows how to flush."""

    flush = getattr(stream, "flush", None)
    if callable(flush):
        flush()


def emit_greeting(*, stream: WritableStream | None = None) -> None:
    """Write the canonical greeting to the provided text stream.

    Provide a deterministic success path that the documentation, smoke
    tests, and packaging checks can rely on while the real logging helpers
    are developed. Writes `CANONICAL_GREETING` followed by a newline to the
    target stream.

    Args:
        stream: Optional text stream receiving the greeting. Defaults to
            `sys.stdout` when None.

    Note:
        Writes to the target stream and flushes it when a ``flush`` attribute
        is available.

    Examples:
        >>> from io import StringIO
        >>> buffer = StringIO()
        >>> emit_greeting(stream=buffer)
        >>> buffer.getvalue() == "Hello World\\n"
        True

    """

    target = _target_stream(stream)
    target.write(_greeting_line())
    _flush_if_possible(target)


def raise_intentional_failure() -> None:
    """Raise RuntimeError so transports can exercise failure flows.

    CLI commands and tests need a guaranteed failure scenario to ensure the
    shared exit-code helpers and traceback toggles remain correct. Always
    raises RuntimeError with the message "I should fail".

    Raises:
        RuntimeError: Unconditionally raised regardless of input.

    Examples:
        >>> raise_intentional_failure()
        Traceback (most recent call last):
        ...
        RuntimeError: I should fail

    """

    raise RuntimeError("I should fail")


def noop_main() -> None:
    """Explicit placeholder callable for transports without domain logic yet.

    Some tools expect a module-level ``main`` even when the underlying
    feature set is still stubbed out. Exposing this helper makes that
    contract obvious and easy to replace later. Performs no work and returns
    immediately.

    Examples:
        >>> noop_main()

    """

    return None


__all__ = [
    "CANONICAL_GREETING",
    "WritableStream",
    "emit_greeting",
    "noop_main",
    "raise_intentional_failure",
]
