"""Typed access to the Unix-only stdlib surfaces this package uses.

Contents:
    fcntl_module: The ``fcntl`` module, typed and imported on first use.

Note:
    ``fcntl`` exists only on Unix, so its attributes are unknown to a type
    check run for Windows even where the call sits on a POSIX-only path. The
    module is cast onto a Protocol declaring the one call this package makes:
    the cast is a runtime no-op, so behaviour is unchanged, while every call
    site keeps complete types on all three platforms.

    This lives in one place rather than in each backend that needs it. The
    first version of it was written into the macOS neighbour backend, and the
    next caller - the POSIX interface backend - reached for a bare import and
    broke the Windows type check all over again.

"""

from __future__ import annotations

from typing import Protocol, cast

__all__ = ["fcntl_module"]


class _Fcntl(Protocol):
    """The one ``fcntl`` call this package makes, in the one form used."""

    def ioctl(self, fd: int, request: int, arg: bytes, /) -> bytes: ...


def fcntl_module() -> _Fcntl:
    """Return the ``fcntl`` module, typed, importing it on first use.

    Raises:
        ModuleNotFoundError: On a platform without it. Every caller is already
            on a POSIX-only path, so reaching this means the dispatch above it
            is wrong and should fail loudly rather than be papered over.

    Examples:
        >>> import sys
        >>> if sys.platform != "win32":
        ...     _ = fcntl_module().ioctl

    """

    import fcntl  # noqa: PLC0415 - Unix-only, and only on a POSIX path

    return cast("_Fcntl", fcntl)
