"""Typed access to the Unix-only stdlib surfaces this package uses.

Contents:
    fcntl_module: The ``fcntl`` module, typed and imported on first use.
    packet_family: The ``AF_PACKET`` constant, or why this host has none.

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

import socket
from typing import Protocol, cast

from .errors import IPScoutUnsupportedError

__all__ = ["fcntl_module", "packet_family"]


class _Fcntl(Protocol):
    """The ``fcntl`` calls this package makes, in the forms it uses.

    ``arg`` is optional because a BSD ``_IO`` request - ``BIOCPROMISC``, for
    one - carries no argument at all, and passing one makes the kernel refuse
    the call. Declaring it required would have forced a suppression at that
    call site instead of typing what the module really accepts.
    """

    def ioctl(self, fd: int, request: int, arg: bytes = ..., /) -> bytes: ...


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


def packet_family() -> int:
    """Return the ``AF_PACKET`` constant, or say why this host has none.

    Read with ``getattr`` rather than as ``socket.AF_PACKET`` because the
    attribute exists only on Linux: a direct reference fails the type check
    run for Windows and macOS even on a Linux-only path.

    Raises:
        IPScoutUnsupportedError: Off Linux, where no packet socket exists.

    Examples:
        >>> import sys
        >>> if sys.platform.startswith("linux"):
        ...     assert packet_family() == socket.AF_PACKET

    """

    af_packet = getattr(socket, "AF_PACKET", None)
    if not isinstance(af_packet, int):  # pragma: no cover - non-Linux
        msg = "AF_PACKET is a Linux facility and this process is not on Linux"
        raise IPScoutUnsupportedError(msg)
    return af_packet
