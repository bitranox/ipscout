"""Banner grabs: what each host says first on a TCP port, read on one connection.

Contents:
    grab_banners / agrab_banners: The first line many hosts send on one port.

Note:
    Everything for one host happens on ONE connection - connect, read the
    greeting, optionally say goodbye, close. That is not a convenience: some
    embedded servers refuse a new connect for a moment after each session
    (measured on a print server: about 0.1 s), so "find the open ports, then
    connect again to read" misses exactly the devices a banner identifies.

    One deadline per host covers name resolution, the connect and the read
    together, so a caller's ``timeout`` bounds how long any one host can take,
    rather than each phase taking up to that long on its own.

    A refused connection is reported, not retried. Whether a refusal is worth a
    second try depends on the device, and only the caller knows the device.

"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .api import require_host_names
from .errors import IPScoutError, refused_arguments
from .models import AddressFamily, Banner, BannerState, Port, Timeout
from .pool import Concurrency, gather_bounded
from .resolve import resolve_one
from .sockerr import is_refusal

if TYPE_CHECKING:
    from collections.abc import Coroutine, Iterable

__all__ = ["DEFAULT_CONCURRENCY", "DEFAULT_MAX_LINE_BYTES", "DEFAULT_TIMEOUT", "BannerSettings", "agrab_banners", "grab_banners"]

#: Connections in flight at once. Enough for a /24 in a few rounds while
#: staying far from any per-process file-handle limit.
DEFAULT_CONCURRENCY = 64

#: Seconds per host. Generous on purpose: with dozens of connects in flight a
#: present but slow embedded device was measured taking over 2 s to accept.
DEFAULT_TIMEOUT = 3.0

#: A greeting is one short line; this bounds what a hostile or chatty server
#: can make the caller buffer per host.
DEFAULT_MAX_LINE_BYTES = 512

_T = TypeVar("_T")


class BannerSettings(BaseModel):
    """The arguments of one banner grab, checked once so every host is grabbed the same way.

    Every bound is declared on its field, so the check and the documentation
    cannot drift apart, and the command line reads the same declarations for
    its options instead of restating them. Strict: a caller's ``True`` is not
    a port and ``"3"`` is not a timeout.

    Examples:
        >>> BannerSettings(port=21).timeout == DEFAULT_TIMEOUT
        True
        >>> BannerSettings(port=21, farewell=b"")
        Traceback (most recent call last):
        ...
        pydantic_core._pydantic_core.ValidationError: ...

    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    #: The TCP port to connect to on every host.
    port: Port
    #: Seconds per host for resolving, connecting and reading together, under
    #: the library's one timeout rule: zero would never wait, and an unbounded
    #: wait would let one silent host hold the grab open.
    timeout: Timeout = DEFAULT_TIMEOUT
    #: The most bytes of greeting kept per host.
    max_line_bytes: int = Field(default=DEFAULT_MAX_LINE_BYTES, ge=1)
    #: Bytes sent after a greeting, before closing. Empty would be accepted
    #: and never sent, so it is refused rather than silently ignored.
    farewell: bytes | None = Field(default=None, min_length=1)
    #: Connections in flight at once, under the pool's one concurrency rule.
    concurrency: Concurrency = DEFAULT_CONCURRENCY
    #: Use only IPv4 or IPv6 addresses for every host.
    family: AddressFamily | None = None


def _reason(exc: BaseException) -> str:
    """Return why a grab failed, in the exception's own words or by its name.

    An exception can carry an empty message, and an unreachable result must
    name a reason, so the class name stands in rather than an empty string.

    Examples:
        >>> _reason(OSError("Network is unreachable"))
        'Network is unreachable'
        >>> _reason(IPScoutError())
        'IPScoutError'

    """

    return str(exc) or type(exc).__name__


async def _within(deadline: float, awaitable: Coroutine[object, object, _T]) -> _T:
    """Await ``awaitable`` with whatever is left until ``deadline``.

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


async def _read_line(reader: asyncio.StreamReader, deadline: float, cap: int) -> bytes:
    """Read until a newline, the close, ``cap`` bytes or the deadline - whichever comes first.

    Whatever arrived by then is the line, terminator excluded: a server that
    writes a partial greeting and hangs up has still said something.
    """

    received = bytearray()
    while len(received) < cap:
        try:
            chunk = await _within(deadline, reader.read(cap - len(received)))
        except OSError:  # TimeoutError included: the deadline ends the line too
            break
        if not chunk:
            break
        end = chunk.find(b"\n")
        if end >= 0:
            received += chunk[:end]
            break
        received += chunk
    return bytes(received)


async def _say_goodbye(writer: asyncio.StreamWriter, farewell: bytes) -> None:
    """Send the farewell; a peer that already left changes nothing about what it said."""

    with contextlib.suppress(OSError):
        writer.write(farewell)
        await writer.drain()


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(OSError, asyncio.TimeoutError, ConnectionError):
        await writer.wait_closed()


async def _converse(host: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, settings: BannerSettings, deadline: float) -> Banner:
    """Read the greeting on an open connection, say goodbye if asked, and close it."""

    try:
        raw = await _read_line(reader, deadline, settings.max_line_bytes)
        if raw and settings.farewell is not None:
            await _say_goodbye(writer, settings.farewell)
    finally:
        await _close(writer)
    if not raw:
        return Banner(host=host, port=settings.port, state=BannerState.SILENT)
    line = raw.decode("utf-8", errors="replace").strip()
    return Banner(host=host, port=settings.port, state=BannerState.GREETED, line=line)


async def _grab_one(host: str, settings: BannerSettings) -> Banner:
    """Grab one host's banner. Every failure is a result, never a raise."""

    deadline = asyncio.get_running_loop().time() + settings.timeout

    def unreachable(reason: str) -> Banner:
        return Banner(host=host, port=settings.port, state=BannerState.UNREACHABLE, error=reason)

    try:
        # In a thread: a slow DNS answer for one name must not stall every other host.
        target = await _within(deadline, asyncio.to_thread(resolve_one, host, family=settings.family))
        reader, writer = await _within(deadline, asyncio.open_connection(target.address, settings.port, family=target.family.socket_family))
    except IPScoutError as exc:
        return unreachable(_reason(exc))
    except TimeoutError:
        return unreachable(f"no connection within {settings.timeout:g} s")
    except OSError as exc:
        if is_refusal(exc):
            return Banner(host=host, port=settings.port, state=BannerState.REFUSED)
        return unreachable(_reason(exc))
    return await _converse(host, reader, writer, settings, deadline)


async def agrab_banners(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    hosts: Iterable[str],
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    farewell: bytes | None = None,
    concurrency: int = DEFAULT_CONCURRENCY,
    family: AddressFamily | None = None,
) -> dict[str, Banner]:
    """Read the first line each host sends on a TCP port, many hosts at once.

    Args:
        hosts: Hostnames or address literals; a link-local IPv6 address needs
            its ``%zone``. Any collection or iterator of ``str``, never one
            bare string: ``"printer.lan"`` is itself an iterable of one-letter
            names. Duplicates are collapsed, since the result is keyed by host
            and a repeat could only overwrite itself.
        port: The TCP port to connect to on every host.
        timeout: Seconds allowed per host for resolving, connecting and
            reading together. A host that connects but has not finished its
            line by then returns what it sent so far.
        max_line_bytes: The most bytes of greeting kept per host. Reading stops
            at the first newline, at the close, or here.
        farewell: Bytes to send after a line was read and before closing, such
            as ``b"QUIT\\r\\n"`` for FTP or SMTP, so the server logs a clean exit
            rather than a dropped session. Sent to any host that said
            something, and never to one that stayed silent. Must not be
            empty: an empty farewell could only be skipped.
        concurrency: Connections in flight at once.
        family: Use only IPv4 or IPv6 addresses for every host.

    Returns:
        A mapping of host, exactly as given, to its :class:`Banner`, in the
        order the hosts were given. Every host has an entry: a name that does
        not resolve is an UNREACHABLE result, never an exception.

    Raises:
        ValueError: ``port`` is outside 1-65535, ``timeout`` is not above 0 and
            at most ``MAX_TIMEOUT``, ``max_line_bytes`` or ``concurrency`` is below 1, or
            ``farewell`` is empty. One message names every bad argument, as
            ``<argument>: <reason>``, and it is raised before anything connects.
            ``hosts`` being one bare string or holding a non-``str`` entry is
            refused the same way, checked after the other arguments so a bad
            one is reported before any host is taken from ``hosts``.

    Examples:
        >>> import asyncio
        >>> results = asyncio.run(agrab_banners(["nothing.invalid"], 21))
        >>> results["nothing.invalid"].state
        <BannerState.UNREACHABLE: 'unreachable'>

    """

    try:
        settings = BannerSettings(port=port, timeout=timeout, max_line_bytes=max_line_bytes, farewell=farewell, concurrency=concurrency, family=family)
    except ValidationError as refused:
        raise refused_arguments("banner grab", refused) from refused
    unique = require_host_names(hosts, operation="banner grab", argument="hosts")

    async def one(host: str) -> tuple[str, Banner]:
        # Paired with its host: the pool completes out of order.
        return host, await _grab_one(host, settings)

    completed = dict(await gather_bounded(unique, one, settings.concurrency))
    return {host: completed[host] for host in unique}


def grab_banners(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    hosts: Iterable[str],
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    farewell: bytes | None = None,
    concurrency: int = DEFAULT_CONCURRENCY,
    family: AddressFamily | None = None,
) -> dict[str, Banner]:
    """Read the first line each host sends on a TCP port, from synchronous code.

    Takes the same arguments as :func:`agrab_banners`.

    Returns:
        A mapping of host to :class:`Banner`, in the order the hosts were given.

    Raises:
        ValueError: As :func:`agrab_banners`.
        RuntimeError: Called from inside a running event loop, where it would
            deadlock. Await :func:`agrab_banners` there instead.

    Examples:
        >>> grab_banners(["nothing.invalid"], 21)["nothing.invalid"].state
        <BannerState.UNREACHABLE: 'unreachable'>

    """

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        msg = "grab_banners() cannot run inside an event loop; await agrab_banners() instead"
        raise RuntimeError(msg)

    return asyncio.run(
        agrab_banners(
            hosts,
            port,
            timeout=timeout,
            max_line_bytes=max_line_bytes,
            farewell=farewell,
            concurrency=concurrency,
            family=family,
        )
    )
