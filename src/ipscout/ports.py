"""Protocols the probing layers depend on, so backends stay substitutable.

These are the seams. ``service`` and ``traceroute`` are written against the
protocols here and never import a concrete backend, which means a test can
hand them a real in-process fake instead of a socket. That is why this package
needs no ``mock.patch`` of its own internals anywhere: the substitution point
is a constructor argument, not a monkeypatched module attribute.

Contents:
    EchoResult: What a single probe attempt reports back.
    EchoTransport: Synchronous probe interface.
    AsyncEchoTransport: The same contract for asyncio callers.
    PacketCapture: A source of raw link-layer frames.

Note:
    A transport reports *what happened*, including "nothing came back", and
    raises only when it cannot probe at all. Keeping that split here is what
    lets the strict error contract hold uniformly across every backend.

"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, model_validator

from .deadline import MIN_WAIT as MIN_CAPTURE_WAIT
from .models import RoundTrip

if TYPE_CHECKING:
    from types import TracebackType

__all__ = ["CAPTURE_RECEIVE_BUFFER", "MIN_CAPTURE_WAIT", "AsyncEchoTransport", "EchoResult", "EchoTransport", "PacketCapture"]

#: The socket receive buffer a capture asks for. Asked for, not required: the
#: kernel may double it for bookkeeping and clamp it (Linux: net.core.rmem_max),
#: so the value that sticks is often smaller. It is a cushion against a burst
#: arriving between two reads, never a correctness dependency, so failing to set
#: it is not a failure to capture.
CAPTURE_RECEIVE_BUFFER = 1 << 20

# MIN_CAPTURE_WAIT, the shortest wait one capture read makes, is
# deadline.MIN_WAIT under the name the capture backends import it by: the
# reason for the floor is the same, so its value lives once, in deadline.


class EchoResult(BaseModel):
    """The outcome of one probe attempt.

    Attributes:
        rtt_ms: Round trip in milliseconds, or ``None`` if nothing answered.
        source: Who answered. For a normal reply this is the target; for a
            TTL-expired response it is the router that dropped the packet.
            Set exactly when ``rtt_ms`` is: an answer always comes from
            someone, and nobody answers a probe that timed out.
        ttl_expired: True when a router reported Time Exceeded rather than the
            target replying. Traceroute needs this; ping treats it as no answer.
            Only an answer can be one.

    Examples:
        >>> EchoResult(rtt_ms=1.5, source="127.0.0.1").answered
        True
        >>> EchoResult().answered
        False
        >>> EchoResult(rtt_ms=float("nan"), source="127.0.0.1")
        Traceback (most recent call last):
        ...
        pydantic_core._pydantic_core.ValidationError: ...

    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rtt_ms: RoundTrip | None = None
    source: str | None = None
    ttl_expired: bool = False

    @model_validator(mode="after")
    def _an_answer_has_a_time_and_a_source(self) -> EchoResult:
        if (self.rtt_ms is None) != (self.source is None):
            msg = "rtt_ms and source are set together: an answer comes from someone, a timeout from no one"
            raise ValueError(msg)
        if self.ttl_expired and self.rtt_ms is None:
            msg = "ttl_expired needs the router's answer: rtt_ms and source"
            raise ValueError(msg)
        return self

    @property
    def answered(self) -> bool:
        """Return whether anything at all came back."""

        return self.rtt_ms is not None


@runtime_checkable
class EchoTransport(Protocol):
    """A synchronous way to send one echo and wait for its reply.

    Implementations must be usable as a context manager so the caller can
    release sockets and OS handles deterministically rather than at GC time.
    """

    #: Whether this transport carries ICMP or substitutes TCP.
    @property
    def supports_ttl(self) -> bool:
        """Return whether this transport can set a per-probe TTL.

        Traceroute needs this; a backend that cannot vary the TTL says so
        rather than silently returning first-hop results for every hop.
        """
        ...

    @property
    def supports_ttl_discovery(self) -> bool:
        """Return whether an expired hop can actually be *observed*.

        Separate from :attr:`supports_ttl` because the two come apart: macOS
        can set a hop limit but never surfaces the resulting Time Exceeded to
        an unprivileged process, so a traceroute built there would report
        silence at every hop and look like a broken network.
        """
        ...

    def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:
        """Send one echo and wait up to ``timeout`` seconds for its reply.

        Args:
            sequence: Sequence number identifying this probe.
            timeout: Seconds to wait before giving up on a reply.
            ttl: Hop limit for this probe, or ``None`` for the system default.

        Returns:
            The outcome. A timeout is an ``EchoResult`` with ``rtt_ms=None``,
            not an exception.
        """
        ...

    def close(self) -> None:
        """Release any sockets or OS handles held by this transport."""
        ...

    def __enter__(self) -> EchoTransport: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...


@runtime_checkable
class PacketCapture(Protocol):
    """A source of raw link-layer frames, read until the caller stops asking.

    Implementations must be usable as a context manager so the caller can
    release sockets and OS handles deterministically rather than at GC time.

    Like :class:`EchoTransport`, a capture reports *what arrived*, including
    "nothing did", and raises only when it cannot capture at all. Silence is
    the ordinary case here rather than the exceptional one: a capture watching
    for one machine's traffic spends nearly all of its time seeing none of it.
    """

    def receive(self, *, timeout: float) -> bytes | None:
        """Return the next frame, or ``None`` if none arrived in ``timeout``.

        Args:
            timeout: Seconds to wait. A caller holding a deadline passes a
                short slice of it repeatedly rather than the whole remainder,
                so that a request to stop is noticed promptly.

        Returns:
            One frame exactly as captured, or ``None`` on timeout. ``None``
            means "not yet", never "give up": when to stop is a decision only
            the caller can make.
        """
        ...

    def close(self) -> None:
        """Release the socket or handle held by this capture."""
        ...

    def __enter__(self) -> PacketCapture: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...


@runtime_checkable
class AsyncEchoTransport(Protocol):
    """The same contract as :class:`EchoTransport`, for asyncio callers."""

    @property
    def supports_ttl(self) -> bool:
        """Return whether this transport can set a per-probe TTL."""
        ...

    @property
    def supports_ttl_discovery(self) -> bool:
        """Return whether an expired hop can actually be observed."""
        ...

    async def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:
        """Send one echo and await its reply, up to ``timeout`` seconds."""
        ...

    async def aclose(self) -> None:
        """Release any sockets or OS handles held by this transport."""
        ...

    async def __aenter__(self) -> AsyncEchoTransport: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...
