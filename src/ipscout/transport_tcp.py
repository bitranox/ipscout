"""Reachability by TCP connect, for when ICMP is unavailable or filtered.

This is a deliberate second-best and is never selected automatically. A caller
opts in with ``allow_tcp_fallback=True``, and every result it produces is
stamped ``ProbeMethod.TCP`` so it can never be mistaken for an ICMP round trip.

Contents:
    TcpEchoTransport: Synchronous connect probe.
    AsyncTcpEchoTransport: The same over asyncio.

What a TCP probe does and does not tell you:

    A completed handshake proves the host is up. So does an actively refused
    connection: something answered with RST, which only a live host does. Both
    therefore count as reached. A timeout does not, though it is ambiguous -
    the host may be down, or a firewall may simply be dropping the packets.

    The timing is not comparable to ICMP. It includes the full handshake and
    is handled in user space by the peer's TCP stack rather than by its kernel
    ICMP path, so it reads consistently higher.

Note:
    Only full connects are made, never half-open SYN probes. Sending a bare
    SYN needs a raw socket and therefore administrator rights, which is exactly
    what this library exists to avoid.

"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import time
from typing import TYPE_CHECKING

from .models import AddressFamily
from .ports import EchoResult

if TYPE_CHECKING:
    from types import TracebackType

__all__ = ["AsyncTcpEchoTransport", "TcpEchoTransport"]

_FAMILY_TO_SOCKET = {
    AddressFamily.IPV4: socket.AF_INET,
    AddressFamily.IPV6: socket.AF_INET6,
}


class TcpEchoTransport:
    """Probe reachability by attempting a TCP connection.

    Args:
        address: The resolved address to probe.
        family: Address family of ``address``.
        port: TCP port to connect to.

    Examples:
        >>> import socket
        >>> listener = socket.socket()
        >>> listener.bind(("127.0.0.1", 0))
        >>> listener.listen(1)
        >>> port = listener.getsockname()[1]
        >>> with TcpEchoTransport("127.0.0.1", AddressFamily.IPV4, port=port) as transport:
        ...     transport.probe(sequence=1, timeout=2.0).answered
        True
        >>> listener.close()

    """

    def __init__(self, address: str, family: AddressFamily, *, port: int = 443) -> None:
        self._address = address
        self._family = family
        self._port = port

    @property
    def supports_ttl(self) -> bool:
        """Return False: a connect probe cannot usefully carry a hop limit.

        Saying so explicitly keeps traceroute from silently reporting the same
        first hop for every TTL it asks for.
        """

        return False

    @property
    def supports_ttl_discovery(self) -> bool:
        """Return False: with no hop limit there is no expiry to observe."""

        return False

    def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:
        """Attempt one connection and time it.

        Args:
            sequence: Accepted for interface compatibility; TCP has no
                sequence of its own to carry.
            timeout: Seconds to allow for the handshake.
            ttl: Accepted and ignored, since ``supports_ttl`` is False.

        Returns:
            Answered when the handshake completed or the port actively refused
            the connection; unanswered on timeout or an unreachable network.

        """

        del sequence, ttl
        sock = socket.socket(_FAMILY_TO_SOCKET[self._family], socket.SOCK_STREAM)
        sock.settimeout(timeout)
        started = time.perf_counter()
        try:
            sock.connect((self._address, self._port))
        except ConnectionRefusedError:
            # Refused means something answered, which only a live host does.
            return EchoResult(rtt_ms=(time.perf_counter() - started) * 1000.0, source=self._address)
        except (TimeoutError, OSError):
            return EchoResult()
        else:
            return EchoResult(rtt_ms=(time.perf_counter() - started) * 1000.0, source=self._address)
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    def close(self) -> None:
        """Release resources. Each probe owns its own socket, so this is a no-op."""

    def __enter__(self) -> TcpEchoTransport:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class AsyncTcpEchoTransport:
    """The same connect probe, awaited rather than blocking.

    Args:
        address: The resolved address to probe.
        family: Address family of ``address``.
        port: TCP port to connect to.

    """

    def __init__(self, address: str, family: AddressFamily, *, port: int = 443) -> None:
        self._address = address
        self._family = family
        self._port = port

    @property
    def supports_ttl(self) -> bool:
        """Return False: a connect probe cannot usefully carry a hop limit."""

        return False

    @property
    def supports_ttl_discovery(self) -> bool:
        """Return False: with no hop limit there is no expiry to observe."""

        return False

    async def probe(self, *, sequence: int, timeout: float, ttl: int | None = None) -> EchoResult:
        """Attempt one connection and time it.

        Args:
            sequence: Accepted for interface compatibility.
            timeout: Seconds to allow for the handshake.
            ttl: Accepted and ignored, since ``supports_ttl`` is False.

        Returns:
            Answered on a completed handshake or an active refusal.

        """

        del sequence, ttl
        started = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._address, self._port),
                timeout,
            )
        except ConnectionRefusedError:
            return EchoResult(rtt_ms=(time.perf_counter() - started) * 1000.0, source=self._address)
        except (TimeoutError, asyncio.TimeoutError, OSError):
            return EchoResult()

        del reader
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        writer.close()
        with contextlib.suppress(OSError, ConnectionError):
            await writer.wait_closed()
        return EchoResult(rtt_ms=elapsed_ms, source=self._address)

    async def aclose(self) -> None:
        """Release resources. Each probe owns its own connection, so this is a no-op."""

    async def __aenter__(self) -> AsyncTcpEchoTransport:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
