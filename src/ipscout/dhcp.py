"""Watch a DHCP handshake and learn the address a machine is being given.

Contents:
    observe_dhcp: Every address offered to a hardware address, in order seen.
    observe_dhcp_session: The same, startable before the machine is started.
    observe_dhcp_first_reachable: The first offered address that answers.
    dhcp_capture_available: Whether this host can capture at all.
    DhcpSession: The session object the context manager hands back.

The window nothing else reaches:
    Every other way this package finds a machine needs it already up and
    answering. A neighbour-cache entry only exists after real traffic; a sweep
    needs the host to answer ARP, so it must already hold an address; a lease
    describes *this* host, not one handed to somebody else.

    A machine that has just been started has none of those. It asks for an
    address about a second after the start command, and watching that exchange
    is the only way to learn what it was given. That is not a niche case: it
    is the normal path for anything that boots a machine and then has to reach
    it.

Why the session form exists, and why it is the important one:
    A one-shot call that begins capturing when invoked is too late. By the
    time the caller has issued its start command and called in, the handshake
    is over. The session opens the capture first, so the exchange can be
    started inside it:

        with observe_dhcp_session(mac, interface="br0", timeout=150) as watch:
            start_the_machine()
            addresses = watch.result()

    Opening the capture in ``__enter__`` is what makes a missing privilege
    surface *before* a machine is started and waited on, rather than as an
    empty list two minutes later.

Note:
    This listens. It never transmits: no DHCP traffic is sent, no address is
    ever requested, and nothing on the network can tell it is running beyond
    the interface being in promiscuous mode.

"""

from __future__ import annotations

import contextlib
import sys
import threading
import time
from typing import TYPE_CHECKING

from .api import is_reachable
from .bootp import DhcpReply, merge_offers
from .errors import IPScoutError, IPScoutUnsupportedError
from .neighbours import normalise_mac
from .routes import default_gateway

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from types import TracebackType

    from .ports import PacketCapture

    #: How a session obtains its capture. Injecting this is the seam that lets
    #: the deadline, the ordering, the de-duplication and the teardown all be
    #: exercised over replayed frames on a host where no capture may be opened
    #: at all - which is every CI runner.
    CaptureFactory = Callable[[str], PacketCapture]

__all__ = [
    "DEFAULT_SETTLE",
    "DEFAULT_TIMEOUT",
    "DhcpSession",
    "dhcp_capture_available",
    "observe_dhcp",
    "observe_dhcp_first_reachable",
    "observe_dhcp_session",
]

#: Seconds to watch for before giving up on a machine appearing at all.
DEFAULT_TIMEOUT = 60.0

#: Seconds of quiet, after the last new address, before the answer is given.
#:
#: Reasoned rather than measured. RFC 2131 has a client wait at least ten
#: seconds before restarting configuration after declining an address, and a
#: real capture showed 5.85 seconds between an offer and the one that replaced
#: it. Anything below ten would truncate a conforming client's second attempt,
#: which is exactly the address it ends up using.
DEFAULT_SETTLE = 12.0

#: How long a single read waits before the loop checks whether it should stop.
#: The only cost of a tick is a wakeup; the benefit is that a session closes
#: within one of them rather than at the end of its window.
_POLL_TICK = 0.25

#: How long a close waits for the reading thread before giving up on it, so a
#: wedged capture cannot hold the caller forever.
_JOIN_TIMEOUT = 2.0

_IS_LINUX = sys.platform.startswith("linux")


def _the_exchange_has_gone_quiet(*, last_seen_at: float | None, now: float, started_at: float, timeout: float, settle: float) -> bool:
    """Return whether watching can stop.

    The rule, in one sentence: stop once ``settle`` seconds have passed with
    no new address, and never watch longer than ``timeout``.

    Args:
        last_seen_at: When the most recent new address arrived, or ``None``
            when none has.
        now: The current moment, on the same clock as the other two.
        started_at: When the session opened.
        timeout: The whole window.
        settle: Quiet needed after the last address.

    Returns:
        Whether the answer can be given now.

    Note:
        Nothing seen at all costs the whole window, because only the whole
        window can establish absence. A ``settle`` of at least ``timeout``
        collapses this to "watch the whole window regardless", which is the
        exhaustive read.

    Examples:
        >>> quiet = _the_exchange_has_gone_quiet
        >>> quiet(last_seen_at=None, now=5.0, started_at=0.0, timeout=60.0, settle=12.0)
        False
        >>> quiet(last_seen_at=None, now=60.0, started_at=0.0, timeout=60.0, settle=12.0)
        True
        >>> quiet(last_seen_at=2.0, now=13.0, started_at=0.0, timeout=60.0, settle=12.0)
        False
        >>> quiet(last_seen_at=2.0, now=14.0, started_at=0.0, timeout=60.0, settle=12.0)
        True

    """

    if now >= started_at + timeout:
        return True
    if last_seen_at is None:
        return False
    return now >= last_seen_at + settle


class DhcpSession:
    """A running capture, watching for addresses offered to one machine.

    Built by :func:`observe_dhcp_session` rather than directly, and used as a
    context manager. The capture opens on entry and stops on exit, so the
    exchange being watched for has to happen inside the block.
    """

    def __init__(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
        self,
        mac: str,
        *,
        interface: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        settle: float = DEFAULT_SETTLE,
        capture: PacketCapture | None = None,
        promiscuous: bool = True,
    ) -> None:
        wanted = normalise_mac(mac)
        if wanted is None:
            # Refused here rather than after the capture opens, so a typo is
            # the same error on every host instead of being masked by a
            # permission failure on the ones that cannot capture.
            msg = f"not a hardware address: {mac!r}"
            raise ValueError(msg)
        if timeout <= 0:
            msg = f"timeout must be positive, got {timeout!r}: a window of zero could never see anything"
            raise ValueError(msg)
        if settle < 0:
            msg = f"settle cannot be negative, got {settle!r}"
            raise ValueError(msg)

        self._mac = wanted
        self._interface = interface
        self._timeout = timeout
        self._settle = settle
        self._injected = capture
        self._promiscuous = promiscuous

        self._condition = threading.Condition()
        self._found: list[str] = []
        self._last_seen: float | None = None
        self._started = 0.0
        self._finished = threading.Event()
        self._stopping = threading.Event()
        self._failure: BaseException | None = None
        self._recorded: list[str] | None = None
        self._capture: PacketCapture | None = None
        self._reader: threading.Thread | None = None
        self._entered = False

    @property
    def mac(self) -> str:
        """The hardware address being watched for, canonicalised."""

        return self._mac

    @property
    def running(self) -> bool:
        """Whether the capture is still watching."""

        return self._entered and not self._finished.is_set()

    def __enter__(self) -> DhcpSession:
        """Open the capture and begin watching.

        Returns:
            This session.

        Raises:
            RuntimeError: The session was already used. A session records one
                window; reusing it would silently blend two.
            IPScoutPermissionError: The capture needs a privilege this process
                does not have. Raised here, before the caller starts anything,
                because learning it afterwards is indistinguishable from a
                machine that never appeared.
            IPScoutUnsupportedError: This platform has no capture available,
                or the named interface does not exist.
        """

        if self._entered:
            msg = "this session has already been used; open a new one per machine you watch for"
            raise RuntimeError(msg)
        self._entered = True

        interface = self._interface if self._interface is not None else _default_interface()
        self._interface = interface
        self._capture = self._injected if self._injected is not None else _open_capture(interface, promiscuous=self._promiscuous)

        self._started = time.monotonic()
        self._reader = threading.Thread(target=self._read_until_done, name=f"ipscout-dhcp-{self._mac}", daemon=True)
        self._reader.start()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        """Stop watching and release the capture, whatever happened inside."""

        del exc_type, exc, tb
        self.stop()

    def _read_until_done(self) -> None:
        """Drain the capture until the window closes or the session stops."""

        capture = self._capture
        deadline = self._started + self._timeout
        try:
            while not self._stopping.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if capture is None:  # pragma: no cover - set before the thread starts
                    break
                frame = capture.receive(timeout=min(_POLL_TICK, remaining))
                if frame is not None:
                    self._absorb(frame)
        except BaseException as failure:
            # A capture that dies mid-window is a setup failure, so it must
            # reach the caller. It cannot be raised from here - this is
            # another thread - so it is carried to whichever call asks next.
            self._failure = failure
        finally:
            with self._condition:
                self._finished.set()
                self._condition.notify_all()

    def _absorb(self, frame: bytes) -> None:
        """Record the address a frame offers, if it offers one to this machine."""

        reply = DhcpReply.from_frame(frame)
        if reply is None or reply.client_mac != self._mac:
            return
        with self._condition:
            grown = merge_offers(self._found, [reply.offered_ip])
            if len(grown) == len(self._found):
                # A retransmission of an address already seen. It does not
                # restart the quiet window, or a chatty server would hold the
                # answer open indefinitely.
                return
            self._found = grown
            self._last_seen = time.monotonic()
            self._condition.notify_all()

    def offers(self) -> Iterator[str]:
        """Yield each newly offered address as it arrives.

        Yields:
            Each distinct address, once, in the order first seen. Ends when
            the window closes.

        Raises:
            IPScoutError: The capture failed part-way through the window.

        Note:
            This is the primitive; :meth:`result` is the wait-for-quiet
            convenience over it. Iterate this when there is a better stopping
            rule than a clock, which there usually is - "the address answers"
            is what a caller actually wants to know, and reaching it early
            costs nothing.

            Iterating does not consume the record. A second iterator replays
            what has already been yielded and then continues, and
            :meth:`result` still reports every address afterwards.
        """

        index = 0
        while True:
            with self._condition:
                while index >= len(self._found) and not self._finished.is_set():
                    self._condition.wait(_POLL_TICK)
                address = self._found[index] if index < len(self._found) else None
                index += 1
            if address is None:
                self._reraise_any_failure()
                return
            yield address

    def result(self) -> list[str]:
        """Return every address offered, blocking until the exchange is quiet.

        Returns:
            Each distinct address offered to this machine since the session
            opened, in the order first seen. Empty when nothing appeared,
            which is an answer rather than a failure: a machine that did not
            show up is a different fact from a capture that could not run, and
            only the second raises.

        Raises:
            IPScoutError: The capture failed part-way through the window. The
                addresses seen before it failed are not returned, because a
                partial list cannot be told apart from a complete one.

        Note:
            **Blocks until the exchange goes quiet, or until the window ends.**
            Quiet means ``settle`` seconds with no new address; each new one
            restarts that clock. Returning at the first offer would report
            exactly the address that did not work, because a guest that
            declines an offer takes seconds to ask again and the second answer
            is the one it keeps.

            Nothing appearing at all costs the whole ``timeout``, since only
            the whole window can establish absence.

            **The default settle is a floor on how long this takes.** Against
            a real bridge a machine's whole exchange ran 5.2 seconds while the
            settle window is 12, so the wait is dominated by the quiet period
            rather than by the handshake. If that is too slow, use
            :meth:`offers` or :func:`observe_dhcp_first_reachable`, which
            return as soon as there is an answer worth having. Do not shorten
            ``timeout`` instead: that truncates the second offer, which is the
            failure this whole design exists to prevent.

            Calling it again returns the same answer without blocking, and
            calling it after the block has exited returns what was captured
            while it was open.
        """

        if self._recorded is None:
            self._wait_for_quiet()
            with self._condition:
                self._recorded = list(self._found)
        self._reraise_any_failure()
        return list(self._recorded)

    def _wait_for_quiet(self) -> None:
        """Block until the settle window expires, or the whole window does."""

        deadline = self._started + self._timeout
        with self._condition:
            while True:
                now = time.monotonic()
                if self._finished.is_set():
                    return
                if _the_exchange_has_gone_quiet(
                    last_seen_at=self._last_seen,
                    now=now,
                    started_at=self._started,
                    timeout=self._timeout,
                    settle=self._settle,
                ):
                    return
                # Sleep exactly until the next moment the answer could change,
                # and no longer. A new address wakes this early through the
                # condition, which is what makes the window slide.
                wake = deadline if self._last_seen is None else min(deadline, self._last_seen + self._settle)
                self._condition.wait(max(0.0, wake - now))

    def stop(self) -> None:
        """Stop watching and release the capture. Safe to call more than once."""

        self._stopping.set()
        reader, self._reader = self._reader, None
        if reader is not None:
            reader.join(_JOIN_TIMEOUT)
        capture, self._capture = self._capture, None
        if capture is not None:
            # Closing twice is harmless, and a capture already torn down by a
            # failure must not turn a tidy exit into a second error.
            with contextlib.suppress(OSError):
                capture.close()
        with self._condition:
            self._finished.set()
            self._condition.notify_all()

    def _reraise_any_failure(self) -> None:
        """Re-raise, on the caller's thread, a failure the reader hit."""

        failure = self._failure
        if failure is None:
            return
        msg = f"the DHCP capture on {self._interface!r} stopped before the window ended: {failure}"
        raise IPScoutError(msg) from failure


def observe_dhcp_session(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    mac: str,
    *,
    interface: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    settle: float = DEFAULT_SETTLE,
    capture: PacketCapture | None = None,
    promiscuous: bool = True,
) -> DhcpSession:
    """Return a session that watches for addresses offered to one machine.

    Args:
        mac: The hardware address to watch for, in any common written form.
        interface: Which interface to watch. Defaults to the one carrying the
            default route, which is a guess: **name the bridge explicitly for
            a virtual machine**, because the bridge a guest boots on is
            frequently not the routed interface.
        timeout: Seconds to watch before giving up on the machine appearing.
        settle: Seconds of quiet, after the last new address, before
            :meth:`DhcpSession.result` answers. See its note.
        capture: A substitute frame source. The seam that lets the ordering,
            the timing and the teardown be tested without a real capture.
        promiscuous: Whether to put the interface into promiscuous mode. See
            :func:`observe_dhcp` for why turning this off usually means seeing
            nothing.

    Returns:
        A session that has not started yet. Entering it opens the capture.

    Raises:
        ValueError: The hardware address is not one, or the window is not a
            positive number of seconds.

    Examples:
        >>> session = observe_dhcp_session("02:00:5e:10:00:00", interface="br0")
        >>> session.mac
        '02:00:5e:10:00:00'

    """

    return DhcpSession(mac, interface=interface, timeout=timeout, settle=settle, capture=capture, promiscuous=promiscuous)


def observe_dhcp(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    mac: str,
    *,
    interface: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    settle: float = DEFAULT_SETTLE,
    capture: PacketCapture | None = None,
    promiscuous: bool = True,
) -> list[str]:
    """Return every address offered to a hardware address, in the order seen.

    Args:
        mac: The hardware address to watch for, in any common written form.
        interface: Which interface to watch. Defaults to the one carrying the
            default route; name the bridge explicitly for a virtual machine.
        timeout: Seconds to watch before giving up.
        settle: Seconds of quiet before answering.
        capture: A substitute frame source, for tests.
        promiscuous: Whether to put the interface into promiscuous mode, on by
            default. **Turning it off usually means seeing nothing.** On a
            bridge a reply is forwarded to the guest's own port and never
            reaches this host's capture unless the interface is promiscuous,
            and only a client that sets the broadcast flag is visible without
            it - which Windows does and Linux generally does not.

    Returns:
        Each distinct address offered, in the order first seen. Empty when
        nothing appeared, which is an answer rather than a failure.

    Raises:
        ValueError: The hardware address is not one.
        IPScoutPermissionError: Capturing needs a privilege this process does
            not have.
        IPScoutUnsupportedError: This platform cannot capture, or the named
            interface does not exist.
        IPScoutError: The capture stopped part-way through the window.

    Note:
        **The address the machine most likely settled on is the last element,
        not the first.** A pool that hands out an address the guest declines
        offers the working one afterwards, so the order is chronological
        rather than by preference. Check them rather than assuming, which
        :func:`observe_dhcp_first_reachable` does for you.

        This begins capturing when it is called, so it only sees a handshake
        that has not happened yet. To watch for one you are about to cause,
        use :func:`observe_dhcp_session` and start the machine inside it.

    Examples:
        >>> observe_dhcp("02:00:5e:10:00:00", interface="lo", timeout=0.2, settle=0.05)
        []

    """

    with observe_dhcp_session(
        mac,
        interface=interface,
        timeout=timeout,
        settle=settle,
        capture=capture,
        promiscuous=promiscuous,
    ) as session:
        return session.result()


def observe_dhcp_first_reachable(  # noqa: PLR0913 - public API: every knob is keyword-only and independently useful
    mac: str,
    *,
    interface: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    tcp_port: int = 22,
    probe_timeout: float = 2.0,
    capture: PacketCapture | None = None,
    promiscuous: bool = True,
) -> str | None:
    """Return the first offered address that answers, or None if none does.

    Args:
        mac: The hardware address to watch for.
        interface: Which interface to watch.
        timeout: Seconds to watch before giving up.
        tcp_port: Port to try when ICMP does not answer. Defaults to 22 rather
            than this package's usual 443 because a machine thirty seconds
            into its boot is far likelier to have SSH up than HTTPS.
        probe_timeout: Seconds to spend on each candidate.
        capture: A substitute frame source, for tests.
        promiscuous: Whether to put the interface into promiscuous mode.

    Returns:
        The first address that answered, or ``None`` when none did -
        including when nothing was offered at all. Both are the same practical
        fact, "no usable address", and neither is an error.

    Raises:
        ValueError: The hardware address is not one.
        IPScoutPermissionError: Capturing needs a privilege this process lacks.
        IPScoutUnsupportedError: This platform cannot capture.
        IPScoutError: The capture stopped part-way through the window.

    Note:
        Consumes the stream rather than the finished list, so it returns as
        soon as a candidate answers instead of waiting out the quiet window.
        Reachability is asked through :func:`ipscout.is_reachable`, which
        never raises and falls back to TCP, because a machine that is up early
        in its boot routinely answers a port while still ignoring ICMP.

    Examples:
        >>> observe_dhcp_first_reachable("02:00:5e:10:00:00", interface="lo",
        ...                              timeout=0.2) is None
        True

    """

    with observe_dhcp_session(
        mac,
        interface=interface,
        timeout=timeout,
        settle=timeout,
        capture=capture,
        promiscuous=promiscuous,
    ) as session:
        for address in session.offers():
            if is_reachable(address, timeout=probe_timeout, tcp_port=tcp_port):
                return address
    return None


def dhcp_capture_available() -> bool:
    """Return whether this host can capture DHCP traffic at all.

    Returns:
        Whether a capture could be opened right now. False on a platform with
        no backend, and false when the privilege is missing.

    Note:
        Asks rather than provoking an exception, the same shape as
        :func:`ipscout.icmp_available`. A caller deciding whether to offer the
        feature wants a boolean, not a traceback.

    Examples:
        >>> isinstance(dhcp_capture_available(), bool)
        True

    """

    if not _IS_LINUX:
        return False
    from .dhcp_linux import capture_available  # noqa: PLC0415 - Linux-only import

    return capture_available()


def _default_interface() -> str:
    """Return the interface carrying the default route, or refuse to guess."""

    route = default_gateway()
    if route is None or route.interface is None:
        msg = "no default route to take an interface from, so there is nothing to watch; name one with interface="
        raise IPScoutUnsupportedError(msg)
    return route.interface


def _open_capture(interface: str, *, promiscuous: bool = True, platform: str = sys.platform) -> PacketCapture:
    """Return a capture on one interface, or say why this host cannot.

    The platform is a parameter rather than read from ``sys.platform`` inside,
    so the refusals other operating systems get can be exercised from the one
    running the tests.
    """

    if platform.startswith("linux"):
        from .dhcp_linux import open_capture  # noqa: PLC0415 - Linux-only import

        return open_capture(interface, promiscuous=promiscuous)
    if platform == "darwin":
        msg = (
            "observing DHCP is not implemented on macOS yet. The mechanism exists - BPF, through "
            "/dev/bpf, which this package already uses to resolve neighbours - but it is unmeasured "
            "here, and shipping an untested capture would report a machine that booted fine as one "
            "that never appeared. Read this host's own lease with subnet_info() instead, which needs "
            "nothing but only describes this host, or watch from the Linux host owning the bridge"
        )
        raise IPScoutUnsupportedError(msg)
    if platform == "win32":
        msg = (
            "observing DHCP is not implemented on Windows yet. A driver-free path exists - a raw "
            "socket in SIO_RCVALL promiscuous mode, needing Administrator - but it sees only what "
            "this host's own interface sees, which on a Hyper-V switch excludes other guests' "
            "traffic unless port mirroring is configured. Read this host's own lease with "
            "subnet_info() instead, or watch from the Linux host owning the bridge"
        )
        raise IPScoutUnsupportedError(msg)
    msg = f"observing DHCP needs a link-layer capture, and this package has no backend for {platform!r}"
    raise IPScoutUnsupportedError(msg)
