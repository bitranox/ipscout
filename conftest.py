"""Root pytest configuration governing doctest collection.

Exists for one reason: the docstring examples in this package are real, and
several of them genuinely send ICMP echoes. That is deliberate - an example
that only pretends to probe would not be worth reading - but it means those
examples cannot run where unprivileged ICMP is unavailable.

That is not a hypothetical. GitHub Actions runners ship with
``net.ipv4.ping_group_range`` locked down, so ``SOCK_DGRAM``/``IPPROTO_ICMP``
fails with ``EACCES`` and the raw fallback with ``EPERM``. Loopback does not
help: the restriction is on opening the socket, not on the destination.

So the ICMP-dependent doctests are skipped with an explicit reason wherever the
capability is missing, exactly as the integration tests already do. Everywhere
the capability exists - any normal developer machine - they run for real.

Note:
    Which doctests need ICMP is derived from their own source rather than kept
    in a hand-maintained list, so an example added later is covered
    automatically instead of turning CI red the first time it runs somewhere
    hardened.

"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import pytest

from ipscout.factory import icmp_available

if TYPE_CHECKING:
    from collections.abc import Iterable

#: Keep this file out of doctest collection. ``--doctest-modules`` would
#: otherwise import it as a test module and collide with ``tests/conftest.py``,
#: which shares its basename, producing an "import file mismatch" collection
#: error before a single test runs.
collect_ignore = ["conftest.py"]

#: Call fragments that put an ICMP echo on the wire. ``is_reachable`` is
#: deliberately absent: it falls back to TCP and stays truthful without ICMP.
_POSIX_ONLY = (
    "PosixEchoTransport(",
    "AsyncPosixEchoTransport(",
)

_NEEDS_ICMP = (
    "ping(",
    "aping(",
    "ping_many(",
    "aping_many(",
    "PosixEchoTransport(",
    "AsyncPosixEchoTransport(",
    "WindowsEchoTransport(",
)


def _doctest_source(item: pytest.Item) -> str:
    """Return the concatenated source of a doctest item, or "" for other items."""

    test = getattr(item, "dtest", None)
    if test is None:
        return ""
    examples: Iterable[object] = getattr(test, "examples", ())
    return "".join(str(getattr(example, "source", "")) for example in examples)


def _icmp_available() -> bool:
    """Return whether an ICMP echo can be sent from this process."""

    return icmp_available()


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip doctests that need ICMP when this machine cannot provide it.

    Args:
        items: The collected test items, modified in place.

    Note:
        Availability is probed once per session rather than per item, because
        opening a socket per doctest to answer the same question would be
        wasteful and could itself hit a descriptor limit.

    """

    if sys.platform == "win32":
        # These construct a POSIX ICMP socket directly, which does not exist on
        # Windows however available ICMP itself is through iphlpapi.
        posix_only = pytest.mark.skip(reason="the doctest drives a POSIX ICMP socket, which Windows does not have")
        for item in items:
            if any(marker in _doctest_source(item) for marker in _POSIX_ONLY):
                item.add_marker(posix_only)

    candidates = [item for item in items if any(marker in _doctest_source(item) for marker in _NEEDS_ICMP)]
    if not candidates or _icmp_available():
        return

    skip = pytest.mark.skip(
        reason='unprivileged ICMP unavailable on this host (set net.ipv4.ping_group_range="0 2147483647", or grant CAP_NET_RAW); the doctest sends a real echo'
    )
    for item in candidates:
        item.add_marker(skip)
