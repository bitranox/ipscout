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

from ipscout.dhcp import dhcp_capture_available
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
#: Modules whose doctests can only run on one platform, matched on the node id
#: rather than on the example source. Naming the module is exact, where source
#: scanning would have to guess which calls are portable.
_POSIX_ONLY_MODULES = ("transport_posix.py", "interfaces_posix.py")
# winapi.py is deliberately absent: its address and status helpers are pure
# byte manipulation that runs anywhere, and that portability is what lets the
# Windows encoding be verified from Linux. Only its DLL loading is Windows-only,
# and that is guarded inside the function.
_WINDOWS_ONLY_MODULES = ("transport_windows.py", "interfaces_windows.py")

_NEEDS_ICMP = (
    "ping(",
    "aping(",
    "ping_many(",
    "aping_many(",
    "PosixEchoTransport(",
    "AsyncPosixEchoTransport(",
    "WindowsEchoTransport(",
)

#: Call fragments that open a link-layer capture, which needs root or
#: CAP_NET_RAW. ``dhcp_capture_available(`` is deliberately absent: answering
#: "no" is exactly what it is for, so its example runs everywhere.
_NEEDS_CAPTURE = (
    "observe_dhcp(",
    "observe_dhcp_first_reachable(",
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


def _skip_foreign_platform_doctests(items: list[pytest.Item]) -> None:
    """Skip doctests in a backend that cannot execute on this platform.

    ``getifaddrs`` does not exist on Windows and ``iphlpapi`` does not exist
    anywhere else, so those modules' examples are real but unrunnable off their
    own platform.
    """

    if sys.platform == "win32":
        foreign, reason = _POSIX_ONLY_MODULES, "POSIX-only backend; Windows uses iphlpapi"
    else:
        foreign, reason = _WINDOWS_ONLY_MODULES, "Windows-only backend; this platform uses the POSIX APIs"

    skip = pytest.mark.skip(reason=f"doctest lives in a {reason}")
    for item in items:
        if _doctest_source(item) and any(module in item.nodeid for module in foreign):
            item.add_marker(skip)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip doctests that need ICMP when this machine cannot provide it.

    Args:
        items: The collected test items, modified in place.

    Note:
        Availability is probed once per session rather than per item, because
        opening a socket per doctest to answer the same question would be
        wasteful and could itself hit a descriptor limit.

    """

    _skip_foreign_platform_doctests(items)
    _skip_capture_doctests(items)

    candidates = [item for item in items if any(marker in _doctest_source(item) for marker in _NEEDS_ICMP)]
    if not candidates or _icmp_available():
        return

    skip = pytest.mark.skip(
        reason='unprivileged ICMP unavailable on this host (set net.ipv4.ping_group_range="0 2147483647", or grant CAP_NET_RAW); the doctest sends a real echo'
    )
    for item in candidates:
        item.add_marker(skip)


def _skip_capture_doctests(items: list[pytest.Item]) -> None:
    """Skip doctests that open a capture when this host may not open one."""

    candidates = [item for item in items if any(marker in _doctest_source(item) for marker in _NEEDS_CAPTURE)]
    if not candidates or dhcp_capture_available():
        return

    skip = pytest.mark.skip(reason="capturing DHCP needs root or CAP_NET_RAW here; the doctest opens a real link-layer socket")
    for item in candidates:
        item.add_marker(skip)
