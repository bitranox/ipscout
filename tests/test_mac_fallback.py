"""lookup_mac's fallback from an active resolution to the cache, and the method it reports.

The rule under test: an active lookup falls back to the cache only when this
host CANNOT ask (no privilege, no path that can carry the request), and the
record says which one answered. An active ask that nobody answered is an
answer in its own right and is never replaced by a cache entry, and a
caller's mistake still raises.
"""

from __future__ import annotations

import json
import socket
import sys

import pytest

import ipscout
from ipscout.cli import EXIT_ERROR, EXIT_NOT_REACHED, main
from ipscout.errors import IPScoutPermissionError, IPScoutResolutionError, IPScoutUnsupportedError
from ipscout.models import MacLookup, MacMethod, MacScope
from ipscout.neighbours import ask_or_read_cache

_ACTIVE_MISS = MacLookup(ip="192.0.2.7", scope=MacScope.UNKNOWN, method=MacMethod.ACTIVE)
_CACHED_HIT = MacLookup(ip="192.0.2.7", mac="00:00:5e:00:53:07", scope=MacScope.DIRECT, method=MacMethod.CACHE)


def _loopback_name() -> str:
    """Return this host's loopback interface name (``lo`` on Linux, ``lo0`` on macOS)."""

    return next(name for _index, name in socket.if_nameindex() if name.startswith("lo"))


def _raising(error: Exception) -> MacLookup:
    raise error


# --------------------------------------------------------------------------
# The rule itself, through its two lookups as parameters
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_an_active_miss_is_the_answer_and_the_cache_is_never_read() -> None:
    def read_cache() -> MacLookup:
        pytest.fail("the cache was read after an active ask had answered")

    assert ask_or_read_cache(lambda: _ACTIVE_MISS, read_cache, fall_back=True) is _ACTIVE_MISS


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "cannot_ask",
    [IPScoutPermissionError("active ARP needs a raw socket"), IPScoutUnsupportedError("lo has no hardware address")],
    ids=["no-privilege", "no-path"],
)
def test_a_host_that_cannot_ask_reads_the_cache_instead(cannot_ask: Exception) -> None:
    assert ask_or_read_cache(lambda: _raising(cannot_ask), lambda: _CACHED_HIT, fall_back=True) is _CACHED_HIT


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "mistake",
    [IPScoutResolutionError("no interface named 'nosuchif0'"), ValueError("not an IP address literal")],
    ids=["unknown-zone", "not-a-literal"],
)
def test_a_callers_mistake_still_raises_with_fallback_on(mistake: Exception) -> None:
    with pytest.raises(type(mistake)):
        ask_or_read_cache(lambda: _raising(mistake), lambda: _CACHED_HIT, fall_back=True)


@pytest.mark.os_agnostic
def test_without_fallback_a_host_that_cannot_ask_still_raises() -> None:
    with pytest.raises(IPScoutPermissionError):
        ask_or_read_cache(lambda: _raising(IPScoutPermissionError("no raw socket")), lambda: _CACHED_HIT, fall_back=False)


# --------------------------------------------------------------------------
# lookup_mac on this real host
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_passive_lookup_says_the_cache_answered() -> None:
    assert ipscout.lookup_mac("203.0.113.199").method is MacMethod.CACHE


@pytest.mark.os_agnostic
def test_fallback_without_an_active_ask_is_refused() -> None:
    with pytest.raises(ValueError, match=r"^fallback_to_cache=True needs active=True"):
        ipscout.lookup_mac("192.0.2.7", fallback_to_cache=True)


@pytest.mark.os_agnostic
def test_get_mac_address_refuses_the_same_combination() -> None:
    with pytest.raises(ValueError, match=r"^fallback_to_cache=True needs active=True"):
        ipscout.get_mac_address("192.0.2.7", fallback_to_cache=True)


@pytest.mark.os_posix
def test_an_interface_that_cannot_carry_a_request_falls_back_to_the_cache() -> None:
    answer = ipscout.lookup_mac(f"fe80::1%{_loopback_name()}", active=True, fallback_to_cache=True)

    assert answer.method is MacMethod.CACHE
    assert answer.scope is MacScope.UNKNOWN


@pytest.mark.os_posix
def test_a_zone_naming_no_interface_still_raises_with_fallback_on() -> None:
    with pytest.raises(IPScoutResolutionError, match=r"no interface named 'nosuchif0'"):
        ipscout.lookup_mac("fe80::1%nosuchif0", active=True, fallback_to_cache=True)


@pytest.mark.os_agnostic
def test_a_host_name_still_raises_with_fallback_on() -> None:
    with pytest.raises(ValueError, match=r"not an IP address literal"):
        ipscout.lookup_mac("printer.example", active=True, fallback_to_cache=True)


@pytest.mark.os_agnostic
def test_an_unprivileged_host_answers_a_known_neighbour_from_the_cache() -> None:
    if sys.platform == "win32":
        pytest.skip("Windows resolves IPv4 actively without privilege, so nothing falls back")
    entries = ipscout.neighbours()
    if not entries:
        pytest.skip("this host's neighbour cache is empty")
    known = entries[0].ip
    try:
        ipscout.lookup_mac(known, active=True)
    except IPScoutPermissionError:
        pass
    else:
        pytest.skip("this process may send raw frames, so the active ask succeeds and nothing falls back")

    answer = ipscout.lookup_mac(known, active=True, fallback_to_cache=True)

    assert answer.method is MacMethod.CACHE
    assert answer.mac == ipscout.lookup_mac(known).mac


# --------------------------------------------------------------------------
# The CLI
# --------------------------------------------------------------------------


@pytest.mark.os_posix
@pytest.mark.parametrize("strict", [False, True], ids=["lookup", "strict"])
def test_the_mac_command_reports_which_method_answered(strict: bool, capsys: pytest.CaptureFixture[str]) -> None:
    args = ["--json", "mac", f"fe80::1%{_loopback_name()}", "--active", "--fallback-to-cache"]
    code = main([*args, "--strict"] if strict else args)

    assert json.loads(capsys.readouterr().out)["data"]["method"] == "cache"
    assert code == EXIT_NOT_REACHED


@pytest.mark.os_agnostic
def test_the_mac_command_refuses_fallback_without_active(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--json", "mac", "192.0.2.7", "--fallback-to-cache"])

    assert code == EXIT_ERROR
    assert "--fallback-to-cache needs --active" in json.loads(capsys.readouterr().out)["error"]["message"]


# --------------------------------------------------------------------------
# A real active answer: Windows resolves IPv4 unprivileged (SendARP)
# --------------------------------------------------------------------------


def _windows_gateway() -> str:
    route = ipscout.default_gateway()
    if route is None or not route.gateway:
        pytest.skip("this host has no IPv4 default gateway to ask for")
    return route.gateway


@pytest.mark.os_windows
@pytest.mark.skipif(sys.platform != "win32", reason="only Windows asks actively without privilege")
def test_an_on_link_active_answer_says_it_was_asked() -> None:
    answer = ipscout.lookup_mac(_windows_gateway(), active=True, fallback_to_cache=True)

    assert answer.method is MacMethod.ACTIVE
    assert answer.scope in {MacScope.DIRECT, MacScope.UNKNOWN}


@pytest.mark.os_windows
@pytest.mark.skipif(sys.platform != "win32", reason="only Windows asks actively without privilege")
def test_a_routed_active_answer_says_it_was_asked() -> None:
    _windows_gateway()
    answer = ipscout.lookup_mac("203.0.113.199", active=True, fallback_to_cache=True)

    assert answer.method is MacMethod.ACTIVE
    assert answer.scope is MacScope.NEXT_HOP


@pytest.mark.os_windows
@pytest.mark.skipif(sys.platform != "win32", reason="only Windows asks actively without privilege")
def test_strict_keeps_the_method_of_a_routed_active_answer(capsys: pytest.CaptureFixture[str]) -> None:
    _windows_gateway()
    code = main(["--json", "mac", "203.0.113.199", "--active", "--strict"])
    data = json.loads(capsys.readouterr().out)["data"]

    assert (data["method"], data["scope"], data["mac"]) == ("active", "unknown", None)
    assert code == EXIT_NOT_REACHED
