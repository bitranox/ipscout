"""Shared pytest fixtures for CLI and module-entry tests."""

from __future__ import annotations

import os
import re
import sys
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

if TYPE_CHECKING:
    from collections.abc import Callable

ANSI_ESCAPE_PATTERN = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _remove_ansi_codes(text: str) -> str:
    """Return text stripped of ANSI escape sequences.

    Tests compare human-readable CLI output; stripping colour codes keeps
    assertions stable across environments.

    Args:
        text: Raw string captured from CLI output.

    Returns:
        The string without ANSI escape sequences.

    """
    return ANSI_ESCAPE_PATTERN.sub("", text)


@pytest.fixture
def cli_runner() -> CliRunner:
    """Provide a fresh CliRunner per test."""
    return CliRunner()


@pytest.fixture
def strip_ansi() -> Callable[[str], str]:
    """Return a helper that strips ANSI escape sequences from a string."""
    return _remove_ansi_codes


#: Which platforms each ``os_*`` marker lets a test run on. Registering a marker in pyproject only
#: silences pytest's unknown-marker warning; without this table a marked test runs everywhere.
_PLATFORM_MARKERS: dict[str, Callable[[str], bool]] = {
    "os_windows": lambda platform: platform == "win32",
    "os_macos": lambda platform: platform == "darwin",
    "os_linux": lambda platform: platform.startswith("linux"),
    "os_posix": lambda platform: platform != "win32",
}


#: Opt-in switch for tests that change this host's network state. Opt-in rather than gated on
#: privilege: the windows-latest runner is elevated, and a test that writes the neighbour table there
#: would run on every push without anybody having asked for it.
HOST_WRITE_OPT_IN = "IPSCOUT_HOST_WRITE_TESTS"


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Skip a test whose ``os_*`` marker names another platform, or a host-mutating test not opted into."""
    for name, runs_on in _PLATFORM_MARKERS.items():
        if item.get_closest_marker(name) is not None and not runs_on(sys.platform):
            pytest.skip(f"marked {name}; this is {sys.platform}")
    if item.get_closest_marker("host_mutating") is not None and os.environ.get(HOST_WRITE_OPT_IN) != "1":
        pytest.skip(f"changes this host's network state; set {HOST_WRITE_OPT_IN}=1 and run with the privilege it needs")
