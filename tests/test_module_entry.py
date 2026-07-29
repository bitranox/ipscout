"""Module-entry stories: ``python -m ipscout`` must behave exactly like the script."""

from __future__ import annotations

import runpy
import sys

import pytest

from ipscout import cli as cli_mod

pytestmark = pytest.mark.os_agnostic

NEVER_RESOLVES = "nothing.invalid"


def _run_module(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    """Run ``python -m ipscout`` with ``argv`` and return its exit code."""

    monkeypatch.setattr(sys, "argv", ["ipscout", *argv], raising=False)
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("ipscout.__main__", run_name="__main__")
    code = exit_info.value.code
    return code if isinstance(code, int) else 0


def test_a_successful_command_exits_zero_through_the_module_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _run_module(monkeypatch, ["resolve", "localhost"]) == 0


def test_an_error_exits_non_zero_through_the_module_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _run_module(monkeypatch, ["resolve", NEVER_RESOLVES]) != 0


def test_the_module_entry_honours_the_json_flag(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    import json

    _run_module(monkeypatch, ["--json", "resolve", "localhost"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["command"] == "resolve"


def test_the_module_entry_reports_a_failure_as_json_too(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    import json

    code = _run_module(monkeypatch, ["--json", "resolve", NEVER_RESOLVES])

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert code != 0


def test_the_cli_group_is_importable_under_its_name() -> None:
    assert cli_mod.cli.name is not None
