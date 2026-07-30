"""CLI stories: the JSON contract, the exit codes, and the human rendering.

The JSON surface is asserted as a contract rather than by matching strings, so
these keep their meaning when any message is reworded.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import ipaddress
import json
from typing import Any

import pytest
from click.testing import CliRunner

import ipscout
from ipscout import cli as cli_module
from ipscout.cli import EXIT_ERROR, EXIT_NOT_REACHED, EXIT_OK, cli, main

pytestmark = pytest.mark.os_agnostic

#: RFC 6761 reserves .invalid so it never resolves; RFC 5737 reserves TEST-NET-3.
NEVER_RESOLVES = "nothing.invalid"
NEVER_ANSWERS = "203.0.113.1"

#: Every command, with arguments that work offline or against loopback. The
#: sweeps below run all of them, so a command added without routing through the
#: shared _emit helper fails the suite instead of quietly ignoring --json.
ALL_COMMANDS: list[list[str]] = [
    ["ping", "127.0.0.1", "-c", "1", "--interval", "0"],
    ["ping-many", "127.0.0.1", "-c", "1"],
    ["reachable", "127.0.0.1"],
    ["traceroute", "127.0.0.1", "--max-hops", "2", "--timeout", "1"],
    ["resolve", "localhost"],
    ["reverse-dns", "127.0.0.1"],
    ["interfaces"],
    ["gateway"],
    ["neighbours"],
    ["mac", "127.0.0.1"],
    ["find-ip", "aa:bb:cc:dd:ee:ff"],
    ["arp-scan", "--network", "127.0.0.0/30"],
    ["subnet"],
    ["scan-ports", "127.0.0.1", "--ports", "1", "--timeout", "0.3"],
    ["mtu", "127.0.0.1"],
    ["wake", "aa:bb:cc:dd:ee:ff", "--broadcast", "127.0.0.1"],
    ["capabilities"],
    ["info"],
]


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _invoke(runner: CliRunner, args: list[str]) -> Any:
    return runner.invoke(cli, args, standalone_mode=False)


def _traceroute_supported() -> bool:
    """Return whether this host can observe expired hops.

    Asked of the CLI's own ``capabilities`` command rather than of
    ``sys.platform``, because that is what the library itself acts on: setting
    a hop limit and observing its expiry come apart on macOS, so a platform
    name is the wrong thing to branch on.
    """

    result = CliRunner().invoke(cli, ["--json", "capabilities"], standalone_mode=False)
    return bool(json.loads(result.output)["data"]["traceroute"])


def _skip_what_this_host_cannot_do(args: list[str]) -> None:
    """Skip a command this host is not equipped to run.

    Two distinct reasons, and they are not the same thing: ICMP may be
    forbidden outright, or it may work while the platform still refuses to
    surface Time Exceeded to an unprivileged process. Reporting either as a
    test failure would dress a documented platform limit up as a defect.
    """

    if args[0] in {"ping", "ping-many", "traceroute", "arp-scan"} and not ipscout.icmp_available():
        pytest.skip("unprivileged ICMP unavailable on this host")
    if args[0] == "traceroute" and not _traceroute_supported():
        pytest.skip("this platform does not surface ICMP Time Exceeded to an unprivileged process")


@pytest.mark.parametrize("args", ALL_COMMANDS, ids=lambda a: a[0])
def test_every_command_emits_a_valid_json_envelope(runner: CliRunner, args: list[str]) -> None:
    _skip_what_this_host_cannot_do(args)

    payload = json.loads(_invoke(runner, ["--json", *args]).output)

    assert payload["ok"] is True, payload
    assert payload["command"] == args[0]
    assert "data" in payload


@pytest.mark.parametrize("args", ALL_COMMANDS, ids=lambda a: a[0])
def test_every_command_also_renders_for_a_human(runner: CliRunner, args: list[str]) -> None:
    _skip_what_this_host_cannot_do(args)

    output = _invoke(runner, args).output

    assert output.strip()
    with pytest.raises(json.JSONDecodeError):
        json.loads(output)


@pytest.mark.parametrize("args", ALL_COMMANDS, ids=lambda a: a[0])
def test_bare_mode_drops_the_envelope(runner: CliRunner, args: list[str]) -> None:
    _skip_what_this_host_cannot_do(args)

    payload = json.loads(_invoke(runner, ["--json-bare", *args]).output)

    if isinstance(payload, dict):
        assert "ok" not in payload
        assert "command" not in payload


def test_the_two_output_shapes_are_mutually_exclusive(runner: CliRunner) -> None:
    # A silent precedence rule would leave a caller parsing a shape they never
    # asked for, so saying both is a mistake worth reporting.
    assert _invoke(runner, ["--json", "--json-bare", "info"]).exit_code != EXIT_OK


def test_a_failure_is_serialised_as_data_not_a_traceback(runner: CliRunner) -> None:
    result = _invoke(runner, ["--json", "ping", NEVER_RESOLVES])
    payload = json.loads(result.output)

    assert payload["ok"] is False
    assert payload["command"] == "ping"
    assert payload["error"]["type"] == "IPScoutResolutionError"
    assert NEVER_RESOLVES in payload["error"]["message"]
    assert "Traceback" not in result.output


def test_a_failure_in_bare_mode_is_still_json() -> None:
    # Bare mode promised the payload at top level, and a caller piping it into
    # jq gets that on every success. A line of prose on the one path that
    # matters most breaks the pipeline exactly when it is reporting a problem.
    import contextlib
    import io

    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        code = main(["--json-bare", "ping", NEVER_RESOLVES])
    payload = json.loads(stream.getvalue())

    assert code == EXIT_ERROR
    assert payload["type"] == "IPScoutResolutionError"
    assert NEVER_RESOLVES in payload["message"]
    assert "ok" not in payload, "bare mode drops the envelope on failure too"


@pytest.mark.parametrize(("bare", "envelope"), [(True, False), (False, True)])
def test_an_escaping_failure_keeps_the_shape_that_was_asked_for(*, bare: bool, envelope: bool, capsys: pytest.CaptureFixture[str]) -> None:
    # Anything getting past a command's own guard is reported by main()'s
    # handler, which reads the shape from argv because there may be no Click
    # context left to ask. Bare mode used to fall through to the envelope here.
    cli_module._exception_handler(as_json=True, bare=bare)(RuntimeError("boom"))
    payload = json.loads(capsys.readouterr().out)

    assert ("ok" in payload) is envelope
    assert "boom" in json.dumps(payload)


def test_a_human_failure_does_not_name_a_python_class(runner: CliRunner) -> None:
    # The message already names the remedy. Prefixing it with the exception
    # type puts an implementation detail in a sentence written for a person.
    output = _invoke(runner, ["find-ip", "nonsense"]).output

    assert "not a hardware address" in output
    assert "ValueError" not in output
    assert "IPScout" not in output


def test_a_refused_sweep_reports_the_uncovered_network_as_data(runner: CliRunner) -> None:
    # A reader must be able to tell full coverage from partial without parsing
    # the message. Nothing is swept here, so no probe leaves the host.
    payload = json.loads(_invoke(runner, ["--json", "arp-scan", "--network", "172.17.0.0/16"]).output)

    assert payload["ok"] is False
    assert payload["command"] == "arp-scan"
    assert payload["error"]["type"] == "IPScoutSweepTooWideError"
    assert payload["skipped"] == ["172.17.0.0/16"]


def test_a_covered_sweep_reports_nothing_skipped(runner: CliRunner) -> None:
    if not ipscout.icmp_available():
        pytest.skip("unprivileged ICMP unavailable on this host")

    payload = json.loads(_invoke(runner, ["--json", "arp-scan", "--network", "127.0.0.0/30"]).output)

    assert payload["ok"] is True
    assert payload["skipped"] == []


def test_a_skipped_network_is_noted_on_stderr_never_in_the_parsed_stream(capsys: pytest.CaptureFixture[str]) -> None:
    # stdout is what a caller parses, so a note about coverage cannot go there
    # even in human mode, where it would still precede a table.
    cli_module._note_skipped((ipaddress.IPv4Network("172.17.0.0/16"),))
    captured = capsys.readouterr()

    assert "172.17.0.0/16" in captured.err
    assert captured.out == ""


def test_a_find_that_swept_reports_its_own_coverage(runner: CliRunner) -> None:
    # The address list cannot say whether a network went unprobed, so the
    # report carries the scope: this is what survives --json-bare, where there
    # is no envelope to hold it.
    if not ipscout.icmp_available():
        pytest.skip("unprivileged ICMP unavailable on this host")

    payload = json.loads(_invoke(runner, ["--json-bare", "find-ip", "--scan", "--network", "127.0.0.0/30", "aa:bb:cc:dd:ee:ff"]).output)

    assert payload["scope"]["networks"] == ["127.0.0.0/30"]
    assert payload["scope"]["complete"] is True


def test_a_find_that_only_read_the_cache_claims_no_coverage(runner: CliRunner) -> None:
    # No sweep means nothing to report about coverage, which is different from
    # reporting complete coverage.
    payload = json.loads(_invoke(runner, ["--json-bare", "find-ip", "aa:bb:cc:dd:ee:ff"]).output)

    assert payload["scope"] is None


def test_enums_are_serialised_as_their_values(runner: CliRunner) -> None:
    # json.dumps(asdict(result)) raises outright on these two fields.
    if not ipscout.icmp_available():
        pytest.skip("unprivileged ICMP unavailable on this host")

    data = json.loads(_invoke(runner, ["--json", "ping", "127.0.0.1", "-c", "1", "--interval", "0"]).output)["data"]

    assert data["family"] == "ipv4"
    assert data["method"] == "icmp"


@pytest.mark.parametrize(
    "computed",
    ["str_result", "n_packets_lost", "packets_lost_percentage", "time_min_ms", "time_avg_ms", "time_max_ms", "jitter_ms"],
)
def test_computed_fields_survive_into_the_payload(runner: CliRunner, computed: str) -> None:
    # Each of these is a property, so dataclasses.asdict drops it: the payload
    # would look complete while missing the average round trip and the loss
    # percentage, which are the two numbers a caller most wants.
    if not ipscout.icmp_available():
        pytest.skip("unprivileged ICMP unavailable on this host")

    data = json.loads(_invoke(runner, ["--json", "ping", "127.0.0.1", "-c", "2", "--interval", "0"]).output)["data"]

    assert computed in data


def test_reaching_a_host_exits_zero() -> None:
    if not ipscout.icmp_available():
        pytest.skip("unprivileged ICMP unavailable on this host")

    assert main(["ping", "127.0.0.1", "-c", "1", "--interval", "0"]) == EXIT_OK


def test_a_silent_host_exits_one_rather_than_zero() -> None:
    # Click returns ctx.exit()'s code instead of raising it when standalone
    # mode is off, so anything that drops that value collapses every outcome
    # into success. That is what the lib_cli_exit_tools>=2.3.4 floor buys.
    if not ipscout.icmp_available():
        pytest.skip("unprivileged ICMP unavailable on this host")

    assert main(["ping", NEVER_ANSWERS, "-c", "1", "--timeout", "1", "--interval", "0"]) == EXIT_NOT_REACHED


def test_an_error_exits_two_distinctly_from_not_reached() -> None:
    assert main(["ping", NEVER_RESOLVES]) == EXIT_ERROR
    assert main(["--json", "ping", NEVER_RESOLVES]) == EXIT_ERROR


def test_a_missing_ptr_record_exits_one() -> None:
    assert main(["reverse-dns", NEVER_ANSWERS]) == EXIT_NOT_REACHED


def test_the_family_flags_are_mutually_exclusive(runner: CliRunner) -> None:
    assert _invoke(runner, ["resolve", "localhost", "-4", "-6"]).exit_code != EXIT_OK


def test_forcing_a_family_the_target_lacks_is_reported_as_an_error(runner: CliRunner) -> None:
    payload = json.loads(_invoke(runner, ["--json", "resolve", "127.0.0.1", "-6"]).output)

    assert payload["ok"] is False
    assert payload["error"]["type"] == "IPScoutResolutionError"


def test_interfaces_renders_addresses_as_address_slash_prefix(runner: CliRunner) -> None:
    # The sweep above only asserts that a command prints something that is not
    # JSON, so a table can be populated with the wrong thing and still pass.
    # InterfaceAddress is a model, and iterating a model yields (name, value)
    # pairs, so unpacking one as a 2-tuple silently renders the field NAMES.
    output = _invoke(runner, ["interfaces"]).output

    assert "127.0.0.1/8" in output, output
    assert "'address'" not in output, output


def test_capabilities_answers_with_a_boolean_per_capability(runner: CliRunner) -> None:
    data = json.loads(_invoke(runner, ["--json", "capabilities"]).output)["data"]

    assert set(data) == {"icmp_ipv4", "icmp_ipv6", "traceroute"}
    assert all(isinstance(value, bool) for value in data.values())


def test_interfaces_json_names_the_address_fields(runner: CliRunner) -> None:
    # An (address, prefix) tuple would serialise as a bare two-element array
    # whose ordering the reader has to already know.
    data = json.loads(_invoke(runner, ["--json", "interfaces"]).output)["data"]

    assert data
    for entry in data:
        for address in (*entry["ipv4"], *entry["ipv6"]):
            assert set(address) == {"address", "prefix_len"}


def test_the_bare_group_shows_help(runner: CliRunner) -> None:
    result = _invoke(runner, [])

    assert "Commands" in result.output
    assert result.exit_code == EXIT_OK


def test_the_version_flag_reports_the_package_version(runner: CliRunner) -> None:
    from ipscout import __init__conf__

    assert __init__conf__.version in _invoke(runner, ["--version"]).output
