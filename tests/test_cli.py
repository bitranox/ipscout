"""CLI stories: the JSON contract, the exit codes, and the human rendering.

The JSON surface is asserted as a contract rather than by matching strings, so
these keep their meaning when any message is reworded.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import socket
import threading
from typing import Any

import pytest
from capture_support import capture_interface
from click import UsageError
from click.testing import CliRunner
from snmp_agent import DESCRIPTION, SYSTEM, FakeAgent, honest

import ipscout
from ipscout import cli as cli_module
from ipscout.cli import EXIT_ERROR, EXIT_NOT_REACHED, EXIT_OK, CliContext, OutputMode, cli, main
from ipscout.snmpber import OCTET_STRING

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
    # set-neighbour is absent: its success path needs privilege. Its three
    # failure shapes are pinned in test_static_neighbours.py instead. Removing
    # an entry nobody holds reads the cache only, so it runs anywhere.
    ["remove-neighbour", "192.0.2.254"],
    ["subnet"],
    ["scan-ports", "127.0.0.1", "--ports", "1", "--timeout", "0.3"],
    ["banners", "127.0.0.1", "--port", "1", "--timeout", "0.3"],
    ["snmp-system", "127.0.0.1", "--timeout", "0.3"],
    ["mtu", "127.0.0.1"],
    ["wake", "aa:bb:cc:dd:ee:ff", "--broadcast", "127.0.0.1"],
    # A window short enough not to slow the sweep. The interface is chosen per
    # platform: "lo" on POSIX, where nothing ever DHCPs, so the suite never
    # sniffs a developer's real LAN. Windows has no "lo" and SIO_RCVALL binds
    # to an address, so it gets a real adapter's - and is skipped if it has none.
    ["observe-dhcp", "aa:bb:cc:dd:ee:ff", "--interface", capture_interface() or "lo", "--timeout", "0.3", "--settle", "0.1"],
    ["capabilities"],
    ["info"],
]


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _invoke(runner: CliRunner, args: list[str]) -> Any:
    """Invoke for OUTPUT, never for an exit code.

    ``standalone_mode=False`` makes Click swallow ``ctx.exit()``, so this
    reports 0 for every command that exits 1 (not reached) or 2 (via ``_fail``).
    Measured: ``find-ip`` with an unknown MAC gives 0 here and 1 for real.
    Assert exit codes through :func:`main` or a standalone ``runner.invoke``.
    """

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
    if args[0] == "observe-dhcp" and not ipscout.dhcp_capture_available():
        pytest.skip("capturing DHCP needs elevation: root or CAP_NET_RAW on POSIX, Administrator on Windows")
    if args[0] == "observe-dhcp" and capture_interface() is None:
        pytest.skip("no interface on this host can be captured on")


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


@pytest.mark.parametrize(("mode", "envelope"), [(OutputMode.BARE, False), (OutputMode.ENVELOPE, True)])
def test_an_escaping_failure_keeps_the_shape_that_was_asked_for(*, mode: OutputMode, envelope: bool, capsys: pytest.CaptureFixture[str]) -> None:
    # Anything getting past a command's own guard is reported by main()'s
    # handler, which reads the shape from argv because there may be no Click
    # context left to ask. Bare mode used to fall through to the envelope here.
    cli_module._exception_handler(mode)(RuntimeError("boom"))  # pyright: ignore[reportPrivateUsage] - the handler under test has no public caller taking an exception
    payload = json.loads(capsys.readouterr().out)

    assert ("ok" in payload) is envelope
    assert "boom" in json.dumps(payload)


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["info"], OutputMode.HUMAN),
        (["--json", "info"], OutputMode.ENVELOPE),
        (["-j", "info"], OutputMode.ENVELOPE),
        (["--json-bare", "info"], OutputMode.BARE),
        (["--json", "--json-bare", "info"], OutputMode.BARE),
        (["--json-bare", "-j", "info"], OutputMode.BARE),
    ],
    ids=["neither", "json", "j", "json-bare", "json-then-bare", "bare-then-j"],
)
def test_the_raw_argv_names_one_output_mode(argv: list[str], expected: OutputMode) -> None:
    # main() reads the mode before Click parses anything, so an error escaping
    # before the context exists still comes out in the shape asked for. Compared
    # by identity: a str-Enum equals its value, so == would also pass for a
    # call site that handed back a plain string.
    assert OutputMode.from_argv(argv) is expected


@pytest.mark.parametrize(
    ("json_output", "json_bare", "expected"),
    [(False, False, OutputMode.HUMAN), (True, False, OutputMode.ENVELOPE), (False, True, OutputMode.BARE)],
    ids=["neither", "json", "json-bare"],
)
def test_the_two_flags_name_one_output_mode(*, json_output: bool, json_bare: bool, expected: OutputMode) -> None:
    assert OutputMode.from_flags(json_output=json_output, json_bare=json_bare) is expected


def test_both_flags_are_refused_with_the_documented_message() -> None:
    with pytest.raises(UsageError, match=r"^--json and --json-bare are mutually exclusive; pick one output shape$"):
        OutputMode.from_flags(json_output=True, json_bare=True)


def test_both_flags_are_refused_end_to_end_in_the_bare_shape() -> None:
    # The refusal travels through main()'s handler, whose mode came from argv,
    # where --json-bare wins: the report is the bare error record, not prose.
    import contextlib
    import io

    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        code = main(["--json", "--json-bare", "info"])

    assert code == EXIT_ERROR
    assert json.loads(stream.getvalue()) == {"type": "UsageError", "message": "--json and --json-bare are mutually exclusive; pick one output shape"}


def test_the_context_carries_the_mode_the_flags_chose() -> None:
    assert CliContext().output is OutputMode.HUMAN
    assert CliContext().machine_readable is False
    assert CliContext(output=OutputMode.ENVELOPE).machine_readable is True
    assert CliContext(output=OutputMode.BARE).machine_readable is True


def test_a_network_without_a_scan_is_refused_rather_than_dropped() -> None:
    # Dropping the flag answered from the cache while the caller believed that
    # network had been swept, and reported ok: true for it. Driven through
    # main(), because a usage error is serialised by the handler main() installs
    # and never reaches the envelope under CliRunner's non-standalone mode.
    import contextlib
    import io

    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        code = main(["--json", "find-ip", "--network", "10.0.0.0/8", "aa:bb:cc:dd:ee:ff"])
    payload = json.loads(stream.getvalue())

    assert code == EXIT_ERROR
    assert payload["ok"] is False
    assert "--scan" in payload["error"]["message"]


def test_a_malformed_invocation_exits_with_the_error_code() -> None:
    # Exit 1 is documented as "not reached", so returning it for a usage error
    # tells a script the host went silent when the real problem was the command.
    import contextlib
    import io

    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        both_families = main(["resolve", "localhost", "-4", "-6"])
        both_shapes = main(["--json", "--json-bare", "info"])
        network_without_scan = main(["find-ip", "--network", "10.0.0.0/8", "aa:bb:cc:dd:ee:ff"])

    assert (both_families, both_shapes, network_without_scan) == (EXIT_ERROR, EXIT_ERROR, EXIT_ERROR)


def test_a_human_failure_does_not_name_a_python_class(runner: CliRunner) -> None:
    # The message already names the remedy. Prefixing it with the exception
    # type puts an implementation detail in a sentence written for a person.
    output = _invoke(runner, ["find-ip", "nonsense"]).output

    assert "not a hardware address" in output
    assert "ValueError" not in output
    assert "IPScout" not in output


@pytest.mark.parametrize(
    ("args", "why"),
    [
        (["reachable", NEVER_ANSWERS, "--timeout", "1"], "nothing answers a TEST-NET-3 address"),
        (["reverse-dns", NEVER_ANSWERS], "a reserved address has no PTR record"),
        (["find-ip", "aa:bb:cc:dd:ee:ff"], "that hardware address holds nothing here"),
        (["remove-neighbour", "192.0.2.254"], "no entry for a TEST-NET-1 address, so nothing was removed"),
        (["banners", NEVER_ANSWERS, "--port", "21", "--timeout", "0.5"], "nothing greets from a TEST-NET-3 address"),
        (["snmp-system", NEVER_ANSWERS, "--timeout", "0.5"], "no SNMP agent answers from a TEST-NET-3 address"),
        # "mac" is deliberately absent: for a routed address it reports the
        # gateway's MAC labelled next_hop, which is a positive answer and
        # exits 0. That is the documented router-hop behaviour, not a miss.
    ],
    ids=lambda v: v if isinstance(v, str) else v[0],
)
def test_a_valid_but_negative_answer_exits_one(args: list[str], why: str) -> None:
    # Exit 1 is published in README, docs/usage.md and the shipped skill as the
    # contract for machine consumers, so it needs pinning per command rather
    # than trusting one example. Through main(), because CliRunner with
    # standalone_mode=False swallows ctx.exit() and reports 0 for all of these.
    _skip_what_this_host_cannot_do(args)

    assert main(args) == EXIT_NOT_REACHED, why


def test_observe_dhcp_refuses_a_bad_address_before_it_needs_any_privilege(runner: CliRunner) -> None:
    # Runs on every host, including the ones that could never capture: the
    # hardware address is validated before the socket is opened, so a typo is
    # reported as a typo rather than as a missing permission.
    # Invoked in standalone mode deliberately: ctx.exit() is swallowed by
    # standalone_mode=False, so _invoke would report 0 here for any command
    # that fails through _fail, including the ones that already existed.
    result = runner.invoke(cli, ["observe-dhcp", "nonsense"])

    assert result.exit_code == EXIT_ERROR
    assert "not a hardware address" in result.output
    assert "ValueError" not in result.output


def test_observe_dhcp_reports_the_window_its_empty_answer_rests_on(runner: CliRunner) -> None:
    # An empty list after sixty seconds and an empty list after a fifth of a
    # second are different facts, and a machine reader has no other way to
    # tell them apart.
    interface = capture_interface()
    if not ipscout.dhcp_capture_available() or interface is None:
        pytest.skip("capturing DHCP needs elevation and an interface this host can watch")
    args = ["--json", "observe-dhcp", "aa:bb:cc:dd:ee:ff", "--interface", interface, "--timeout", "0.3", "--settle", "0.1"]
    data = json.loads(_invoke(runner, args).output)["data"]

    assert data["addresses"] == []
    assert (data["timeout"], data["settle"], data["interface"]) == (0.3, 0.1, interface)


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
    cli_module._note_skipped((ipaddress.IPv4Network("172.17.0.0/16"),))  # pyright: ignore[reportPrivateUsage] - the stderr channel is only reachable through _emit, which also writes stdout
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

    assert set(data) == {"icmp_ipv4", "icmp_ipv6", "traceroute", "dhcp_capture"}
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


class _OneGreeting:
    """A loopback server that greets one client, then records what it sends back."""

    def __init__(self, greeting: bytes) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(5.0)
        self.port = int(self._listener.getsockname()[1])
        self.received = b""
        self._thread = threading.Thread(target=self._serve, args=(greeting,), daemon=True)
        self._thread.start()

    def _serve(self, greeting: bytes) -> None:
        try:
            conn, _ = self._listener.accept()
        except OSError:
            return
        with conn:
            conn.sendall(greeting)
            conn.settimeout(5.0)
            chunks: list[bytes] = []
            with contextlib.suppress(OSError):
                while chunk := conn.recv(4096):
                    chunks.append(chunk)
            self.received = b"".join(chunks)

    def finish(self) -> bytes:
        """Wait for the session to end and return what the client sent."""

        self._thread.join(timeout=6.0)
        self._listener.close()
        return self.received


def test_banners_reports_the_greeting_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    server = _OneGreeting(b"220 Print Server Ready.\r\n")

    code = main(["--json", "banners", "127.0.0.1", "--port", str(server.port)])
    server.finish()
    data = json.loads(capsys.readouterr().out)["data"]

    assert code == EXIT_OK
    assert data == {"127.0.0.1": {"host": "127.0.0.1", "port": server.port, "state": "greeted", "line": "220 Print Server Ready.", "error": None}}


def test_banners_sends_the_farewell_with_its_escapes_decoded(capsys: pytest.CaptureFixture[str]) -> None:
    # Typed on a shell, "QUIT\r\n" arrives as backslashes; FTP needs the real CR LF.
    server = _OneGreeting(b"220 ready\r\n")

    main(["banners", "127.0.0.1", "--port", str(server.port), "--farewell", "QUIT\\r\\n"])
    capsys.readouterr()

    assert server.finish() == b"QUIT\r\n"


def test_snmp_system_reports_the_values_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with FakeAgent(honest()) as agent:
        code = main(["--json", "snmp-system", "127.0.0.1", "--port", str(agent.port), "--timeout", "1"])
    data = json.loads(capsys.readouterr().out)["data"]

    assert code == EXIT_OK
    assert data == {
        "127.0.0.1": {
            "host": "127.0.0.1",
            "state": "answered",
            "uptime_seconds": 123.45,
            "name": "PRINTER",
            "description": "A print server",
            "object_id": "1.3.6.1.4.1.11.2.3.9.1",
            "error": None,
        }
    }


def test_snmp_system_takes_the_community_from_the_environment(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # The environment is an external edge (os.environ), not an ipscout internal.
    monkeypatch.setenv("IPSCOUT_SNMP_COMMUNITY", "from-env")
    with FakeAgent(honest()) as agent:
        main(["--json", "snmp-system", "127.0.0.1", "--port", str(agent.port), "--timeout", "1"])
    capsys.readouterr()

    assert agent.requests[0].community == b"from-env"


def test_snmp_system_sends_v2c_when_asked(capsys: pytest.CaptureFixture[str]) -> None:
    with FakeAgent(honest()) as agent:
        main(["--json", "snmp-system", "127.0.0.1", "--port", str(agent.port), "--version", "v2c", "--timeout", "1"])
    capsys.readouterr()

    assert agent.requests[0].version == 1


def test_snmp_system_refuses_an_unknown_version(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["snmp-system", "127.0.0.1", "--version", "v3"])
    said = capsys.readouterr()

    # Naming the option: an unknown COMMAND would also exit EXIT_ERROR.
    assert code == EXIT_ERROR
    assert "'--version'" in said.out + said.err


def test_snmp_system_prints_what_the_device_said_literally(capsys: pytest.CaptureFixture[str]) -> None:
    # The description is the device's own text: a "[/]" in it is not rich markup, and must
    # neither raise MarkupError nor restyle the table.
    said = b"HP [/] JetDirect [bold]x"
    with FakeAgent(honest({**SYSTEM, DESCRIPTION: (OCTET_STRING, said)})) as agent:
        code = main(["snmp-system", "127.0.0.1", "--port", str(agent.port), "--timeout", "1"])
    out = capsys.readouterr().out

    assert code == EXIT_OK
    assert said.decode() in out
    assert "0:02:03" in out  # 12345 ticks, as a person reads an uptime


def test_banners_prints_a_greeting_literally(capsys: pytest.CaptureFixture[str]) -> None:
    server = _OneGreeting(b"220 [/] ready\r\n")

    code = main(["banners", "127.0.0.1", "--port", str(server.port)])
    out = capsys.readouterr().out
    server.finish()

    assert code == EXIT_OK
    assert "220 [/] ready" in out


def test_snmp_system_expands_a_network_and_exits_zero_when_one_host_answered(capsys: pytest.CaptureFixture[str]) -> None:
    with FakeAgent(honest()) as agent:
        code = main(["--json", "snmp-system", "127.0.0.0/30", "--port", str(agent.port), "--timeout", "0.5"])
    data = json.loads(capsys.readouterr().out)["data"]

    assert list(data) == ["127.0.0.1", "127.0.0.2"]
    assert data["127.0.0.1"]["state"] == "answered"
    assert data["127.0.0.2"]["state"] != "answered"
    assert code == EXIT_OK


def test_snmp_system_passes_the_family_flag(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--json", "snmp-system", "::1", "-4", "--timeout", "0.5"])
    record = json.loads(capsys.readouterr().out)["data"]["::1"]

    assert code == EXIT_NOT_REACHED
    assert (record["state"], "ipv4" in record["error"]) == ("unreachable", True)


@pytest.mark.parametrize("farewell", ["QUIT\\q", "QUIT é"], ids=["unknown-escape", "not-ascii"])
def test_banners_refuses_a_farewell_it_cannot_send_exactly(farewell: str, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--json", "banners", "127.0.0.1", "--port", "21", "--farewell", farewell])
    payload = json.loads(capsys.readouterr().out)

    assert code == EXIT_ERROR
    assert "--farewell" in payload["error"]["message"]


@pytest.mark.parametrize("bare", [False, True], ids=["envelope", "bare"])
def test_a_bad_option_value_names_the_option_in_json(bare: bool, capsys: pytest.CaptureFixture[str]) -> None:
    # Click keeps the option's name outside the exception's text, so a JSON
    # reader given only str(exc) learned that some value was not a number,
    # but not which of the command's options it was.
    flag = "--json-bare" if bare else "--json"
    code = main([flag, "scan-ports", "127.0.0.1", "--ports", "1", "--timeout", "abc"])
    payload = json.loads(capsys.readouterr().out)
    error = payload if bare else payload["error"]

    assert code == EXIT_ERROR
    assert "--timeout" in error["message"]


def test_banners_expands_a_network_into_its_hosts(capsys: pytest.CaptureFixture[str]) -> None:
    main(["--json", "banners", "127.0.0.0/30", "--port", "1", "--timeout", "0.3"])
    data = json.loads(capsys.readouterr().out)["data"]

    assert list(data) == ["127.0.0.1", "127.0.0.2"]


def test_banners_refuses_a_network_wider_than_one_sweep(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--json", "banners", "10.0.0.0/19", "--port", "21"])
    payload = json.loads(capsys.readouterr().out)

    assert code == EXIT_ERROR
    assert payload["ok"] is False
    assert "10.0.0.0/19" in payload["error"]["message"]


def test_banners_refuses_a_malformed_network(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--json", "banners", "10.0.0.0/99", "--port", "21"])
    payload = json.loads(capsys.readouterr().out)

    assert code == EXIT_ERROR
    assert "10.0.0.0/99" in payload["error"]["message"]
