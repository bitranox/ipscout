"""Argument bounds: a value no probe can use is refused before anything is sent.

Every library entry point here checks its arguments once, at entry, through a
declared model; the command line converts its options through those same
declarations, so a bad option is a usage error (exit 2) in the library's own
words rather than a run that reports every target "not reached" (exit 1).
"""

from __future__ import annotations

import asyncio
import errno
import json
import math
import socket
from typing import TYPE_CHECKING, Any

import pytest

import ipscout
from ipscout import scan, wol
from ipscout.banner import grab_banners
from ipscout.cli import EXIT_ERROR, main
from ipscout.errors import IPScoutResolutionError, IPScoutSweepTooWideError
from ipscout.models import UNKNOWN_IP, SweepScope
from ipscout.portscan import ascan_ports, scan_ports, syn_scan

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.os_agnostic

MAC = "aa:bb:cc:dd:ee:ff"


def _json(capsys: pytest.CaptureFixture[str], args: list[str]) -> tuple[int, Any]:
    """Run the CLI in envelope mode and return its exit code and parsed stdout."""

    code = main(["--json", *args])
    return code, json.loads(capsys.readouterr().out)


@pytest.fixture
def listening_port() -> Iterator[int]:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    try:
        yield listener.getsockname()[1]
    finally:
        listener.close()


@pytest.fixture
def receiver() -> Iterator[socket.socket]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    try:
        yield sock
    finally:
        sock.close()


class _NoRoute:
    """A datagram socket whose every send fails, as one with no route to its destination does.

    Stands in for the stdlib socket at the one edge a test cannot reach
    otherwise: a real send failure would need a route this host lacks, or
    traffic leaving it.
    """

    def __init__(self, *_args: object) -> None:
        pass

    def __enter__(self) -> _NoRoute:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def setsockopt(self, *_args: object) -> None:
        pass

    def sendto(self, _data: bytes, _address: object) -> int:
        raise OSError(errno.ENETUNREACH, "Network is unreachable")


# --- the command line: a bad option is a usage error ------------------------------


@pytest.mark.parametrize(
    ("args", "option"),
    [
        (["ping", "127.0.0.1", "-c", "0"], "--times"),
        (["ping-many", "127.0.0.1", "-c", "0"], "--times"),
        (["ping-many", "127.0.0.1", "--timeout", "0"], "--timeout"),
        (["ping-many", "127.0.0.1", "--concurrency", "0"], "--concurrency"),
        (["reachable", "127.0.0.1", "--timeout", "0"], "--timeout"),
        (["scan-ports", "127.0.0.1", "--ports", "1", "--timeout", "0"], "--timeout"),
        (["scan-ports", "127.0.0.1", "--ports", "1", "--concurrency", "0"], "--concurrency"),
        (["arp-scan", "--network", "127.0.0.0/30", "--concurrency", "0"], "--concurrency"),
        (["banners", "127.0.0.1", "--port", "1", "--timeout", "inf"], "--timeout"),
        (["traceroute", "127.0.0.1", "--max-hops", "256", "--timeout", "0.2"], "--max-hops"),
        (["traceroute", "127.0.0.1", "--timeout", "0"], "--timeout"),
        (["observe-dhcp", MAC, "--interface", "lo", "--timeout", "0"], "--timeout"),
        (["observe-dhcp", MAC, "--interface", "lo", "--settle", "-1"], "--settle"),
        (["wake", MAC, "--broadcast", "127.0.0.1", "--port", "0"], "--port"),
    ],
    ids=[
        "ping-times",
        "ping-many-times",
        "ping-many-timeout",
        "ping-many-concurrency",
        "reachable-timeout",
        "scan-ports-timeout",
        "scan-ports-concurrency",
        "arp-scan-concurrency",
        "banners-timeout-infinite",
        "traceroute-max-hops",
        "traceroute-timeout",
        "observe-dhcp-timeout",
        "observe-dhcp-settle",
        "wake-port",
    ],
)
def test_a_bad_option_is_a_usage_error_naming_the_option(args: list[str], option: str, capsys: pytest.CaptureFixture[str]) -> None:
    code, payload = _json(capsys, args)

    assert code == EXIT_ERROR
    assert payload["ok"] is False
    assert option in payload["error"]["message"]


@pytest.mark.parametrize("args", [["--timeout", "0"], ["--settle", "-1"]], ids=["timeout", "settle"])
def test_a_bad_dhcp_watch_window_is_refused_before_the_command_runs(args: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    # The command body is what opens the capture, and a refusal it raised would
    # carry its name in the envelope; no command named means Click refused the
    # value while parsing, so no capture socket was ever opened.
    code, payload = _json(capsys, ["observe-dhcp", MAC, "--interface", "lo", *args])

    assert code == EXIT_ERROR
    assert payload["command"] is None


def test_a_refused_option_reads_as_the_library_s_reason_not_pydantic_s(capsys: pytest.CaptureFixture[str]) -> None:
    # Measured before: "1 validation error for PingRequest ... https://errors.pydantic.dev/...".
    _code, payload = _json(capsys, ["ping", "127.0.0.1", "-c", "0"])
    message = payload["error"]["message"]

    assert "greater than or equal to 1" in message
    assert "pydantic" not in message
    assert "validation error for" not in message


def test_a_human_usage_error_names_the_option_without_a_traceback(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["ping-many", "127.0.0.1", "-c", "0"])
    err = capsys.readouterr().err

    assert code == EXIT_ERROR
    assert "Invalid value for '--times'" in err
    assert "Traceback" not in err


def test_an_empty_farewell_is_refused_rather_than_silently_not_sent(capsys: pytest.CaptureFixture[str]) -> None:
    code, payload = _json(capsys, ["banners", "127.0.0.1", "--port", "1", "--farewell", ""])

    assert code == EXIT_ERROR
    assert "farewell" in payload["error"]["message"]


def test_a_failed_wake_send_is_reported_by_the_command(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    # Measured before: the IPScoutError escaped the command, so the envelope
    # named no command and the exit code was the errno mapping's 1, which reads
    # as "not reached".
    monkeypatch.setattr(socket, "socket", _NoRoute)

    code, payload = _json(capsys, ["wake", MAC, "--broadcast", "127.0.0.1"])

    assert code == EXIT_ERROR
    assert payload["command"] == "wake"
    assert payload["error"]["type"] == "IPScoutError"


def test_a_gateway_query_for_a_non_address_is_reported_by_the_command(capsys: pytest.CaptureFixture[str]) -> None:
    # Measured before: the ValueError escaped, exit 22 and no command named.
    code, payload = _json(capsys, ["gateway", "--to", "nonsense"])

    assert code == EXIT_ERROR
    assert payload["command"] == "gateway"


def test_a_mac_lookup_of_a_name_is_reported_by_the_command(capsys: pytest.CaptureFixture[str]) -> None:
    # The route lookup behind it refuses a non-literal with ValueError, which
    # escaped the command: exit 22 and no command named.
    code, payload = _json(capsys, ["mac", "example.test"])

    assert code == EXIT_ERROR
    assert payload["command"] == "mac"


def test_banners_refuses_networks_that_only_fit_one_at_a_time_naming_each(capsys: pytest.CaptureFixture[str]) -> None:
    # The budget is on the whole sweep: each fits alone, together they do not.
    code, payload = _json(capsys, ["banners", "10.0.0.0/20", "10.1.0.0/24", "--port", "21"])

    assert code == EXIT_ERROR
    assert payload["error"]["type"] == "IPScoutSweepTooWideError"
    assert "10.0.0.0/20 holds 4096 addresses, 10.1.0.0/24 holds 256 addresses" in payload["error"]["message"]


# --- the port scan ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "named"),
    [({"timeout": 0}, "timeout"), ({"timeout": math.nan}, "timeout"), ({"timeout": math.inf}, "timeout"), ({"concurrency": 0}, "concurrency")],
    ids=["timeout-zero", "timeout-nan", "timeout-infinite", "concurrency-zero"],
)
def test_a_port_scan_refuses_a_setting_no_probe_can_use(kwargs: dict[str, Any], named: str, listening_port: int) -> None:
    # Measured before: timeout=0 reported a listening port FILTERED, which
    # reads as a firewall rather than as the caller's mistake.
    with pytest.raises(ValueError, match=rf"{named}: "):
        scan_ports("127.0.0.1", [listening_port], **kwargs)
    with pytest.raises(ValueError, match=rf"{named}: "):
        asyncio.run(ascan_ports("127.0.0.1", [listening_port], **kwargs))


def test_a_syn_scan_refuses_a_bad_timeout_before_asking_for_privileges() -> None:
    with pytest.raises(ValueError, match="timeout: "):
        syn_scan("127.0.0.1", [80], timeout=0)


def test_a_port_scan_of_a_name_that_does_not_resolve_raises_rather_than_reporting_filtered() -> None:
    # Measured before: every port came back FILTERED for a name with no address.
    with pytest.raises(IPScoutResolutionError):
        scan_ports("nothing.invalid", [80], timeout=0.2)


@pytest.fixture
def port_listening_where_localhost_resolves() -> Iterator[int]:
    # The resolver's first answer for "localhost" differs by host: 127.0.0.1
    # on some, ::1 on the GitHub runners, so the listener follows it rather
    # than assuming IPv4.
    family, _, _, _, sockaddr = socket.getaddrinfo("localhost", None, type=socket.SOCK_STREAM)[0]
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.bind((sockaddr[0], 0))
    listener.listen(8)
    try:
        yield listener.getsockname()[1]
    finally:
        listener.close()


def test_a_port_scan_of_a_name_asks_the_address_it_resolves_to(port_listening_where_localhost_resolves: int) -> None:
    port = port_listening_where_localhost_resolves
    assert scan_ports("localhost", [port], timeout=1.0)[port] is ipscout.PortState.OPEN


# --- banners --------------------------------------------------------------------------


@pytest.mark.parametrize(("kwargs", "named"), [({"farewell": b""}, "farewell"), ({"timeout": math.inf}, "timeout")], ids=["empty-farewell", "infinite-timeout"])
def test_a_banner_grab_refuses_an_argument_it_could_not_honour(kwargs: dict[str, Any], named: str) -> None:
    with pytest.raises(ValueError, match=rf"{named}: "):
        grab_banners(["nothing.invalid"], 21, **kwargs)


# --- wake-on-LAN ----------------------------------------------------------------------


@pytest.mark.parametrize("broadcast", ["", UNKNOWN_IP, "300.1.1.1", "nothing.invalid", "::1"], ids=["empty", "unspecified", "not-a-quad", "name", "ipv6"])
def test_a_magic_packet_is_never_sent_to_something_that_is_not_an_ipv4_destination(broadcast: str, receiver: socket.socket) -> None:
    # Measured before: "" and "0.0.0.0" both meant INADDR_ANY, so the packet
    # went to this host and the call reported it sent.
    port = receiver.getsockname()[1]

    with pytest.raises(ValueError, match="broadcast must be an IPv4 address"):
        wol.wake_on_lan(MAC, broadcast=broadcast, port=port)

    with pytest.raises(BlockingIOError):
        receiver.recv(256)


def test_the_default_broadcast_is_the_limited_broadcast_address() -> None:
    assert wol.DEFAULT_BROADCAST == "255.255.255.255"


# --- the sweep ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "named"),
    [({"timeout": 0}, "timeout"), ({"timeout": math.inf}, "timeout"), ({"concurrency": 0}, "concurrency")],
    ids=["timeout-zero", "timeout-infinite", "concurrency-zero"],
)
def test_an_arp_scan_refuses_a_setting_before_probing(kwargs: dict[str, Any], named: str) -> None:
    # Measured before: timeout=0 refused every probe, swallowed it, and
    # returned the cache as it stood as though the sweep had produced it.
    with pytest.raises(ValueError, match=rf"{named}: "):
        scan.arp_scan("127.0.0.0/30", **kwargs)


def test_a_mac_search_refuses_a_concurrency_of_none() -> None:
    with pytest.raises(ValueError, match="concurrency: "):
        scan.find_ip_by_mac(MAC, scan=True, network="127.0.0.0/30", concurrency=0)


@pytest.mark.parametrize("limit", [0, -1])
def test_a_sweep_budget_below_one_is_refused(limit: int) -> None:
    # Measured before: limit=0 returned a scope with every network skipped.
    with pytest.raises(ValueError, match="limit: "):
        scan.sweep_scope("127.0.0.0/30", limit=limit)


def test_a_partial_scope_is_refused_naming_every_network() -> None:
    plan = SweepScope.from_networks(["10.0.0.0/20", "10.1.0.0/24"], limit=4096)

    with pytest.raises(IPScoutSweepTooWideError, match=r"^10\.0\.0\.0/20 holds 4096 addresses, 10\.1\.0\.0/24 holds 256 addresses, more than the 4096"):
        scan.refuse_a_partial_scope(plan)


def test_a_whole_scope_passes() -> None:
    scan.refuse_a_partial_scope(SweepScope.from_networks(["192.0.2.0/24"], limit=4096))


def test_the_library_and_the_command_line_share_one_refusal_for_a_sweep_argument_without_a_sweep() -> None:
    library = scan.sweep_argument_refusal(scan=False, named="network")
    command_line = scan.sweep_argument_refusal(scan=False, named="--network", scan_flag="--scan")

    assert library == "network applies only with scan=True; without it only the existing neighbour cache is searched"
    assert command_line == "--network applies only with --scan; without it only the existing neighbour cache is searched"
    with pytest.raises(ValueError, match=r"^network applies only with scan=True"):
        scan.find_ip_by_mac(MAC, network="192.0.2.0/24")
