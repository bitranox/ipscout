"""Command-line surface. Every public function is reachable from here.

Contents:
    cli: Root group holding the global flags.
    One subcommand per public callable, plus ``capabilities`` and ``info``.
    main: Entry point for the console script and ``python -m ipscout``.

Output modes:
    Human-readable by default. ``--json``/``-j`` switches to an envelope -
    ``{"ok": ..., "command": ..., "data"|"error": ...}`` - which is what a
    machine reading only stdout needs: a boolean it can always see, rather than
    an exit code it may not have captured, and errors as structured data rather
    than a traceback on stderr. ``--json-bare`` drops the envelope for ``jq``.

Note:
    Both flags live on the group rather than on each command, so they compose
    with every subcommand including ones added later. Rendering goes through
    one helper, :func:`_emit`, so a command cannot support JSON on its success
    path and forget it on another.

"""

from __future__ import annotations

import enum
import ipaddress
import re
import sys
from typing import TYPE_CHECKING

import lib_cli_exit_tools
import rich_click as click
from pydantic import BaseModel, ConfigDict
from rich.console import Console
from rich.style import Style
from rich.table import Table

from . import __init__conf__
from .api import is_reachable, ping, ping_many
from .banner import DEFAULT_CONCURRENCY as DEFAULT_BANNER_CONCURRENCY
from .banner import DEFAULT_MAX_LINE_BYTES, grab_banners
from .banner import DEFAULT_TIMEOUT as DEFAULT_BANNER_TIMEOUT
from .dhcp import DEFAULT_SETTLE, DEFAULT_TIMEOUT, dhcp_capture_available, observe_dhcp
from .errors import IPScoutError, IPScoutSweepTooWideError
from .factory import icmp_available
from .interfaces import local_interfaces
from .models import (
    AddressFamily,
    BannerState,
    CapabilityReport,
    CommandName,
    FindIpReport,
    IPNetwork,
    JsonEnvelope,
    JsonError,
    MacLookup,
    MacScope,
    MtuReport,
    Neighbour,
    ObserveDhcpReport,
    PackageInfo,
    PortResult,
    PortScanReport,
    PortState,
    ReachabilityReport,
    RemoveNeighbourReport,
    ResolveReport,
    ReverseDnsReport,
    RouteInfo,
    ScanMethod,
    SweepScope,
    WakeReport,
)
from .mtu import path_mtu
from .neighbours import get_mac_address, lookup_mac, neighbours
from .portscan import scan_ports
from .resolve import resolve as resolve_target
from .resolve import reverse_dns
from .routes import default_gateway, query_route
from .scan import MAX_SWEEP_HOSTS, arp_scan, find_ip_by_mac, sweep_scope
from .serialize import dumps, to_jsonable
from .service import DEFAULT_INTERVAL, DEFAULT_TIMES
from .service import DEFAULT_TIMEOUT as DEFAULT_PING_TIMEOUT
from .static_neighbours import remove_neighbour, set_neighbour
from .subnet import subnet_info
from .traceroute import traceroute
from .transport_tcp import DEFAULT_TCP_PORT
from .typed_click import argument, option, version_option
from .wol import wake_on_lan

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    #: Everything a command may hand to :func:`_emit`: one result record, a
    #: sequence of them, or a mapping onto them. Named rather than left as
    #: ``Any`` so a raw dict or a bare string cannot reach the output boundary
    #: through the one helper every command routes through.
    EmitPayload = BaseModel | Sequence[BaseModel] | Mapping[str, BaseModel]

__all__ = [
    "CLICK_CONTEXT_SETTINGS",
    "CliContext",
    "OutputMode",
    "cli",
    "console",
    "error_console",
    "main",
]

#: Shared Click context flags for consistent help output.
CLICK_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

#: Console for rich output.
console = Console()

#: Console for anything that must not land in the parsed stream: coverage
#: notes go here in every output mode.
error_console = Console(stderr=True)

#: Style for error messages when traceback is suppressed.
_ERROR_STYLE = Style(color="red", bold=True)

#: Style for a coverage note, which qualifies a result rather than replacing it.
_NOTE_STYLE = Style(color="yellow")

#: Exit codes. Independent of output format.
EXIT_OK = 0
EXIT_NOT_REACHED = 1
EXIT_ERROR = 2


class OutputMode(str, enum.Enum):
    """The shape every command writes its result in.

    One value rather than a pair of flags: the two flags admit a fourth
    combination - both set - that names no shape at all, and every branch
    reading them had to decide afresh which one wins.

    Attributes:
        HUMAN: Readable text for a person at a terminal. The default.
        ENVELOPE: The JSON envelope ``{"ok", "command", "data"|"error"}``,
            selected by ``--json``/``-j``.
        BARE: The JSON payload at top level with no envelope, for ``jq``,
            selected by ``--json-bare``.

    Examples:
        >>> OutputMode.from_argv(["--json", "info"]) is OutputMode.ENVELOPE
        True
        >>> OutputMode.from_argv(["info"]).value
        'human'

    """

    HUMAN = "human"
    ENVELOPE = "envelope"
    BARE = "bare"

    @classmethod
    def from_argv(cls, argv: Sequence[str]) -> OutputMode:
        """Return the mode the raw command line asks for, before Click parses it.

        Args:
            argv: The arguments after the program name.

        Returns:
            ``BARE`` when ``--json-bare`` is present, else ``ENVELOPE`` when
            ``--json`` or ``-j`` is, else ``HUMAN``.

        Note:
            ``--json-bare`` wins when both are given. That invocation is
            refused as a usage error, but the refusal is reported through this
            mode, and it must still come out as JSON rather than prose: either
            JSON shape satisfies that, so the precedence only has to be fixed.

        Examples:
            >>> OutputMode.from_argv(["--json", "--json-bare", "info"]).value
            'bare'

        """

        if "--json-bare" in argv:
            return cls.BARE
        if "--json" in argv or "-j" in argv:
            return cls.ENVELOPE
        return cls.HUMAN

    @classmethod
    def from_flags(cls, *, json_output: bool, json_bare: bool) -> OutputMode:
        """Return the mode the root command's two flags select.

        Args:
            json_output: Whether ``--json``/``-j`` was given.
            json_bare: Whether ``--json-bare`` was given.

        Returns:
            The single mode the flags name.

        Raises:
            click.UsageError: When both flags are given. A silent precedence
                rule would leave a caller parsing a shape they never asked for.

        Examples:
            >>> OutputMode.from_flags(json_output=False, json_bare=True).value
            'bare'

        """

        if json_output and json_bare:
            msg = "--json and --json-bare are mutually exclusive; pick one output shape"
            raise click.UsageError(msg)
        if json_bare:
            return cls.BARE
        if json_output:
            return cls.ENVELOPE
        return cls.HUMAN


class CliContext(BaseModel):
    """Typed context object for Click's ``ctx.obj``.

    Attributes:
        output: The shape results and failures are written in.

    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    output: OutputMode = OutputMode.HUMAN

    @property
    def machine_readable(self) -> bool:
        """Return whether output should be JSON in either of its two shapes."""

        return self.output is not OutputMode.HUMAN


def _context(ctx: click.Context) -> CliContext:
    """Return the typed context object, creating it if a command runs alone."""

    if not isinstance(ctx.obj, CliContext):
        ctx.obj = CliContext()
    return ctx.obj


def _emit(ctx: click.Context, command: CommandName, payload: EmitPayload, human: Callable[[], None], *, skipped: tuple[IPNetwork, ...] = ()) -> None:
    """Render one command's result in whichever format was asked for.

    Args:
        ctx: The Click context carrying the output flags.
        command: The subcommand name, echoed into the envelope so a transcript
            of several calls stays unambiguous.
        payload: The data to serialise when a JSON mode is active.
        human: Callable that prints the human-readable rendering.
        skipped: Networks the command could not cover, reported on the
            envelope and as a note on stderr. Passing them here rather than
            printing them per command is what keeps a partial result from
            reading as a complete one in whichever mode was forgotten.

    Note:
        Every command routes through here. That is deliberate: a per-command
        ``if json:`` branch is exactly the kind of thing that gets added on the
        success path and forgotten everywhere else.

        The note goes to stderr in every mode, including the human one, because
        stdout is the stream a caller parses and a JSON document with a line of
        prose in front of it is not one.

    """

    state = _context(ctx)
    _note_skipped(skipped)
    match state.output:
        case OutputMode.BARE:
            click.echo(dumps(payload))
        case OutputMode.ENVELOPE:
            envelope = JsonEnvelope(ok=True, command=command, data=to_jsonable(payload), skipped=skipped)
            click.echo(dumps(envelope))
        case OutputMode.HUMAN:
            human()


def _note_skipped(skipped: tuple[IPNetwork, ...]) -> None:
    """Say on stderr which networks were left out, when any were."""

    if not skipped:
        return
    left_out = ", ".join(str(item) for item in skipped)
    # One wording for both reasons a network is left out - too wide on its own,
    # or the sweep's budget already spent on the networks before it - because
    # naming it with --network is the remedy either way.
    error_console.print(
        f"note: not swept: {left_out} - outside what one sweep covers; name it with --network to sweep it on its own", style=_NOTE_STYLE, highlight=False
    )


def _fail(ctx: click.Context, command: CommandName, exc: Exception, *, skipped: tuple[IPNetwork, ...] = ()) -> None:
    """Report a failure in the active output format, then exit non-zero.

    Args:
        ctx: The Click context carrying the output flags.
        command: The subcommand the failure belongs to.
        exc: The anticipated failure to report.
        skipped: Networks left uncovered, when the command got far enough to
            know. A refusal caused by missing coverage should say so as data
            too, not only inside the message.

    Note:
        The human line carries the message alone. Everything reaching here is
        an anticipated failure whose message already names the remedy, so the
        exception's class name would add a Python detail to a sentence written
        for a person. The machine-readable ``type`` field keeps it, where a
        reader can branch on it.

    """

    state = _context(ctx)
    error = _json_error(exc)
    match state.output:
        case OutputMode.BARE:
            click.echo(dumps(error))
        case OutputMode.ENVELOPE:
            click.echo(dumps(JsonEnvelope(ok=False, command=command, error=error, skipped=skipped)))
        case OutputMode.HUMAN:
            console.print(f"Error: {exc}", style=_ERROR_STYLE, highlight=False)
    ctx.exit(EXIT_ERROR)


def _json_error(exc: BaseException) -> JsonError:
    """Return the machine-readable record of a failure, for either JSON shape."""

    # Click keeps the offending option's name in the exception's formatting,
    # not its text: str() of a bad --timeout says only that "abc" is not a
    # number, which leaves a JSON reader to guess which option was meant.
    message = exc.format_message() if isinstance(exc, click.ClickException) else str(exc)
    return JsonError(type=type(exc).__name__, message=message)


def _family(*, ipv4: bool, ipv6: bool) -> AddressFamily | None:
    """Return the family the -4/-6 flags select, or None for either."""

    if ipv4 and ipv6:
        msg = "-4 and -6 are mutually exclusive"
        raise click.UsageError(msg)
    if ipv4:
        return AddressFamily.IPV4
    if ipv6:
        return AddressFamily.IPV6
    return None


@click.group(
    help=__init__conf__.title,
    context_settings=CLICK_CONTEXT_SETTINGS,
    invoke_without_command=True,
)
@version_option(
    version=__init__conf__.version,
    prog_name=__init__conf__.shell_command,
    message=f"{__init__conf__.shell_command} version {__init__conf__.version}",
)
@option("--json", "-j", "json_output", is_flag=True, default=False, help="Emit a JSON envelope: {ok, command, data|error}.")
@option("--json-bare", "json_bare", is_flag=True, default=False, help="Emit the JSON payload at top level, without the envelope.")
# The traceback setting is read from argv by main(), because the exception it
# governs can escape before this command runs; Click only has to accept the
# flag, so its value is not handed to the command at all.
@option("--traceback/--no-traceback", is_flag=True, default=True, expose_value=False, help="Show a full Python traceback on unexpected errors.")
@click.pass_context
def cli(ctx: click.Context, *, json_output: bool, json_bare: bool) -> None:
    """Probe reachability and inspect the local network, without admin rights.

    Examples:
        >>> from click.testing import CliRunner
        >>> result = CliRunner().invoke(cli, ["--json", "info"])
        >>> result.exit_code
        0
        >>> import json
        >>> json.loads(result.output)["ok"]
        True

    """

    # The two flags stay on the command line, where they are the documented
    # surface; inside, they become the one mode that every renderer reads.
    ctx.obj = CliContext(output=OutputMode.from_flags(json_output=json_output, json_bare=json_bare))
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command("ping", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("target")
@option("--times", "-c", type=int, default=DEFAULT_TIMES, show_default=True, help="Echoes to send.")
@option("--timeout", type=float, default=DEFAULT_PING_TIMEOUT, show_default=True, help="Seconds to wait per reply.")
@option("--interval", type=float, default=DEFAULT_INTERVAL, show_default=True, help="Seconds between echoes.")
@option("-4", "ipv4", is_flag=True, default=False, help="Force IPv4.")
@option("-6", "ipv6", is_flag=True, default=False, help="Force IPv6.")
@option("--tcp-fallback", is_flag=True, default=False, help="Fall back to a TCP connect when ICMP is unavailable.")
@option("--tcp-port", type=int, default=DEFAULT_TCP_PORT, show_default=True, help="Port for the TCP fallback.")
@click.pass_context
def cli_ping(  # noqa: PLR0913 - one parameter per documented CLI option; collapsing them would hide the interface
    ctx: click.Context,
    target: str,
    *,
    times: int,
    timeout: float,
    interval: float,
    ipv4: bool,
    ipv6: bool,
    tcp_fallback: bool,
    tcp_port: int,
) -> None:
    """Ping a host and report what came back."""

    try:
        result = ping(
            target,
            times,
            timeout=timeout,
            interval=interval,
            family=_family(ipv4=ipv4, ipv6=ipv6),
            allow_tcp_fallback=tcp_fallback,
            tcp_port=tcp_port,
        )
    except (IPScoutError, ValueError) as exc:
        _fail(ctx, CommandName.PING, exc)
        return

    _emit(ctx, CommandName.PING, result, lambda: console.print(result.str_result))
    if not result.reached:
        ctx.exit(EXIT_NOT_REACHED)


@cli.command("ping-many", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("targets", nargs=-1, required=True)
@option("--times", "-c", type=int, default=DEFAULT_TIMES, show_default=True, help="Echoes per target.")
@option("--timeout", type=float, default=DEFAULT_PING_TIMEOUT, show_default=True, help="Seconds to wait per reply.")
@option("--concurrency", type=int, default=64, show_default=True, help="Probes in flight at once.")
@click.pass_context
def cli_ping_many(ctx: click.Context, targets: tuple[str, ...], *, times: int, timeout: float, concurrency: int) -> None:
    """Ping many hosts concurrently."""

    results = ping_many(list(targets), times=times, timeout=timeout, concurrency=concurrency)

    def human() -> None:
        table = Table("target", "reached", "loss", "avg ms", "error")
        for name, result in results.items():
            table.add_row(
                name,
                "yes" if result.reached else "no",
                f"{result.packets_lost_percentage}%",
                f"{result.time_avg_ms:.2f}" if result.reached else "-",
                result.error or "",
            )
        console.print(table)

    _emit(ctx, CommandName.PING_MANY, results, human)
    if not any(result.reached for result in results.values()):
        ctx.exit(EXIT_NOT_REACHED)


@cli.command("reachable", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("target")
@option("--timeout", type=float, default=DEFAULT_PING_TIMEOUT, show_default=True, help="Seconds to allow per attempt.")
@option("--tcp-port", type=int, default=DEFAULT_TCP_PORT, show_default=True, help="Port for the TCP attempt.")
@click.pass_context
def cli_reachable(ctx: click.Context, target: str, *, timeout: float, tcp_port: int) -> None:
    """Answer whether a host responds, by ICMP or failing that TCP."""

    answer = is_reachable(target, timeout=timeout, tcp_port=tcp_port)

    _emit(ctx, CommandName.REACHABLE, ReachabilityReport(target=target, reachable=answer), lambda: console.print("yes" if answer else "no"))
    if not answer:
        ctx.exit(EXIT_NOT_REACHED)


@cli.command("traceroute", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("target")
@option("--max-hops", type=int, default=30, show_default=True, help="Highest hop limit to try.")
@option("--timeout", type=float, default=2.0, show_default=True, help="Seconds to wait per hop.")
@option("-4", "ipv4", is_flag=True, default=False, help="Force IPv4.")
@option("-6", "ipv6", is_flag=True, default=False, help="Force IPv6.")
@option("--resolve-names", is_flag=True, default=False, help="Reverse-resolve each responding hop.")
@click.pass_context
def cli_traceroute(  # noqa: PLR0913 - one parameter per documented CLI option; collapsing them would hide the interface
    ctx: click.Context,
    target: str,
    *,
    max_hops: int,
    timeout: float,
    ipv4: bool,
    ipv6: bool,
    resolve_names: bool,
) -> None:
    """Report the path packets take to a host."""

    try:
        hops = traceroute(
            target,
            max_hops=max_hops,
            timeout=timeout,
            family=_family(ipv4=ipv4, ipv6=ipv6),
            resolve_names=resolve_names,
        )
    except (IPScoutError, ValueError) as exc:
        _fail(ctx, CommandName.TRACEROUTE, exc)
        return

    def human() -> None:
        for hop in hops:
            rtt = f"{hop.rtt_ms:7.2f}ms" if hop.rtt_ms is not None else "      *  "
            name = f"  {hop.hostname}" if hop.hostname else ""
            marker = "  <- target" if hop.reached else ""
            console.print(f"{hop.ttl:3}  {rtt}  {hop.address or '*'}{name}{marker}", highlight=False)

    _emit(ctx, CommandName.TRACEROUTE, hops, human)
    if not any(hop.reached for hop in hops):
        ctx.exit(EXIT_NOT_REACHED)


@cli.command("resolve", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("target")
@option("-4", "ipv4", is_flag=True, default=False, help="Force IPv4.")
@option("-6", "ipv6", is_flag=True, default=False, help="Force IPv6.")
@click.pass_context
def cli_resolve(ctx: click.Context, target: str, *, ipv4: bool, ipv6: bool) -> None:
    """Resolve a hostname to its addresses."""

    try:
        addresses = resolve_target(target, family=_family(ipv4=ipv4, ipv6=ipv6))
    except (IPScoutError, ValueError) as exc:
        _fail(ctx, CommandName.RESOLVE, exc)
        return

    payload = ResolveReport(target=target, addresses=tuple(addresses))
    _emit(ctx, CommandName.RESOLVE, payload, lambda: console.print("\n".join(addresses), highlight=False))


@cli.command("reverse-dns", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("ip")
@click.pass_context
def cli_reverse_dns(ctx: click.Context, ip: str) -> None:
    """Resolve an address back to a hostname."""

    hostname = reverse_dns(ip)
    payload = ReverseDnsReport(ip=ip, hostname=hostname)
    _emit(ctx, CommandName.REVERSE_DNS, payload, lambda: console.print(hostname or "(no PTR record)", highlight=False))
    if hostname is None:
        ctx.exit(EXIT_NOT_REACHED)


@cli.command("interfaces", context_settings=CLICK_CONTEXT_SETTINGS)
@click.pass_context
def cli_interfaces(ctx: click.Context) -> None:
    """List local network interfaces."""

    interfaces = local_interfaces()

    def human() -> None:
        table = Table("interface", "up", "loopback", "mac", "addresses")
        for item in interfaces:
            addresses = ", ".join(f"{entry.address}/{entry.prefix_len}" for entry in (*item.ipv4, *item.ipv6))
            table.add_row(item.name, "yes" if item.is_up else "no", "yes" if item.is_loopback else "no", item.mac or "-", addresses or "-")
        console.print(table)

    _emit(ctx, CommandName.INTERFACES, interfaces, human)


@cli.command("gateway", context_settings=CLICK_CONTEXT_SETTINGS)
@option("-4", "ipv4", is_flag=True, default=False, help="Force IPv4.")
@option("-6", "ipv6", is_flag=True, default=False, help="Force IPv6.")
@option("--to", "destination", default=None, help="Report the next hop toward this address instead of the default route.")
@click.pass_context
def cli_gateway(ctx: click.Context, *, ipv4: bool, ipv6: bool, destination: str | None) -> None:
    """Show the default route, or the next hop toward one address."""

    family = _family(ipv4=ipv4, ipv6=ipv6) or AddressFamily.IPV4
    route = query_route(destination, family) if destination else default_gateway(family)

    if route is None:
        empty = RouteInfo()
        _emit(ctx, CommandName.GATEWAY, empty, lambda: console.print("(no route)", highlight=False))
        ctx.exit(EXIT_NOT_REACHED)
        return

    def human() -> None:
        table = Table("gateway", "interface", "source")
        table.add_row(route.gateway or "(on-link)", route.interface or "-", route.source or "-")
        console.print(table)

    _emit(ctx, CommandName.GATEWAY, route, human)


def _neighbour_table(entries: tuple[Neighbour, ...]) -> Table:
    """Render neighbour records as a table."""

    table = Table("ip", "mac", "interface", "state", "family")
    for entry in entries:
        table.add_row(entry.ip, entry.mac or "-", entry.interface or "-", entry.state.value, entry.family.value)
    return table


@cli.command("neighbours", context_settings=CLICK_CONTEXT_SETTINGS)
@option("-4", "ipv4", is_flag=True, default=False, help="Report only IPv4.")
@option("-6", "ipv6", is_flag=True, default=False, help="Report only IPv6.")
@click.pass_context
def cli_neighbours(ctx: click.Context, *, ipv4: bool, ipv6: bool) -> None:
    """List the neighbour cache: which addresses this host has learned."""

    entries = neighbours(family=_family(ipv4=ipv4, ipv6=ipv6))
    _emit(ctx, CommandName.NEIGHBOURS, entries, lambda: console.print(_neighbour_table(entries)))
    if not entries:
        ctx.exit(EXIT_NOT_REACHED)


@cli.command("mac", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("ip")
@option("--strict", is_flag=True, default=False, help="Answer only for a directly-attached host; refuse anything routed.")
@option("--active", is_flag=True, default=False, help="Send a real resolution request instead of reading the cache.")
@click.pass_context
def cli_mac(ctx: click.Context, ip: str, *, strict: bool, active: bool) -> None:
    """Show the hardware address for an address, and whose it is."""

    try:
        if strict:
            address = get_mac_address(ip, active=active)
            payload = MacLookup(ip=ip, mac=address, scope=MacScope.DIRECT if address else MacScope.UNKNOWN)
        else:
            payload = lookup_mac(ip, active=active)
    except IPScoutError as exc:
        _fail(ctx, CommandName.MAC, exc)
        return

    def human() -> None:
        table = Table("ip", "mac", "scope", "via", "interface")
        table.add_row(payload.ip, payload.mac or "-", payload.scope.value, payload.via_ip or "-", payload.interface or "-")
        console.print(table)

    _emit(ctx, CommandName.MAC, payload, human)
    if payload.mac is None:
        ctx.exit(EXIT_NOT_REACHED)


@cli.command("find-ip", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("mac")
@option("--scan", is_flag=True, default=False, help="Sweep the subnet first, so hosts not spoken to recently are found.")
@option("--network", default=None, help="CIDR to sweep. Defaults to the subnets this host is attached to.")
@option("-4", "ipv4", is_flag=True, default=False, help="Report only IPv4.")
@option("-6", "ipv6", is_flag=True, default=False, help="Report only IPv6.")
@click.pass_context
def cli_find_ip(  # noqa: PLR0913 - one parameter per documented CLI option; collapsing them would hide the interface
    ctx: click.Context, mac: str, *, scan: bool, network: str | None, ipv4: bool, ipv6: bool
) -> None:
    """Find which addresses currently hold a hardware address."""

    if network is not None and not scan:
        # Dropping the flag would answer from the cache while the caller
        # believes that network was swept. The library refuses the same call;
        # this says it in the vocabulary the user typed.
        msg = "--network applies only with --scan; without it only the existing neighbour cache is searched"
        raise click.UsageError(msg)

    # Asked before sweeping, so the report can state its own coverage: the
    # address list alone cannot say whether a network went unprobed. Inside the
    # guard because a malformed CIDR is refused here first, and bound before it
    # so a refusal can still report what it would have covered.
    scope: SweepScope | None = None
    try:
        if scan:
            scope = sweep_scope(network)
        # The scope reported is the scope swept, rather than two independent
        # computations that could disagree if an interface changed between them.
        addresses = find_ip_by_mac(mac, scan=scan, scope=scope, family=_family(ipv4=ipv4, ipv6=ipv6))
    except (IPScoutError, ValueError) as exc:
        _fail(ctx, CommandName.FIND_IP, exc, skipped=scope.skipped if scope else ())
        return

    payload = FindIpReport(mac=mac, addresses=tuple(addresses), scanned=scan, scope=scope)
    _emit(
        ctx,
        CommandName.FIND_IP,
        payload,
        lambda: console.print("\n".join(addresses) or "(not found)", highlight=False),
        skipped=scope.skipped if scope else (),
    )
    if not addresses:
        ctx.exit(EXIT_NOT_REACHED)


@cli.command("arp-scan", context_settings=CLICK_CONTEXT_SETTINGS)
@option("--network", default=None, help="CIDR to sweep. Defaults to the subnets this host is attached to.")
@option("--concurrency", type=int, default=64, show_default=True, help="Probes in flight at once.")
@option("-4", "ipv4", is_flag=True, default=False, help="Report only IPv4.")
@option("-6", "ipv6", is_flag=True, default=False, help="Report only IPv6.")
@click.pass_context
def cli_arp_scan(ctx: click.Context, *, network: str | None, concurrency: int, ipv4: bool, ipv6: bool) -> None:
    """Sweep a network, then report every hardware address it learned."""

    scope: SweepScope | None = None
    try:
        scope = sweep_scope(network)
        entries = arp_scan(scope=scope, concurrency=concurrency, family=_family(ipv4=ipv4, ipv6=ipv6))
    except (IPScoutError, ValueError) as exc:
        _fail(ctx, CommandName.ARP_SCAN, exc, skipped=scope.skipped if scope else ())
        return

    _emit(ctx, CommandName.ARP_SCAN, entries, lambda: console.print(_neighbour_table(entries)), skipped=scope.skipped if scope else ())
    if not entries:
        ctx.exit(EXIT_NOT_REACHED)


@cli.command("set-neighbour", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("ip")
@argument("mac")
@option("--interface", default=None, help="Interface for the entry, by name or index. Defaults to the one whose subnet holds IP.")
@click.pass_context
def cli_set_neighbour(ctx: click.Context, ip: str, mac: str, *, interface: str | None) -> None:
    """Write a permanent IPv4 neighbour entry mapping IP to MAC. Needs root, CAP_NET_ADMIN or Administrator."""

    try:
        entry = set_neighbour(ip, mac, interface=interface)
    except (IPScoutError, ValueError) as exc:
        _fail(ctx, CommandName.SET_NEIGHBOUR, exc)
        return

    _emit(ctx, CommandName.SET_NEIGHBOUR, entry, lambda: console.print(_neighbour_table((entry,))))


@cli.command("remove-neighbour", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("ip")
@option("--interface", default=None, help="Interface to remove it from, by name or index. Defaults to every interface the cache lists IP on.")
@click.pass_context
def cli_remove_neighbour(ctx: click.Context, ip: str, *, interface: str | None) -> None:
    """Delete the IPv4 neighbour entry for IP. Exits 1 when there was none."""

    try:
        removed = remove_neighbour(ip, interface=interface)
    except (IPScoutError, ValueError) as exc:
        _fail(ctx, CommandName.REMOVE_NEIGHBOUR, exc)
        return

    payload = RemoveNeighbourReport(ip=ip, interface=interface, removed=removed)
    _emit(ctx, CommandName.REMOVE_NEIGHBOUR, payload, lambda: console.print("removed" if removed else "(no entry)", highlight=False))
    if not removed:
        ctx.exit(EXIT_NOT_REACHED)


@cli.command("subnet", context_settings=CLICK_CONTEXT_SETTINGS)
@option("--interface", default=None, help="Report only this interface.")
@click.pass_context
def cli_subnet(ctx: click.Context, *, interface: str | None) -> None:
    """Show addressing, gateway and stored DHCP facts per subnet."""

    subnets = subnet_info(interface)

    def human() -> None:
        table = Table("interface", "address", "network", "broadcast", "gateway", "dns", "mtu")
        for item in subnets:
            table.add_row(
                item.interface,
                f"{item.address}/{item.prefix_len}",
                item.network,
                item.broadcast or "-",
                item.gateway or "-",
                ", ".join(item.dns_servers) or "-",
                str(item.mtu) if item.mtu else "-",
            )
        console.print(table)

    _emit(ctx, CommandName.SUBNET, subnets, human)
    if not subnets:
        ctx.exit(EXIT_NOT_REACHED)


@cli.command("scan-ports", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("host")
@option("--ports", required=True, help="Ports and ranges, as in 22,80,443,8000-8100.")
@option("--syn", is_flag=True, default=False, help="Half-open SYN scan. Needs root or CAP_NET_RAW.")
@option("--timeout", type=float, default=1.0, show_default=True, help="Seconds to wait per port.")
@option("--concurrency", type=int, default=256, show_default=True, help="Connects in flight at once.")
@click.pass_context
def cli_scan_ports(  # noqa: PLR0913 - one parameter per CLI option, which is the point of the command
    ctx: click.Context,
    host: str,
    *,
    ports: str,
    syn: bool,
    timeout: float,
    concurrency: int,
) -> None:
    """Report which ports are open, closed or filtered."""

    method = ScanMethod.SYN if syn else ScanMethod.CONNECT
    try:
        states = scan_ports(host, ports, method=method, timeout=timeout, concurrency=concurrency)
    except (IPScoutError, ValueError) as exc:
        _fail(ctx, CommandName.SCAN_PORTS, exc)
        return

    payload = PortScanReport(
        host=host,
        method=method,
        ports=tuple(PortResult(port=port, state=state) for port, state in sorted(states.items())),
    )

    def human() -> None:
        table = Table("port", "state")
        for entry in payload.ports:
            table.add_row(str(entry.port), entry.state.value)
        console.print(table)

    _emit(ctx, CommandName.SCAN_PORTS, payload, human)
    if not any(state is PortState.OPEN for state in states.values()):
        ctx.exit(EXIT_NOT_REACHED)


#: What ``--farewell`` may spell with a backslash. A shell hands the CLI the
#: two characters ``\r``; a protocol line needs the real CR, so these are the
#: escapes a farewell line can need, and anything else is refused rather than
#: guessed at.
_FAREWELL_ESCAPES = {"r": "\r", "n": "\n", "t": "\t", "\\": "\\"}


def _farewell_bytes(text: str | None) -> bytes | None:
    """Return the farewell to send, with its escapes decoded, as ASCII bytes."""

    if text is None:
        return None

    def unescape(match: re.Match[str]) -> str:
        try:
            return _FAREWELL_ESCAPES[match[1]]
        except KeyError:
            msg = f"unknown escape \\{match[1]}; use \\r, \\n, \\t or \\\\"
            raise click.BadParameter(msg, param_hint="--farewell") from None

    decoded = re.sub(r"\\(.)", unescape, text, flags=re.DOTALL)
    try:
        return decoded.encode("ascii")
    except UnicodeEncodeError:
        msg = "must be ASCII text, since it is sent as-is on the wire"
        raise click.BadParameter(msg, param_hint="--farewell") from None


def _banner_hosts(items: tuple[str, ...]) -> list[str]:
    """Return the hosts to grab: each item as given, or a network's hosts in its place.

    Raises:
        ValueError: An item with a ``/`` is not a network.
        IPScoutSweepTooWideError: The networks together hold more addresses
            than one sweep covers.
    """

    networks = [ipaddress.ip_network(item, strict=False) for item in items if "/" in item]
    total = sum(network.num_addresses for network in networks)
    if total > MAX_SWEEP_HOSTS:
        sizes = ", ".join(f"{network} holds {network.num_addresses} addresses" for network in networks)
        msg = f"{sizes}, more than the {MAX_SWEEP_HOSTS} this will sweep; pass a narrower network"
        raise IPScoutSweepTooWideError(msg)
    expanded = iter(networks)
    hosts: list[str] = []
    for item in items:
        if "/" in item:
            hosts.extend(str(address) for address in next(expanded).hosts())
        else:
            hosts.append(item)
    return hosts


@cli.command("banners", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("hosts", nargs=-1, required=True)
@option("--port", type=int, required=True, help="TCP port to read the greeting on.")
@option("--timeout", type=float, default=DEFAULT_BANNER_TIMEOUT, show_default=True, help="Seconds per host for connect and read together.")
@option("--concurrency", type=int, default=DEFAULT_BANNER_CONCURRENCY, show_default=True, help="Connections in flight at once.")
@option("--max-line-bytes", type=int, default=DEFAULT_MAX_LINE_BYTES, show_default=True, help="Most bytes of greeting kept per host.")
@option("--farewell", default=None, help="Text to send after a greeting, before closing; \\r \\n \\t \\\\ are decoded (e.g. 'QUIT\\r\\n').")
@option("-4", "ipv4", is_flag=True, default=False, help="Force IPv4.")
@option("-6", "ipv6", is_flag=True, default=False, help="Force IPv6.")
@click.pass_context
def cli_banners(  # noqa: PLR0913 - one parameter per CLI option, which is the point of the command
    ctx: click.Context,
    hosts: tuple[str, ...],
    *,
    port: int,
    timeout: float,
    concurrency: int,
    max_line_bytes: int,
    farewell: str | None,
    ipv4: bool,
    ipv6: bool,
) -> None:
    """Read the first line each host sends on a TCP port. HOSTS may include networks, as in 10.0.0.0/24."""

    goodbye = _farewell_bytes(farewell)
    family = _family(ipv4=ipv4, ipv6=ipv6)
    try:
        targets = _banner_hosts(hosts)
        results = grab_banners(targets, port, timeout=timeout, max_line_bytes=max_line_bytes, farewell=goodbye, concurrency=concurrency, family=family)
    except (IPScoutError, ValueError) as exc:
        _fail(ctx, CommandName.BANNERS, exc)
        return

    def human() -> None:
        # One column for the greeting or, when there is none, why: the state
        # column already says which of the two a row holds.
        table = Table("host", "state", "line or reason")
        for host, banner in results.items():
            table.add_row(host, banner.state.value, banner.line or banner.error or "")
        console.print(table)

    _emit(ctx, CommandName.BANNERS, results, human)
    if not any(banner.state is BannerState.GREETED for banner in results.values()):
        ctx.exit(EXIT_NOT_REACHED)


@cli.command("mtu", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("target")
@option("-4", "ipv4", is_flag=True, default=False, help="Force IPv4.")
@option("-6", "ipv6", is_flag=True, default=False, help="Force IPv6.")
@click.pass_context
def cli_mtu(ctx: click.Context, target: str, *, ipv4: bool, ipv6: bool) -> None:
    """Show the largest packet that reaches a target unfragmented."""

    try:
        value = path_mtu(target, family=_family(ipv4=ipv4, ipv6=ipv6))
    except (IPScoutError, ValueError) as exc:
        _fail(ctx, CommandName.MTU, exc)
        return

    # Labelled rather than printed bare: a lone number is also valid JSON,
    # which makes the human output indistinguishable from the machine one.
    rendered = f"path MTU to {target}: {value} bytes" if value else f"path MTU to {target}: unavailable"
    _emit(ctx, CommandName.MTU, MtuReport(target=target, mtu=value), lambda: console.print(rendered, highlight=False))
    if value is None:
        ctx.exit(EXIT_NOT_REACHED)


@cli.command("wake", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("mac")
@option("--broadcast", default="255.255.255.255", show_default=True, help="Where to send the magic packet.")
@option("--port", type=int, default=9, show_default=True, help="UDP port. The NIC matches the payload, not the port.")
@click.pass_context
def cli_wake(ctx: click.Context, mac: str, *, broadcast: str, port: int) -> None:
    """Send a wake-on-LAN magic packet."""

    try:
        wake_on_lan(mac, broadcast=broadcast, port=port)
    except (OSError, ValueError) as exc:
        _fail(ctx, CommandName.WAKE, exc)
        return

    # Nothing acknowledges a magic packet, so this reports only that it was
    # sent. Whether the host woke is a separate question, for `reachable`.
    payload = WakeReport(mac=mac, broadcast=broadcast, port=port)
    _emit(ctx, CommandName.WAKE, payload, lambda: console.print(f"magic packet sent to {broadcast}:{port}", highlight=False))


@cli.command("observe-dhcp", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("mac")
@option("--interface", default=None, help="Interface to watch. Defaults to the one carrying the default route; name the bridge for a VM.")
@option("--timeout", type=float, default=DEFAULT_TIMEOUT, show_default=True, help="Seconds to watch for the machine appearing.")
@option("--settle", type=float, default=DEFAULT_SETTLE, show_default=True, help="Seconds of quiet after the last address before answering.")
@click.pass_context
def cli_observe_dhcp(ctx: click.Context, mac: str, *, interface: str | None, timeout: float, settle: float) -> None:
    """Watch a DHCP handshake for the addresses offered to a hardware address."""

    try:
        addresses = observe_dhcp(mac, interface=interface, timeout=timeout, settle=settle)
    except (IPScoutError, ValueError) as exc:
        _fail(ctx, CommandName.OBSERVE_DHCP, exc)
        return

    payload = ObserveDhcpReport(mac=mac, interface=interface, addresses=tuple(addresses), timeout=timeout, settle=settle)
    # Printed in arrival order, and the last line is the address the machine
    # most likely settled on rather than the first. Said in the docs rather
    # than here, where it would print on every run.
    _emit(ctx, CommandName.OBSERVE_DHCP, payload, lambda: console.print("\n".join(addresses) or "(nothing offered)", highlight=False))
    if not addresses:
        ctx.exit(EXIT_NOT_REACHED)


@cli.command("capabilities", context_settings=CLICK_CONTEXT_SETTINGS)
@click.pass_context
def cli_capabilities(ctx: click.Context) -> None:
    """Report what this host can actually do.

    The machine-readable form of every "unsupported here" message, so a caller
    can find out without provoking an error first.
    """

    capabilities = _probe_capabilities()

    def human() -> None:
        # Iterating the model yields its (field, value) pairs directly. Going
        # through model_dump() would build a dict only to read fields back out
        # of it, and listing the fields here by hand would leave a capability
        # added to the report missing from this table.
        table = Table("capability", "available")
        for name, available in capabilities:
            table.add_row(name, "yes" if available else "no")
        console.print(table)

    _emit(ctx, CommandName.CAPABILITIES, capabilities, human)


def _probe_capabilities() -> CapabilityReport:
    """Return which platform capabilities this process actually has."""

    icmp_v4 = icmp_available(AddressFamily.IPV4)
    return CapabilityReport(
        icmp_ipv4=icmp_v4,
        icmp_ipv6=icmp_available(AddressFamily.IPV6),
        traceroute=_traceroute_available(icmp_v4=icmp_v4),
        dhcp_capture=dhcp_capture_available(),
    )


def _traceroute_available(*, icmp_v4: bool) -> bool:
    """Return whether expired hops can be observed here.

    Asked of a real transport rather than inferred from the platform, for the
    same reason traceroute itself refuses on the capability: setting a hop
    limit and observing its expiry come apart on macOS.
    """

    if not icmp_v4:
        return False
    if sys.platform == "win32":  # pragma: no cover - Windows only
        return True
    from .transport_posix import PosixEchoTransport  # noqa: PLC0415 - POSIX-only import, never reached on Windows

    try:
        with PosixEchoTransport("127.0.0.1", AddressFamily.IPV4) as transport:
            return transport.supports_ttl_discovery
    except IPScoutError:  # pragma: no cover - guarded by icmp_v4 above
        return False


@cli.command("info", context_settings=CLICK_CONTEXT_SETTINGS)
@click.pass_context
def cli_info(ctx: click.Context) -> None:
    """Print resolved package metadata."""

    payload = PackageInfo(
        name=__init__conf__.name,
        version=__init__conf__.version,
        title=__init__conf__.title,
        homepage=__init__conf__.homepage,
        author=__init__conf__.author,
        shell_command=__init__conf__.shell_command,
    )
    _emit(ctx, CommandName.INFO, payload, __init__conf__.print_info)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return its exit code.

    Args:
        argv: Arguments to parse. ``None`` uses ``sys.argv``.

    Returns:
        ``0`` reached, ``1`` not reached, ``2`` error. Signals and a broken
        pipe map to their conventional codes via ``lib_cli_exit_tools``.

    Note:
        Delegates to ``lib_cli_exit_tools.run_cli`` for signal handling
        (SIGINT/SIGTERM/SIGBREAK), ``BrokenPipeError`` - which a JSON-emitting
        CLI meets the moment someone pipes it into ``head`` or ``jq`` - errno
        mapping, and stream flushing. A local exception handler is injected so
        an escaping error is still serialised into the JSON envelope rather
        than printed as a traceback into a stream the caller is parsing.

        Requires ``lib_cli_exit_tools >= 2.3.4``: earlier releases discarded
        Click's return value, which would collapse the not-reached exit code
        of 1 into 0.

    Examples:
        The command prints its result, so the output is captured here to leave
        just the exit code visible.

        >>> import contextlib, io
        >>> with contextlib.redirect_stdout(io.StringIO()):
        ...     code = main(["--json", "resolve", "localhost"])
        >>> code
        0

        A host that does not answer exits 1, distinctly from an error:

        >>> with contextlib.redirect_stdout(io.StringIO()):
        ...     code = main(["--json", "reachable", "nothing.invalid"])
        >>> code
        1

    """

    argv_list = list(argv) if argv is not None else sys.argv[1:]
    # Read the output flags from argv rather than the Click context: an error
    # can escape before the context exists, and a traceback would then land in
    # a stream the caller is parsing as JSON. Both shapes count, or bare mode
    # would be the one shape whose failures are not machine-readable.
    output = OutputMode.from_argv(argv_list)
    show_traceback = "--no-traceback" not in argv_list

    lib_cli_exit_tools.config.traceback = show_traceback and output is OutputMode.HUMAN

    return lib_cli_exit_tools.run_cli(
        cli,
        argv_list,
        prog_name=__init__conf__.shell_command,
        exception_handler=_exception_handler(output),
    )


def _exception_handler(output: OutputMode) -> Callable[[BaseException], int]:
    """Return the handler run_cli should use for an escaping exception.

    Keeps ``lib_cli_exit_tools``'s exit-code mapping - signals, broken pipe,
    errno - while making sure that in either JSON mode the report is data
    rather than a traceback, in the shape that mode promised.

    Args:
        output: The mode read from argv, since an exception can escape before
            the Click context that would otherwise carry it exists.

    Returns:
        A handler mapping the exception to the process exit code.
    """

    def handle(exc: BaseException) -> int:
        # Click states its own code for a malformed invocation, and it agrees
        # with this CLI's documented 2-is-an-error. Falling through to the errno
        # mapping instead returned 1, which a script reads as "host did not
        # answer" - a wrong fact about the network from a typo in the command.
        code = exc.exit_code if isinstance(exc, click.ClickException) else lib_cli_exit_tools.get_system_exit_code(exc)
        match output:
            case OutputMode.BARE:
                click.echo(dumps(_json_error(exc)))
            case OutputMode.ENVELOPE:
                click.echo(dumps(JsonEnvelope(ok=False, error=_json_error(exc))))
            case OutputMode.HUMAN:
                lib_cli_exit_tools.print_exception_message()
        return code

    return handle
