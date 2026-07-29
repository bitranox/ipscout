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

import sys
from typing import TYPE_CHECKING, Any

import lib_cli_exit_tools
import rich_click as click
from pydantic import BaseModel, ConfigDict
from rich.console import Console
from rich.style import Style
from rich.table import Table

from . import __init__conf__
from .api import is_reachable, ping, ping_many
from .errors import IPScoutError
from .factory import icmp_available
from .interfaces import local_interfaces
from .models import (
    AddressFamily,
    CapabilityReport,
    CommandName,
    JsonEnvelope,
    JsonError,
    PackageInfo,
    ReachabilityReport,
    ResolveReport,
    ReverseDnsReport,
    RouteInfo,
)
from .resolve import resolve as resolve_target
from .resolve import reverse_dns
from .routes import default_gateway, query_route
from .serialize import dumps, to_jsonable
from .traceroute import traceroute
from .typed_click import argument, option, version_option

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

__all__ = [
    "CLICK_CONTEXT_SETTINGS",
    "CliContext",
    "cli",
    "console",
    "main",
]

#: Shared Click context flags for consistent help output.
CLICK_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

#: Console for rich output.
console = Console()

#: Style for error messages when traceback is suppressed.
_ERROR_STYLE = Style(color="red", bold=True)

#: Exit codes. Independent of output format.
EXIT_OK = 0
EXIT_NOT_REACHED = 1
EXIT_ERROR = 2


class CliContext(BaseModel):
    """Typed context object for Click's ``ctx.obj``.

    Attributes:
        traceback: Show a full Python traceback on an unexpected error.
        json_output: Emit the JSON envelope instead of human-readable text.
        json_bare: Emit the payload at top level, without the envelope.

    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    traceback: bool = True
    json_output: bool = False
    json_bare: bool = False

    @property
    def machine_readable(self) -> bool:
        """Return whether output should be JSON in either of its two shapes."""

        return self.json_output or self.json_bare


def _context(ctx: click.Context) -> CliContext:
    """Return the typed context object, creating it if a command runs alone."""

    if not isinstance(ctx.obj, CliContext):
        ctx.obj = CliContext()
    return ctx.obj


def _emit(ctx: click.Context, command: CommandName, payload: Any, human: Callable[[], None]) -> None:
    """Render one command's result in whichever format was asked for.

    Args:
        ctx: The Click context carrying the output flags.
        command: The subcommand name, echoed into the envelope so a transcript
            of several calls stays unambiguous.
        payload: The data to serialise when a JSON mode is active.
        human: Callable that prints the human-readable rendering.

    Note:
        Every command routes through here. That is deliberate: a per-command
        ``if json:`` branch is exactly the kind of thing that gets added on the
        success path and forgotten everywhere else.

    """

    state = _context(ctx)
    if state.json_bare:
        click.echo(dumps(payload))
        return
    if state.json_output:
        envelope = JsonEnvelope(ok=True, command=command, data=to_jsonable(payload))
        click.echo(dumps(envelope))
        return
    human()


def _fail(ctx: click.Context, command: CommandName, exc: Exception) -> None:
    """Report a failure in the active output format, then exit non-zero."""

    state = _context(ctx)
    if state.json_output:
        envelope = JsonEnvelope(ok=False, command=command, error=JsonError(type=type(exc).__name__, message=str(exc)))
        click.echo(dumps(envelope))
    else:
        console.print(f"Error: {type(exc).__name__}: {exc}", style=_ERROR_STYLE, highlight=False)
    ctx.exit(EXIT_ERROR)


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
@option("--traceback/--no-traceback", is_flag=True, default=True, help="Show a full Python traceback on unexpected errors.")
@click.pass_context
def cli(ctx: click.Context, *, json_output: bool, json_bare: bool, traceback: bool) -> None:
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

    if json_output and json_bare:
        msg = "--json and --json-bare are mutually exclusive; pick one output shape"
        raise click.UsageError(msg)

    ctx.obj = CliContext(traceback=traceback, json_output=json_output, json_bare=json_bare)
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command("ping", context_settings=CLICK_CONTEXT_SETTINGS)
@argument("target")
@option("--times", "-c", type=int, default=4, show_default=True, help="Echoes to send.")
@option("--timeout", type=float, default=2.0, show_default=True, help="Seconds to wait per reply.")
@option("--interval", type=float, default=0.2, show_default=True, help="Seconds between echoes.")
@option("-4", "ipv4", is_flag=True, default=False, help="Force IPv4.")
@option("-6", "ipv6", is_flag=True, default=False, help="Force IPv6.")
@option("--tcp-fallback", is_flag=True, default=False, help="Fall back to a TCP connect when ICMP is unavailable.")
@option("--tcp-port", type=int, default=443, show_default=True, help="Port for the TCP fallback.")
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
@option("--times", "-c", type=int, default=4, show_default=True, help="Echoes per target.")
@option("--timeout", type=float, default=2.0, show_default=True, help="Seconds to wait per reply.")
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
@option("--timeout", type=float, default=2.0, show_default=True, help="Seconds to allow per attempt.")
@option("--tcp-port", type=int, default=443, show_default=True, help="Port for the TCP attempt.")
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


@cli.command("capabilities", context_settings=CLICK_CONTEXT_SETTINGS)
@click.pass_context
def cli_capabilities(ctx: click.Context) -> None:
    """Report what this host can actually do.

    The machine-readable form of every "unsupported here" message, so a caller
    can find out without provoking an error first.
    """

    capabilities = _probe_capabilities()

    def human() -> None:
        table = Table("capability", "available")
        for name, available in capabilities.model_dump().items():
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
    # Read the output flag from argv rather than the Click context: an error
    # can escape before the context exists, and a traceback would then land in
    # a stream the caller is parsing as JSON.
    as_json = "--json" in argv_list or "-j" in argv_list
    show_traceback = "--no-traceback" not in argv_list

    lib_cli_exit_tools.config.traceback = show_traceback and not as_json

    return lib_cli_exit_tools.run_cli(
        cli,
        argv_list,
        prog_name=__init__conf__.shell_command,
        exception_handler=_exception_handler(as_json=as_json),
    )


def _exception_handler(*, as_json: bool) -> Callable[[BaseException], int]:
    """Return the handler run_cli should use for an escaping exception.

    Keeps ``lib_cli_exit_tools``'s exit-code mapping - signals, broken pipe,
    errno - while making sure that in JSON mode the report is data rather than
    a traceback.
    """

    def handle(exc: BaseException) -> int:
        code = lib_cli_exit_tools.get_system_exit_code(exc)
        if as_json:
            envelope = JsonEnvelope(ok=False, error=JsonError(type=type(exc).__name__, message=str(exc)))
            click.echo(dumps(envelope))
            return code
        lib_cli_exit_tools.print_exception_message()
        return code

    return handle
