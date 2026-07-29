"""CLI adapter wiring the behavior helpers into a rich-click interface.

Expose a stable command-line surface using rich-click for consistent,
beautiful terminal output. The CLI delegates to behavior helpers while
maintaining clean separation of concerns.

Contents:
    CLICK_CONTEXT_SETTINGS: Shared Click settings for consistent help.
    cli: Root command group with global options.
    cli_info: Print package metadata.
    cli_hello: Demonstrate success path.
    cli_fail: Demonstrate error handling.
    main: Entry point for console scripts.

Note:
    The CLI is the primary adapter for local development workflows. Packaging
    targets register the console script defined in __init__conf__. The module
    entry point (python -m) reuses the same helpers for consistency.

"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

import rich_click as click
from click.core import ParameterSource
from rich.console import Console
from rich.style import Style
from rich.traceback import Traceback
from rich.traceback import install as install_rich_traceback

from . import __init__conf__
from .behaviors import emit_greeting, noop_main, raise_intentional_failure
from .typed_click import option, version_option

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "CLICK_CONTEXT_SETTINGS",
    "CliContext",
    "cli",
    "cli_fail",
    "cli_hello",
    "cli_info",
    "console",
    "main",
]

#: Shared Click context flags for consistent help output.
CLICK_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

#: Console for rich output
console = Console()

#: Style for error messages when traceback is suppressed
_ERROR_STYLE = Style(color="red", bold=True)


@dataclass
class CliContext:
    """Typed context object for Click's ``ctx.obj``.

    Replaces an untyped dict so that every downstream command accesses
    strongly-typed attributes instead of string-keyed dictionary items.

    Attributes:
        traceback: Whether to show full Python traceback on errors.

    """

    traceback: bool = True


def _exit_code_from(exc: SystemExit) -> int:
    """Extract integer exit code from SystemExit.

    Args:
        exc: The SystemExit exception to extract the code from.

    Returns:
        Integer exit code: the code itself if int, 1 if truthy, 0 if falsy.

    Examples:
        >>> _exit_code_from(SystemExit(0))
        0
        >>> _exit_code_from(SystemExit(42))
        42
        >>> _exit_code_from(SystemExit("error"))
        1
        >>> _exit_code_from(SystemExit(None))
        0

    """
    if isinstance(exc.code, int):
        return exc.code
    return 1 if exc.code else 0


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
@option(
    "--traceback/--no-traceback",
    is_flag=True,
    default=True,
    help="Show full Python traceback on errors (default: enabled)",
)
@click.pass_context
def cli(ctx: click.Context, *, traceback: bool) -> None:
    """Root command storing global flags.

    When invoked without a subcommand, displays help unless --traceback
    is explicitly provided (for backward compatibility).

    Args:
        ctx: Click context object for the command group.
        traceback: Whether to show full Python traceback on errors.

    Examples:
        >>> from click.testing import CliRunner
        >>> runner = CliRunner()
        >>> result = runner.invoke(cli, ["hello"])
        >>> result.exit_code
        0
        >>> "Hello World" in result.output
        True

    """
    # Store traceback preference in typed context object
    ctx.ensure_object(CliContext)
    ctx.obj.traceback = traceback

    # Show help if no subcommand and no explicit option
    if ctx.invoked_subcommand is None:
        source = ctx.get_parameter_source("traceback")
        if source not in (ParameterSource.DEFAULT, None):
            # Traceback was explicitly set, run default behavior
            noop_main()
        else:
            # No subcommand and default traceback value, show help
            click.echo(ctx.get_help())


@cli.command("info", context_settings=CLICK_CONTEXT_SETTINGS)
def cli_info() -> None:
    """Print resolved metadata so users can inspect installation details."""
    __init__conf__.print_info()


@cli.command("hello", context_settings=CLICK_CONTEXT_SETTINGS)
def cli_hello() -> None:
    """Demonstrate the success path by emitting the canonical greeting."""
    emit_greeting()


@cli.command("fail", context_settings=CLICK_CONTEXT_SETTINGS)
def cli_fail() -> None:
    """Trigger the intentional failure helper to test error handling."""
    raise_intentional_failure()


def main(argv: Sequence[str] | None = None) -> int:
    """Execute the CLI and return the exit code.

    This is the entry point used by console scripts and python -m execution.

    Args:
        argv: Optional sequence of CLI arguments. None uses sys.argv.

    Returns:
        Exit code: 0 for success, non-zero for errors.

    Examples:
        >>> main(["hello"])
        Hello World
        0

    """
    argv_list = list(argv) if argv else sys.argv[1:]
    show_traceback = "--no-traceback" not in argv_list

    if show_traceback:
        install_rich_traceback(show_locals=True)

    try:
        cli(args=argv, standalone_mode=False, prog_name=__init__conf__.shell_command)
        return 0
    except SystemExit as exc:
        return _exit_code_from(exc)
    except Exception as exc:
        _print_error(exc, show_traceback=show_traceback)
        return 1


def _print_error(exc: Exception, *, show_traceback: bool) -> None:
    """Print error to console with or without full traceback.

    Args:
        exc: The exception to display.
        show_traceback: If True, show full rich traceback with locals.
            If False, show simple one-line error message.

    """
    if show_traceback:
        tb = Traceback.from_exception(
            type(exc),
            exc,
            exc.__traceback__,
            show_locals=True,
            width=120,
        )
        console.print(tb)
    else:
        console.print(f"Error: {type(exc).__name__}: {exc}", style=_ERROR_STYLE)
