# Module Reference: lib_ping

## Status

Template / Scaffold (v1.1.2)

## Links & References

**Repository:** https://github.com/bitranox/lib_ping
**PyPI:** https://pypi.org/project/lib-ping/
**Documentation:** README.md, INSTALL.md, DEVELOPMENT.md, CONTRIBUTING.md, CHANGELOG.md
**Related Files:**

* src/lib_ping/__init__.py (public API surface)
* src/lib_ping/behaviors.py (domain behaviors)
* src/lib_ping/cli.py (rich-click CLI adapter)
* src/lib_ping/typed_click.py (strict-typed click decorator wrappers)
* src/lib_ping/__init__conf__.py (static metadata / platform adapter)
* src/lib_ping/__main__.py (python -m entry point)
* src/lib_ping/py.typed (PEP 561 marker)
* tests/test_behaviors.py, tests/test_cli.py, tests/test_metadata.py, tests/test_module_entry.py

---

## Problem Statement

Starting a new backward-compatible Python library that ships a registered CLI command
means re-solving the same structural problems every time:

1. A clean separation between the command-line transport and the domain logic it calls.
2. A single, auditable source of package metadata that stays in sync with `pyproject.toml`.
3. A strict-typed (pyright) codebase without disabling rules for third-party gaps.
4. Consistent entry points for both console scripts and `python -m` execution.
5. Enforced import contracts so the transport never leaks into the domain layer.

This package is the scaffold that answers those once, so a new library starts from a
working, tested, lint-clean baseline rather than an empty `src/`.

---

## Solution Overview

`lib_ping` provides:

1. **Layered Skeleton** - CLI adapter, domain behaviors, and a metadata/platform adapter
   with enforced dependency direction.
2. **Placeholder Domain** - `emit_greeting`, `raise_intentional_failure`, and `noop_main`
   exercise the success, failure, and no-op paths end to end.
3. **rich-click CLI** - `info`, `hello`, and `fail` commands plus a global
   `--traceback/--no-traceback` toggle.
4. **Strict Typing** - pyright strict mode, with the single untyped third-party boundary
   isolated in `typed_click.py`.
5. **Generated Metadata** - constants in `__init__conf__.py` kept in sync with
   `pyproject.toml` by development automation, so runtime code never queries
   `importlib.metadata`.

---

## Architecture Integration

**Layer Structure:**
```
CLI Layer (cli.py, typed_click.py, __main__.py)
    | imports
Domain Layer (behaviors.py)              <- no framework dependencies
    ^
    | imports (metadata only)
Platform Adapter (__init__conf__.py)     <- static package metadata
```

**Data Flow:**
1. A console script or `python -m` invocation calls `cli.main()`.
2. `main()` installs the rich traceback handler (unless suppressed) and dispatches
   the click command group.
3. Each command delegates to a behavior helper (`emit_greeting`, `raise_intentional_failure`)
   or to `__init__conf__.print_info()`.
4. Exit codes are normalized: 0 on success, the `SystemExit` code when raised, 1 on a
   caught exception.

**Dependency Direction:** CLI depends on behaviors, never the reverse. This is enforced in
CI by import-linter (`tool.importlinter` contract "CLI depends on behaviors only").

**Dependencies:**
* **Runtime:** `rich-click>=1.9.8`, `rtoml` (version-split for the Python 3.9 baseline).
* **Development:** pytest, ruff, pyright, bandit, build, twine, import-linter, pip-audit,
   pydantic, textual (install with the `[dev]` extra).

---

## Core Components

### `__init__` Module (Public API)

Re-exports the stable public surface so importers depend on the package, not its internal
module layout.

**Exports:** `CANONICAL_GREETING`, `WritableStream`, `emit_greeting`, `noop_main`,
`print_info`, `raise_intentional_failure`.

**Location:** src/lib_ping/__init__.py

---

### `behaviors` Module (Domain Layer)

Framework-free helpers that other modules import instead of duplicating literals.

#### `WritableStream` (Protocol)

**Purpose:** Structural type for any object exposing `write(str) -> object`. `flush` is
optional and duck-typed at runtime.

**Location:** src/lib_ping/behaviors.py:29

---

#### `CANONICAL_GREETING`

**Purpose:** Single source of the greeting text (`"Hello World"`) shared by the CLI and tests.

**Location:** src/lib_ping/behaviors.py:39

---

#### `emit_greeting(*, stream: WritableStream | None = None) -> None`

**Purpose:** Write the canonical greeting plus a newline to the target stream, flushing when
the stream supports it.

**Input:** `stream` (optional) - text stream to receive the greeting; defaults to
`sys.stdout`.

**Output:** None (writes to the stream).

**Location:** src/lib_ping/behaviors.py:62

**Example:**
```python
from io import StringIO
from lib_ping import emit_greeting

buffer = StringIO()
emit_greeting(stream=buffer)
assert buffer.getvalue() == "Hello World\n"
```

---

#### `raise_intentional_failure() -> None`

**Purpose:** Always raise `RuntimeError("I should fail")` so transports and tests can exercise
failure and traceback handling.

**Raises:** `RuntimeError` unconditionally.

**Location:** src/lib_ping/behaviors.py:92

---

#### `noop_main() -> None`

**Purpose:** Explicit placeholder callable for tools that expect a module-level `main` while
the domain is still stubbed. Performs no work.

**Location:** src/lib_ping/behaviors.py:113

---

### `cli` Module (Transport Adapter)

Wires the behavior helpers into a rich-click interface.

#### `CliContext` (dataclass)

**Purpose:** Typed replacement for Click's untyped `ctx.obj` dict.

**Attributes:** `traceback: bool = True` - whether to show a full traceback on error.

**Location:** src/lib_ping/cli.py:59

---

#### Command group: `cli`

**Purpose:** Root group carrying the global `--traceback/--no-traceback` flag and the
`--version` option. With no subcommand and a default flag value it prints help.

**Location:** src/lib_ping/cli.py:99

---

#### Command: `info`

**Purpose:** Print resolved package metadata via `__init__conf__.print_info()`.

**Location:** src/lib_ping/cli.py:151

---

#### Command: `hello`

**Purpose:** Demonstrate the success path by emitting the canonical greeting.

**Location:** src/lib_ping/cli.py:157

---

#### Command: `fail`

**Purpose:** Demonstrate error handling by calling `raise_intentional_failure()`.

**Location:** src/lib_ping/cli.py:163

---

#### `main(argv: Sequence[str] | None = None) -> int`

**Purpose:** Entry point for console scripts and `python -m`. Installs the rich traceback
handler unless `--no-traceback` is present, dispatches the command group, and returns a
normalized exit code.

**Input:** `argv` (optional) - argument sequence; `None` uses `sys.argv[1:]`.

**Output:** Exit code (0 success, `SystemExit` code when raised, 1 on caught exception).

**Location:** src/lib_ping/cli.py:169

---

### `typed_click` Module (Type Boundary)

**Purpose:** Wrap click's `option` and `version_option` behind fully-known signatures so the
rest of the CLI stays strict-clean under pyright. The only `# pyright: ignore` for this
third-party gap lives here.

**Exports:** `option`, `version_option`.

**Location:** src/lib_ping/typed_click.py

---

### `__init__conf__` Module (Platform Adapter)

**Purpose:** Expose static package metadata (name, title, version, homepage, author,
`shell_command`, and the `LAYEREDCONF_*` identifiers for lib_layered_config paths) as
module-level constants, kept in sync with `pyproject.toml` by automation.

**Key function:** `print_info() -> None` renders the metadata block for the CLI `info`
command.

**Location:** src/lib_ping/__init__conf__.py

---

### `__main__` Module (Module Entry Point)

**Purpose:** Bridge `python -m lib_ping` to `cli.main()`, exiting with its
return code.

**Location:** src/lib_ping/__main__.py

---

## Implementation Details

**Exit-code normalization (`_exit_code_from`):**
1. Return the `SystemExit.code` when it is an int.
2. Otherwise return 1 when the code is truthy, 0 when falsy.

**Traceback handling:**
- `main()` inspects `argv` for `--no-traceback`; when absent it installs the rich traceback
  handler with locals.
- On a caught exception `_print_error` renders either a full rich `Traceback` (with locals)
  or a single red one-line message, depending on the toggle.

**Metadata sync:**
- Constants in `__init__conf__.py` mirror `pyproject.toml`. After changing project metadata,
  `make test` regenerates the module before commit, so runtime code never calls
  `importlib.metadata`.

---

## Testing Approach

**Test modules:**
- `tests/test_behaviors.py` - domain helpers (`emit_greeting`, `raise_intentional_failure`,
  `noop_main`) and the `WritableStream` contract.
- `tests/test_cli.py` - command dispatch, exit codes, and the traceback toggle.
- `tests/test_metadata.py` - metadata constants and `print_info` rendering.
- `tests/test_module_entry.py` - the `python -m` entry point.
- `tests/conftest.py` - shared fixtures.

**Doctests:** enabled via `--doctest-modules` (see `tool.pytest.ini_options`), so the
docstring examples in `behaviors.py`, `cli.py`, and `__init__conf__.py` run as tests.

**OS markers:** `os_agnostic`, `os_windows`, `os_macos`, `os_posix`, `os_linux`, and
`local_only` scope tests to platforms and to local-only runs (skipped in CI).

**Coverage gate:** `fail_under = 85` over `src/lib_ping`.

---

## Known Limitations & Future Enhancements

**By design (do not "fix"):**
- Python 3.9 baseline is intentional for backward compatibility with older applications.
- `from __future__ import annotations` is kept across modules for consistency and forward
  compatibility.
- The domain layer is a placeholder: `emit_greeting`, `raise_intentional_failure`, and
  `noop_main` exist to prove the wiring, not to provide features.

**When adapting this template:**
- Replace the placeholder behaviors with the library's real domain logic.
- Extend the import-linter contract as new layers are added.
- Keep the metadata constants and `pyproject.toml` in sync via the automation.

---

## Security Considerations

- **No untrusted input:** the CLI commands take no external data; `emit_greeting` writes only
  the constant greeting.
- **Type boundary isolated:** the single untyped third-party surface is quarantined in
  `typed_click.py`; the rest is strict-typed.
- **Dependency hygiene:** `pip-audit` runs in CI; known-unfixable advisories are pinned in
  `tool.pip-audit.ignore-vulns` with rationale, and `codecov-cli` is commented out (not
  deleted) to avoid dragging click below the CVE-2026-7246 fix.

---

## Documentation & Resources

**Internal References:**
* README.md - overview and usage
* INSTALL.md - installation, including the `[dev]` extra
* DEVELOPMENT.md - developer workflow and make targets
* CONTRIBUTING.md - contribution guidelines
* CHANGELOG.md - version history

**External References:**
* rich-click documentation: https://github.com/ewels/rich-click
* Click documentation: https://click.palletsprojects.com/
* import-linter documentation: https://import-linter.readthedocs.io/
* PEP 561 (py.typed): https://peps.python.org/pep-0561/

---

## Version History

**v1.1.2 (2026-06-14):**
- Added `typed_click.py` facade wrapping rich-click's `option` / `version_option` decorators
  behind explicit signatures, keeping the CLI strict-clean under pyright without disabling the
  rule.

**v1.1.1 (2026-02-18):**
- Added `__all__` to `__init__conf__.py`; pinned `rtoml` / `pip-audit` for the 3.9 baseline.

**v1.1.0 (2026-02-18):**
- Added the `WritableStream` Protocol for narrower stream typing in `behaviors.py`.

---

## Quick Reference

```python
# Python API
from lib_ping import (
    CANONICAL_GREETING,
    WritableStream,
    emit_greeting,
    noop_main,
    print_info,
    raise_intentional_failure,
)

from io import StringIO

buffer = StringIO()
emit_greeting(stream=buffer)  # writes "Hello World\n"
```

```bash
# CLI usage
lib_ping info          # print resolved metadata
lib_ping hello         # emit the canonical greeting
lib_ping fail          # exercise the failure path
lib_ping --no-traceback fail   # one-line error, no traceback

python -m lib_ping hello       # module entry point
```
