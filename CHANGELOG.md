# Changelog

All notable changes to this project will be documented in this file following
the [Keep a Changelog](https://keepachangelog.com/) format.

## [Unreleased]

## [1.1.3] 2026-07-24 15:56:45

### Changed
- Pinned the lint policy explicitly: added the curated `[tool.ruff.lint].select` list (the same
  family set as `bitranox_template_py_cli`) plus matching `tests/*.py` per-file-ignores, so a future
  ruff release widening its default rule set no longer reddens CI with hundreds of unrelated
  findings.
- Made the root `cli` group callback's `traceback` parameter keyword-only (`PLR0917`); Click still
  invokes it via `**ctx.params`, so no call site changed.

### Fixed
- Replaced `print()` with `sys.stdout.write()` in `__init__conf__.print_info()` (`T201`), matching the
  established fix in `bitranox_template_py_cli`.
- Sorted `__all__` in `behaviors.py` (`RUF022`) and normalized import ordering across `src` and
  `tests` (`I001`, `TC002`, `TC003`).

## [1.1.2] 2026-06-14

### Changed
- Added a `typed_click.py` facade wrapping rich-click's `option` / `version_option` decorators behind explicit, fully-known signatures, keeping the CLI strict-clean under pyright (`reportUnknownMemberType`) without disabling the rule (ignore isolated to the facade).

## [1.1.1] - 2026-02-18

### Added
- `__all__` export declaration in `__init__conf__.py` for consistent public API surface

### Fixed
- Pin `rtoml` and `pip-audit` versions for Python 3.9 compatibility
- Ignore `filelock` transitive dependency vulnerabilities in pip-audit

## [1.1.0] - 2026-02-18

### Added
- `WritableStream` Protocol for narrower stream typing in `behaviors.py`
- `CliContext` dataclass replacing untyped dict for Click context storage
- Dynamic CI matrix extracting Python versions from pyproject.toml classifiers
- Pydantic models for typed TOML parsing in test suite
- Test covering `SystemExit` branch in `cli.main()` for 100% cli.py coverage
- `pydantic` added to dev dependencies

### Changed
- Replace `TextIO` with `WritableStream` Protocol for honest, minimal typing
- Rename `ERROR_STYLE` to `_ERROR_STYLE` (private convention)
- Replace `scripts/` Python build system with bmk-based Makefile targets
- CI workflows renamed and modernized (`default_cicd_public.yml`, `default_release_public.yml`)
- Use stdlib `tomllib` instead of `rtoml` in CI setup job
- Update dev dependency pins (pydantic, ruff, pyright, bandit, etc.)

### Fixed
- CI `IndexError` in Python version parsing by switching to stdlib `tomllib`
- Inconsistent spacing in pip-audit ignore-vulns list
- Undeclared `local_only` pytest marker

### Removed
- `scripts/` directory (replaced by bmk Makefile targets)
- `CLAUDE.md` project instructions file (moved to project-level config)

## [1.0.3] - 2025-12-15

### Changed
- Move deferred imports to module top in `cli.py` for better readability
- Modernize type hints: `Optional[X]` replaced with `X | None` syntax
- Use `collections.abc.Sequence` instead of `typing.Sequence`
- Extract `_exit_code_from()` helper function with comprehensive doctests
- Extract `_print_error()` helper function for cleaner error handling
- Add `ERROR_STYLE` module-level constant for error message styling
- Add typed context documentation comment for Click context dict

### Added
- Add `__all__` export list to `cli.py` for explicit public API surface

### Fixed
- Remove unused `strip_ansi` fixture parameter from test functions
- Remove unused `Callable` import from `test_cli.py`

## [1.0.2] - 2025-12-15

### Changed
- Update CI/CD workflows to use latest GitHub Actions (cache@v5, upload-artifact@v6)
- Update dev dependencies: ruff 0.14.9, textual 6.9.0, import-linter 2.9
- Switch scripts to use rtoml for TOML parsing

### Added
- Add rtoml to dev dependencies

## [1.0.1] - 2025-12-08

### Changed
- Update dependencies to latest versions
- Update CI/CD workflows and configuration
- Convert docstrings to Google style
- Set coverage output to JSON to avoid SQL locks

## [1.0.0] - 2025-11-04
- Bootstrap `ipscout`
