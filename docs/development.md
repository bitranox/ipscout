# Development

The `Makefile` is a thin wrapper around [bmk](https://pypi.org/project/bmk/), the bitranox
build/test/release runner. It does not contain project logic; it forwards each target to bmk.

Do not edit the `Makefile`. Its first line (`# BMK MAKEFILE <version>`) marks it as
generated, and bmk overwrites it on upgrade. Remove that line only if you deliberately want a
custom, unmanaged Makefile.

## How bmk is wired

- bmk is installed once per machine, in uv's own tool directory, and holds only itself and
  its toolchain (pyright, ruff, and so on).
- Your project's dependencies live in the project's own `.venv`, which bmk provisions and
  syncs from `pyproject.toml`. That `.venv` is the environment your tests, pyright and
  pip-audit all run against.
- The `.venv` is disposable: delete it and the next `make` rebuilds it. bmk is re-resolved on
  every invocation, so a new bmk release is picked up automatically.

You need `uv` and `make` on PATH; bmk bootstraps itself on first use.

## Common targets

Bare words after the target are forwarded to bmk; a flag has to go through `ARGS=`
(`make test ARGS="--verbose"`), because make would parse a bare `--verbose` as its own option.
Run `make help` for the complete, authoritative list; the table below is the everyday subset.

| Target                | Aliases           | What it does                                            |
|-----------------------|-------------------|---------------------------------------------------------|
| `test`                | `t`               | Full local gate: lint, type-check, tests with coverage. |
| `test-human`          | `th`              | The same gate with human-readable output.               |
| `test-all`            |                   | Run pytest + pyright on every declared Python version.  |
| `testintegration`     | `testi`, `ti`     | Integration tests only (`-m integration`).              |
| `codecov`             | `coverage`, `cov` | Upload the coverage report to Codecov.                  |
| `build`               | `bld`             | Build wheel and sdist.                                  |
| `run`                 |                   | Run the project CLI.                                    |
| `clean`               | `cln`, `cl`       | Remove build artifacts and caches.                      |
| `clean-all`           |                   | As `clean`, and delete every `.venv*` too.              |
| `ensure`              |                   | Install missing external tools for this OS.             |
| `bump-patch`          |                   | Bump patch version `X.Y.(Z+1)`.                         |
| `bump-minor`          |                   | Bump minor version `X.(Y+1).0`.                         |
| `bump-major`          |                   | Bump major version `(X+1).0.0`.                         |
| `commit`              | `c`               | Commit with a timestamped message.                      |
| `push`                | `psh`, `p`        | Run tests, commit, and push.                            |
| `release`             | `rel`, `r`        | Create a versioned release (tag + GitHub release).      |
| `ship`                | `sh`              | Push, wait for CI, release, wait for release CI.        |
| `dependencies`        | `deps`, `d`       | Check and list project dependencies.                    |
| `dependencies-update` |                   | Update dependencies to their latest versions.           |
| `dev`                 |                   | Editable install with dev extras.                       |
| `install`             |                   | Editable install, no dev extras.                        |
| `info`                |                   | Print resolved package metadata.                        |
| `version-current`     |                   | Print the current version.                              |

## What `make test` runs

`make test` is the single local gate and runs the same checks CI does: Ruff (lint + format
check), Pyright in strict mode, import-linter (the layer contract in `[tool.importlinter]`), Bandit,
pip-audit, and Pytest with coverage (including the doctests in the source modules, with a floor of
85 percent), plus ShellCheck and PSScriptAnalyzer for any shell or PowerShell scripts. It runs
against the project `.venv`, which bmk syncs first, so the result matches what CI sees.

It is not read-only. Before the checks it raises the dependency floors in `pyproject.toml`,
refreshes `uv.lock`, and applies `ruff format` and `ruff check --fix` to the tree, and bmk may
regenerate the `Makefile`. Review `git diff` afterwards and commit that churn with your change.

## Tests

`make test` deselects the `integration` marker; run those with `make testintegration`. The markers
are declared under `[tool.pytest.ini_options]` in `pyproject.toml`:

| Marker                                           | Meaning                                                                                                                                |
|--------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `os_agnostic`                                    | Runs everywhere.                                                                                                                       |
| `os_windows`, `os_macos`, `os_linux`, `os_posix` | Skipped on any other platform by `tests/conftest.py`.                                                                                  |
| `integration`                                    | Reaches the real network; skips when there is no route out.                                                                            |
| `local_only`                                     | Needs something only a developer's network has; CI always deselects it, and `tests/test_snmp_device.py` also skips without its target. |
| `host_mutating`                                  | Changes this host's network state; skipped unless `IPSCOUT_HOST_WRITE_TESTS=1`.                                                        |

Environment variables that switch on live tests:

| Variable                      | Effect                                                                                |
|-------------------------------|---------------------------------------------------------------------------------------|
| `IPSCOUT_HOST_WRITE_TESTS=1`  | Runs the `host_mutating` tests. They also need the privilege the operation needs.     |
| `IPSCOUT_SNMP_TEST_HOST`      | Address of a real SNMP agent for `tests/test_snmp_device.py`; unset skips the module. |
| `IPSCOUT_SNMP_TEST_COMMUNITY` | Community string for that agent. Defaults to `public`.                                |
| `IPSCOUT_SNMP_TEST_V1_ONLY=1` | Declares the agent v1-only, which enables the test that v2c gets no answer.           |

For example, against an agent at a documentation address:

```bash
IPSCOUT_SNMP_TEST_HOST=192.0.2.10 .venv/bin/python -m pytest tests/test_snmp_device.py
```

## Commit messages

Pass a commit message with `MSG=`, not `ARGS=`:

```bash
make push MSG="fix(cli): correct exit code on --no-traceback"
```

`ARGS=` is re-parsed by the shell, so punctuation like `( ) ; $ \`` breaks or executes and a
newline is impossible. `MSG=` is passed through the environment and is safe for any text. With
no message, `make push fix the thing` also works: bare trailing words become a plain one-line
message.

## Versioning and metadata

- `pyproject.toml` `[project]` is the single source of truth for version and metadata.
- `src/ipscout/__init__conf__.py` holds static constants synced from
  `pyproject.toml` by automation; `make bump-*`, `make commit` and `make push` regenerate them.
  Runtime code imports these constants instead of querying `importlib.metadata`.
- Bump only `pyproject.toml` and `CHANGELOG.md`; never hand-edit the version in code.
- The console command names live in `pyproject.toml` `[project.scripts]`.

## Releasing

1. Bump the version (`make bump-patch` / `-minor` / `-major`) and update `CHANGELOG.md`.
2. `make release` tags the commit and creates the GitHub release, or `make ship` pushes,
   waits for CI to pass, then releases.
3. CI publishes to PyPI from the tag. Publishing uses hybrid auth: the `PYPI_API_TOKEN`
   secret when set, otherwise an OIDC Trusted Publisher.

## Continuous integration

Workflows live under `.github/workflows/` and are managed by the shared
`default_cicd_public` template. Do not edit them in this repo.

- `default_cicd_public.yml` - on every push and pull request to `main`, and nightly: lint,
  type-check and test on `ubuntu-latest` and `windows-latest` with CPython 3.10 through 3.15, and
  on `macos-latest` with the newest of them only; then build, verify a `pipx` and `uv tool`
  install of the wheel, and execute `notebooks/Quickstart.ipynb`. The Python versions come from
  the `Programming Language :: Python :: X.Y` classifiers and the operating systems from
  `[tool.ci] os` in `pyproject.toml`.
- `default_release_public.yml` - on a `v*` tag (or a manual dispatch), build and publish to PyPI.
- `codeql.yml` - CodeQL security analysis.

> `.github/` is off-limits for manual edits. Change CI by editing the `default_cicd_public`
> template and redistributing it, never by editing this repo's `.github/`.
