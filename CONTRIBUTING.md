# Contributing

Thanks for helping improve **ipscout**. This page covers the day-to-day
workflow and the checks a change must pass before it merges. For the tooling details, see
[docs/development.md](docs/development.md).

## 1. Workflow

1. Fork and branch with a short, imperative name (`feature/cli-extension`, `fix/exit-code`).
2. Keep commits focused; leave unrelated refactors out of the change.
3. Run `make test` locally before pushing.
4. Update the docs and `CHANGELOG.md` for anything your change affects.
5. Open a pull request and reference any relevant issues.

## 2. Commits and pushes

- Write imperative commit subjects (`Add rich handler`, `Fix CLI exit codes`).
- `make test` runs the full lint/type/test pipeline and leaves the working tree untouched.
- `make push` runs the tests, commits, and pushes. Pass the message with `MSG="..."` (safe for
  any punctuation or newline); `make push fix the thing` also works for a plain one-line
  message. See [docs/development.md](docs/development.md#commit-messages).

## 3. Coding standards

- Follow the Clean Architecture / SOLID rules in `CLAUDE.md` and the system prompts it lists.
- Keep the layer direction intact: `cli` depends on `behaviors`, never the reverse. CI
  enforces this with import-linter.
- Prefer small, single-purpose modules and functions.
- `snake_case` for functions and modules, `PascalCase` for classes.
- Modern type hints (`X | None` over `Optional[X]`), Google-style docstrings with doctests.
- All imports at module top; declare the public surface with `__all__`.
- Keep runtime dependencies minimal; reach for the standard library where practical.

## 4. Tests

- `make test` runs Ruff (lint + format check), Pyright (strict), import-linter, Bandit,
  pip-audit, and Pytest with coverage, including the module doctests. It runs against the
  project `.venv`, which bmk syncs first.
- Name tests for the behavior under test and keep each case focused.
- Mark OS constraints with the provided markers (`@pytest.mark.os_agnostic`,
  `@pytest.mark.os_windows`, and the rest declared in `pyproject.toml`).
- When you add or change a CLI behavior or metadata, update the matching test in
  `tests/test_cli.py`, `tests/test_metadata.py`, or `tests/test_module_entry.py`.

## 5. Before opening a PR

- [ ] `make test` passes locally.
- [ ] Docs (`README.md`, `docs/*`) are updated for the change.
- [ ] No build artifacts or virtual environments are committed.
- [ ] Version bumps touch **only** `pyproject.toml` and `CHANGELOG.md`.

## 6. Security and configuration

- Never commit secrets. Tokens (Codecov, PyPI) belong in `.env` (git-ignored) or CI secrets.
- Sanitize any payload before you log or render it.
