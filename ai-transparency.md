# AI transparency

The author and owner of this project is the human, [@bitranox](https://github.com/bitranox).
Every design and engineering decision is theirs, and they answer for everything published here.
An AI assistant (Claude, run through the Claude Code CLI) was used as a tool along the way,
mostly for the typing and the legwork under that direction. This page says where, plainly, so
you can weigh the work on its merits. The reasoning behind working this way is in
[ai-stance.md](ai-stance.md).

## The human's work

This is a template: a scaffold other Python libraries are cloned from. Its shape is the human's,
start to finish. They set the problem and made every call.

- The problem is theirs: starting a new backward-compatible Python library re-litigates the same
  boilerplate every time, done in a hurry and slightly wrong, so the good defaults should be
  inherited once instead of retyped.
- Every structural decision was the human's: the Python 3.10 baseline chosen on purpose for
  backward compatibility; the layered split where the CLI adapter depends on the domain
  behaviors and never the reverse, enforced in CI by import-linter; the choice to generate
  package metadata into a module synced from `pyproject.toml` rather than query it at runtime;
  quarantining the one untyped third-party surface in `typed_click.py` so the rest stays strict
  under Pyright; shipping two console commands against one entry point; and driving the whole
  lint/type/test/release pipeline through bmk behind a single `make` command. Where there were
  options, the human picked.
- The human reviewed and corrected the work at each step; what ships is what they signed off on.
- Every commit went out under the human's name and authority, with no AI co-author line. The
  human is responsible for what is published.

## Where the AI was used

As a tool, under the human's direction, it did the mechanical parts: typing the modules, the
CLI, the tests and the docs to the human's design; keeping `pyproject.toml`, the metadata module
and the docs consistent with each other; laying out options at each fork for the human to choose
from; and auditing the prose against the actual code so the docs describe what the code does now,
not what an older copy did. None of the decisions, and none of the accountability, were the
AI's. The human directed and approved every action and owns the result.

## What's been checked

The template's own gate is `make test`, and it is the same gate CI runs: Ruff (lint and format),
Pyright in strict mode, the import-linter layer contract, Bandit, pip-audit, and Pytest with
coverage, including the doctests embedded in the source modules. CI runs that gate across three
operating systems (Linux, macOS, Windows) and CPython 3.10 through 3.14 on every push, and again
before a release publishes to PyPI. The badges at the top of the README report the live state.

## Checking it yourself

You do not have to take any of this on faith.

- The source is small and available. Read `src/ipscout/`; the module-by-module
  map with source anchors is in [docs/systemdesign/module_reference.md](docs/systemdesign/module_reference.md).
- The history is available too. Decisions and reversals show up over time.
- The tests live in `tests/` and the doctests live in the modules. Run `make test` and see.

If something does not line up, open an issue. That is what they are for.

## What this isn't

It is a starting point, not a framework. The shipped CLI and API are deliberately tiny (a
greeting, an intentional failure, a metadata printout) and exist only to prove that packaging,
entry points, error handling and doctests work end to end. Replace them with your own once you
clone it.

## License and attribution

The text and code here are under the MIT License (see [LICENSE](LICENSE)). Anthropic's terms put
ownership of model output with the user, so the human owns this and answers for it.
