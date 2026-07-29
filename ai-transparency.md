# AI transparency

The author and owner of this project is the human, [@bitranox](https://github.com/bitranox).
Every design and engineering decision is theirs, and they answer for everything published here.
An AI assistant (Claude, run through the Claude Code CLI) was used as a tool along the way,
mostly for the typing and the legwork under that direction. This page says where, plainly, so
you can weigh the work on its merits. The reasoning behind working this way is in
[ai-stance.md](ai-stance.md).

## The human's work

The human set the problem and every constraint that shaped the answer. Those constraints are
what the library is: remove either one and a much easier design becomes available.

- **The problem is theirs.** Probing reachability from Python normally means spawning `ping` and
  scraping its output, which is locale-dependent and costs a process per host, or reaching for a
  library that quietly needs root. They wanted neither.
- **The two hard constraints are theirs**, stated at the outset and never relaxed: it must not
  shell out, and it must work without administrator rights. Everything difficult here follows
  from those - the unprivileged ping socket, the `iphlpapi` ctypes path on Windows, the ARP,
  netlink and routing-socket parsers, the refusal to read another program's prose as an API.
- **The decisions at every fork were theirs.** The strict error contract, where setup problems
  raise and network conditions are reported as data. Keeping `ping` and its result type as the
  public surface. The Python 3.10 floor. The JSON envelope for machine consumers, defaulting to
  the envelope rather than the bare payload. Adopting `lib_cli_exit_tools`, and fixing and
  releasing it first rather than working around it. Making `make test` the gate rather than a
  hand-picked subset. Converting every record to a validated model. Naming the project.
- **They overrode the assistant where it was too cautious.** Active address resolution and SYN
  scanning need root on most platforms, and the assistant proposed leaving them out on those
  grounds. The human's call was to implement them anyway and fail with a clear permission error
  instead. That was the better call, and acting on it exposed a capability that had been gated
  on the operating system when the real distinction was the socket type.
- **They set the standards the work is held to**: no workaround where a root cause is findable,
  no suppressed type errors, documentation that describes the code as it is rather than how it
  came to be, and every commit under the human's name and authority with no AI co-author line.

## Where the AI was used

As a tool, under the human's direction, it did the mechanical and the laborious parts: writing
the modules, the CLI, the tests and the documentation to the human's design; the byte-level
parsers for netlink, BSD routing sockets, ARP, ICMP and the Windows IP Helper structures; laying
out the options at each fork for the human to choose between; and keeping `pyproject.toml`, the
metadata module, the docs and the shipped skill consistent with the code.

It was also used to check its own work, which is the part worth being specific about. Platform
behaviour here was measured rather than assumed - on real CI runners across Linux, macOS and
Windows - and several defects were found that way rather than by reading code: a decoder that
discarded every reply on macOS, a default-gateway lookup that answered with loopback, a table
that printed field names instead of addresses, a capability gated on the wrong thing. The git
history records each one and what it cost.

None of the decisions, and none of the accountability, were the AI's. The human directed and
approved every action and owns the result.

## What's been checked

The gate is `make test`, and it is the same gate CI runs: Ruff (lint and format), Pyright in
strict mode, the import-linter layer contract, Bandit, pip-audit, and Pytest with coverage,
including the doctests embedded in the source modules. CI runs it across three operating systems
(Linux, macOS, Windows) and CPython 3.10 through 3.14 on every push, and again before a release
publishes to PyPI. The badges at the top of the README report the live state.

That matrix is not decoration. A single-platform run passes on code that is broken on the other
two, and it did so more than once here; every such case was caught by CI and fixed before
release.

## Checking it yourself

You do not have to take any of this on faith.

- The source is small and available. Read `src/ipscout/`; the module-by-module map with source
  anchors is in [docs/systemdesign/module_reference.md](docs/systemdesign/module_reference.md).
- The history is available too. Decisions, mistakes and reversals all show up in it.
- The tests live in `tests/` and the doctests live in the modules. Run `make test` and see.
- The claims this project makes about other libraries are checkable at the source they cite.

If something does not line up, open an issue. That is what they are for.

## What this isn't

It is not a scanner to point at networks you do not own, and it is not a substitute for the
tools that need privilege to do more. Where a capability genuinely requires elevation it says
so and names what is missing, rather than degrading to something weaker under the same name.

## License and attribution

The text and code here are under the MIT License (see [LICENSE](LICENSE)). Anthropic's terms put
ownership of model output with the user, so the human owns this and answers for it.
