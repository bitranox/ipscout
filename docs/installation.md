# Installation

`lib_ping` is a normal PEP 621 package. Every method below registers two
console commands on your PATH: `lib_ping` and `bitranox-template-py-cli`
(both point at the same CLI).

The examples use [uv](https://docs.astral.sh/uv/), a fast Rust-based replacement for
`pip`, `venv`, `pipx` and `poetry`. Nothing here requires uv; the plain `pip` equivalents
follow.

## Requirements

- Python 3.9 or newer.
- Runtime dependencies (installed automatically): `rich-click` for the CLI, and `rtoml`
  for TOML parsing (`rtoml>=0.13` on Python 3.10+, `rtoml>=0.12,<0.13` on 3.9).

## Install uv (optional)

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
# or, with an existing Python
python -m pip install uv
```

## 1. Into a virtual environment (uv)

```bash
uv venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
uv pip install lib_ping
# from GitHub instead of PyPI:
uv pip install "git+https://github.com/bitranox/lib_ping"
```

## 2. As a persistent CLI tool (uv)

Installs into an isolated environment and puts the commands on your PATH:

```bash
uv tool install lib_ping
uv tool upgrade lib_ping
# from GitHub:
uv tool install --from "git+https://github.com/bitranox/lib_ping.git" bitranox-template-py-cli
```

## 3. Run once, without installing (uvx)

```bash
uvx lib_ping info
uvx --from "git+https://github.com/bitranox/lib_ping.git" lib_ping info
```

## 4. Plain pip

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install lib_ping
# from GitHub:
pip install "git+https://github.com/bitranox/lib_ping"
# editable, with dev tooling, for working on the package itself:
pip install -e ".[dev]"
```

## 5. Per-user install (no virtualenv)

```bash
pip install --user lib_ping
```

This respects PEP 668, so it is refused on an externally-managed system Python. Make sure
`~/.local/bin` is on your PATH so the commands are found.

## 6. pipx

```bash
pipx install lib_ping
pipx upgrade lib_ping
```

## 7. From build artifacts

```bash
python -m build
pip install dist/lib_ping-*.whl
```
