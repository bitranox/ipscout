# Installation

`ipscout` is a normal PEP 621 package. Every method below registers two
console commands on your PATH: `ipscout` and `bitranox-template-py-cli`
(both point at the same CLI).

The examples use [uv](https://docs.astral.sh/uv/), a fast Rust-based replacement for
`pip`, `venv`, `pipx` and `poetry`. Nothing here requires uv; the plain `pip` equivalents
follow.

## Requirements

- Python 3.10 or newer.
- Runtime dependencies (installed automatically): `rich-click` for the CLI, and `rtoml`
  for TOML parsing (`rtoml>=0.13`).

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
uv pip install ipscout
# from GitHub instead of PyPI:
uv pip install "git+https://github.com/bitranox/ipscout"
```

## 2. As a persistent CLI tool (uv)

Installs into an isolated environment and puts the commands on your PATH:

```bash
uv tool install ipscout
uv tool upgrade ipscout
# from GitHub:
uv tool install --from "git+https://github.com/bitranox/ipscout.git" bitranox-template-py-cli
```

## 3. Run once, without installing (uvx)

```bash
uvx ipscout info
uvx --from "git+https://github.com/bitranox/ipscout.git" ipscout info
```

## 4. Plain pip

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install ipscout
# from GitHub:
pip install "git+https://github.com/bitranox/ipscout"
# editable, with dev tooling, for working on the package itself:
pip install -e ".[dev]"
```

## 5. Per-user install (no virtualenv)

```bash
pip install --user ipscout
```

This respects PEP 668, so it is refused on an externally-managed system Python. Make sure
`~/.local/bin` is on your PATH so the commands are found.

## 6. pipx

```bash
pipx install ipscout
pipx upgrade ipscout
```

## 7. From build artifacts

```bash
python -m build
pip install dist/ipscout-*.whl
```
