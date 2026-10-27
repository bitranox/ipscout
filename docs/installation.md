# Installation

`ipscout` is a normal PEP 621 package. Every method below registers one console command on your
PATH: `ipscout`.

The examples use [uv](https://docs.astral.sh/uv/), a fast Rust-based replacement for `pip`, `venv`,
`pipx` and `poetry`. Nothing here requires uv; the plain `pip` equivalents follow.

## Requirements

- Python 3.10 or newer. 3.10 is the floor, and the code stays inside it deliberately: the enums
  subclass `str` rather than using `StrEnum`, which arrived in 3.11. CI tests CPython 3.10 through
  3.15 on Linux and Windows, and the newest of them on macOS.
- Runtime dependencies, installed automatically:

| Package              | Floor  | Why it is there                                             |
|----------------------|--------|-------------------------------------------------------------|
| `lib_cli_exit_tools` | 2.4.1  | Signal handling, broken-pipe and errno mapping for the CLI. |
| `pydantic`           | 2.14.1 | The frozen result models and their validation.              |
| `rich-click`         | 1.9.9  | The CLI itself.                                             |

No compiler, no system `ping` binary, and no administrator or root rights are needed to install it,
or to run the default paths (ping, ping sweeps, traceroute on Linux and Windows, interfaces, routes,
the neighbour cache, connect port scans, banners, SNMP, wake-on-LAN). The few operations that do
need privilege are listed under [Operations that need privilege](#operations-that-need-privilege).

## Install uv (optional)

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
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

Installs into an isolated environment and puts the command on your PATH:

```bash
uv tool install ipscout
uv tool upgrade ipscout
# from GitHub:
uv tool install --from "git+https://github.com/bitranox/ipscout.git" ipscout
```

## 3. Run once, without installing (uvx)

```bash
uvx ipscout ping 127.0.0.1
uvx ipscout capabilities
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
`~/.local/bin` is on your PATH so the command is found.

## 6. pipx

```bash
pipx install ipscout
pipx upgrade ipscout
```

## 7. From build artifacts

```bash
pip install build                  # or skip both lines and run: uv build
python -m build
pip install dist/ipscout-*.whl
```

## Verify the install

```bash
ipscout --version
ipscout capabilities
```

`capabilities` reports what this particular host can do, which is more useful than a version string
when something later refuses to run:

```bash
ipscout --json-bare capabilities
```

```json
{
  "icmp_ipv4": true,
  "icmp_ipv6": true,
  "traceroute": true,
  "dhcp_capture": false
}
```

That is an ordinary user on Linux: ICMP and traceroute work unprivileged, while `dhcp_capture`
(`observe-dhcp`) needs root, `CAP_NET_RAW` or Administrator. The library answers the same
questions with `ipscout.icmp_available()` and `ipscout.dhcp_capture_available()`.

## Hardened hosts: unprivileged ICMP may be switched off

On Linux, the unprivileged ping socket is gated by a sysctl. `net.ipv4.ping_group_range` names the
range of group IDs allowed to open one, and some distributions, containers and CI runners ship it
locked down to an empty range. ipscout then falls back to trying a raw socket, and when that also
fails it raises `IPScoutPermissionError` with a message naming every fix.

Check the current setting:

```bash
sysctl net.ipv4.ping_group_range
# net.ipv4.ping_group_range = 0	2147483647   -> every group may open one
# net.ipv4.ping_group_range = 1	0            -> nobody may (low above high is an empty range)
```

Pick whichever fix suits the host:

```bash
# 1. allow every group to open a ping socket (needs root once)
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
# persist it across reboots
echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee /etc/sysctl.d/99-ping-group-range.conf

# 2. or grant the interpreter the capability, leaving the sysctl alone
sudo setcap cap_net_raw+ep "$(readlink -f .venv/bin/python)"
```

`readlink -f` is needed because `setcap` must name the real file, not a symlink. A virtual
environment's `python` is a symlink to the base interpreter, so the capability lands on that shared
binary and every script run with it gains raw sockets. Prefer the sysctl where that matters.

The third option needs no root at all: pass `allow_tcp_fallback=True` (or `--tcp-fallback` on the
CLI) and probe over TCP instead. Read the result's `method` field before treating those numbers as
ICMP round trips, because they are not.

Windows and macOS have no equivalent switch. Windows goes through `iphlpapi.dll`, which any process
may call, and macOS ships the unprivileged ICMP datagram socket enabled.

## Operations that need privilege

Everything outside this table runs as an ordinary user. Each of these raises
`IPScoutPermissionError` when the privilege is missing, and the message names the fix. The two
exceptions raise `IPScoutUnsupportedError` instead: an unprivileged traceroute on macOS, and any SYN
scan on Windows, where no privilege level helps.

| Operation                                    | Linux                   | macOS | Windows                                   |
|----------------------------------------------|-------------------------|-------|-------------------------------------------|
| `traceroute`                                 | none                    | root  | none                                      |
| `observe-dhcp` / `observe_dhcp`              | root or `CAP_NET_RAW`   | root  | Administrator                             |
| `set-neighbour`, `remove-neighbour`          | root or `CAP_NET_ADMIN` | root  | Administrator                             |
| `scan-ports --syn` / `method=ScanMethod.SYN` | root or `CAP_NET_RAW`   | root  | not supported (raw TCP sends are blocked) |
| `mac --active` / `lookup_mac(active=True)`   | root or `CAP_NET_RAW`   | root  | none                                      |

On Linux the refusal message spells the grant as
`setcap cap_net_raw+ep $(readlink -f $(which python3))`, with `cap_net_admin` in place of
`cap_net_raw` for the neighbour-table writes. The same symlink caution as above applies.
Unprivileged alternatives exist for two of them: `arp_scan()` resolves the same addresses as an
active lookup, and a connect port scan (the default) needs no privilege.
