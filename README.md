# ipscout

<!-- Badges -->
[![CI](https://github.com/bitranox/ipscout/actions/workflows/default_cicd_public.yml/badge.svg)](https://github.com/bitranox/ipscout/actions/workflows/default_cicd_public.yml)
[![CodeQL](https://github.com/bitranox/ipscout/actions/workflows/codeql.yml/badge.svg)](https://github.com/bitranox/ipscout/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Open in Codespaces](https://img.shields.io/badge/Codespaces-Open-blue?logo=github&logoColor=white&style=flat-square)](https://codespaces.new/bitranox/ipscout?quickstart=1)
[![PyPI](https://img.shields.io/pypi/v/ipscout.svg)](https://pypi.org/project/ipscout/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/ipscout.svg)](https://pypi.org/project/ipscout/)
[![Code Style: Ruff](https://img.shields.io/badge/Code%20Style-Ruff-46A3FF?logo=ruff&labelColor=000)](https://docs.astral.sh/ruff/)
[![codecov](https://codecov.io/gh/bitranox/ipscout/graph/badge.svg?token=cMExEFiuhI)](https://codecov.io/gh/bitranox/ipscout)
[![Maintainability](https://qlty.sh/badges/041ba2c1-37d6-40bb-85a0-ec5a8a0aca0c/maintainability.svg)](https://qlty.sh/gh/bitranox/projects/ipscout)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

Ping, traceroute and local-network inspection in pure Python. No subprocess, and no admin rights on the default paths.

## What it does

- **Ping and sweep**: ICMP echo to one host or thousands concurrently, sync or async, as an
  ordinary user, with round-trip times, jitter and packet loss on a typed result.
- **Traceroute and path MTU**: the hops to a target, and the largest packet that reaches it
  unfragmented.
- **Ports and services**: a connect (or, with privilege, half-open SYN) port scan, the first line
  each host sends on a port (FTP, SMTP, SSH greetings), and the SNMP system group (uptime, sysName,
  sysDescr, sysObjectID).
- **Hardware addresses**: the MAC for an address with its scope (the host's own, or the next-hop
  router's), the hosts holding a MAC, a subnet sweep, the neighbour cache, and a static IPv4
  neighbour entry written and removed.
- **The local host**: interfaces, subnets with their stored DHCP facts, the default gateway and the
  route toward any address, name resolution both ways, and wake-on-LAN.
- **DHCP observation**: watch a handshake to learn the address a machine that is not up yet is
  given.
- **An error contract you can alert on**: a network condition is an answer, a setup problem raises
  with a message that names the fix, and the CLI's `--json` envelope carries a failure as data.

## Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [A red light that cannot go grey is decoration](#a-red-light-that-cannot-go-grey-is-decoration)
- [The public API at a glance](#the-public-api-at-a-glance)
- [More than ping](#more-than-ping)
- [Output for machines](#output-for-machines)
- [For LLMs and coding agents](#for-llms-and-coding-agents)
- [Platform matrix](#platform-matrix)
- [Limitations worth knowing before you depend on it](#limitations-worth-knowing-before-you-depend-on-it)
- [Architecture](#architecture)
- [Further Documentation](#further-documentation)

## Installation

```bash
uv pip install ipscout          # into the active virtual environment
uv tool install ipscout         # the ipscout command, in its own environment
uvx ipscout capabilities        # run once, without installing
pip install ipscout             # without uv
```

Python 3.10 or newer. Runtime dependencies: `lib_cli_exit_tools`, `pydantic`, `rich-click`.

Full instructions, including per-user installs, `pipx` and installing from GitHub, are in
[docs/installation.md](docs/installation.md).

### Why we recommend uv: supply-chain protection

This repository commits a `uv.lock`. It pins every package the project needs, transitive
dependencies included, to an exact version and to the hashes of that version's files. The
`exclude-newer` setting under `[tool.uv]` in `pyproject.toml` adds a cooldown: uv leaves any
release younger than that out of the lock. CI installs from the lock, so a hijacked release that
gets pulled again within the cooldown never reaches our builds, and a file whose hash does not
match is refused.

That protection stays in this repository. The installable package declares only lower bounds
(`>=`) for its dependencies, so a plain `pip install` takes the newest release of every transitive
dependency at the moment you run it. If one of them was hijacked an hour earlier, you get the
hijacked version. `pipx install` and `uv tool install` without options do the same.

To install the command line tool with a cooldown of your own (uv then skips any release younger
than 7 days, transitive ones included), or to run the exact tree our CI tests:

```bash
uv tool install --exclude-newer "7 days" ipscout
git clone https://github.com/bitranox/ipscout.git && cd ipscout && uv sync --locked && uv run ipscout --help
```

If you depend on ipscout in your own project, give that project the same cooldown (7 days here, as
an example) and commit the `uv.lock` that `uv add ipscout` writes:

```toml
[tool.uv]
exclude-newer = "7 days"
```

## Quick Start

### As a library

```python
import ipscout

result = ipscout.ping("127.0.0.1", 2, interval=0)
print(result.reached, result.ip, round(result.time_avg_ms, 3))
print(result.str_result)

# a whole sweep, concurrently, from synchronous code
results = ipscout.ping_many(["127.0.0.1", "::1"], times=1)
print({target: r.reached for target, r in results.items()})

# the shortcut that never raises and always falls back to TCP
print(ipscout.is_reachable("127.0.0.1"))
print(ipscout.is_reachable("nothing.invalid"))
```

The error contract is the point of the library, so it is worth stating once:

```python
import ipscout

# a network condition is an answer, not an error
down = ipscout.ping("192.0.2.1", 1, timeout=0.5)
assert down.reached is False

# a setup problem raises
try:
    ipscout.ping("nothing.invalid")
except ipscout.IPScoutResolutionError as exc:
    print(f"that is a name problem, not a down host: {exc}")

# or ask for the failure on the result instead of as an exception
muted = ipscout.ping("nothing.invalid", raise_on_error=False)
assert muted.reached is False and muted.error is not None
```

Every deliberate failure derives from `ipscout.IPScoutError`: `IPScoutPermissionError` (a missing
privilege), `IPScoutResolutionError` (a name that does not resolve, or has no address in the family
asked for), `IPScoutUnsupportedError` (no backend on this platform) and `IPScoutSweepError` (a sweep
that cannot run as asked, also a `ValueError`), with its subclasses `IPScoutSweepTooWideError` and
`IPScoutSweepIncompleteError`. A malformed argument raises `ValueError`.

Async works the same way, and on Linux and macOS it is genuinely async:

```python
import asyncio
import ipscout


async def main():
    result = await ipscout.aping("127.0.0.1", 1)
    sweep = await ipscout.aping_many(["127.0.0.1", "::1"], times=1)
    return result.reached, {t: r.reached for t, r in sweep.items()}


print(asyncio.run(main()))
```

### From the shell

```bash
ipscout ping 127.0.0.1 -c 2
ipscout ping-many 127.0.0.1 ::1 -c 1
ipscout reachable example.com
ipscout traceroute example.com --max-hops 10 --resolve-names
ipscout scan-ports 192.0.2.10 --ports 22,80,443,8000-8100
sudo ipscout scan-ports 192.0.2.10 --ports 1-1024 --syn          # half-open, needs a raw socket
ipscout banners 192.0.2.0/24 --port 21 --farewell 'QUIT\r\n'     # what each host says first
ipscout snmp-system 192.0.2.0/28        # uptime, name and description over SNMP
ipscout mac 203.0.113.9                 # a routed address: the gateway's MAC, labelled next_hop
ipscout mac 192.0.2.7 --active          # ask the network instead of reading the cache
ipscout find-ip 00:00:5e:00:53:42 --scan
ipscout arp-scan --network 192.0.2.0/24
ipscout neighbours
sudo ipscout set-neighbour 192.0.2.7 00:00:5e:00:53:07 --interface eth0   # a static entry
sudo ipscout remove-neighbour 192.0.2.7 --interface eth0
ipscout gateway
ipscout gateway --to 203.0.113.9        # the next hop toward one address
ipscout subnet
ipscout mtu example.com
ipscout wake 00:00:5e:00:53:01 --broadcast 192.0.2.255
sudo ipscout observe-dhcp 00:00:5e:00:53:01 --interface br0 --timeout 120
ipscout resolve localhost
ipscout reverse-dns 203.0.113.9
ipscout interfaces
ipscout capabilities
ipscout info
ipscout --help
```

`python -m ipscout` and `uvx ipscout` run the same entry point. Every subcommand takes `--help`.
`snmp-system` reads its community from `--community` or, preferably, the `IPSCOUT_SNMP_COMMUNITY`
environment variable, since an argument is visible in the process list.

## A red light that cannot go grey is decoration

Most reachability code answers every question you ask it. Host down? `reached=False`. No permission
to send ICMP? `reached=False`. Typo in the hostname? `reached=False`. It never raises, never refuses,
never once makes anybody feel uncertain. That gets sold as robustness. It is closer to a witness who
answers every question confidently: pleasant company, useless in court. The valuable thing a witness
can say is "I do not know", precisely because saying it is expensive.

So the interesting bug in that design is never a crash. It is the afternoon somebody spends hunting
a network fault that does not exist, because a monitoring job reported a rack of machines as
unreachable when the real story was that the container it ran in had lost `CAP_NET_RAW`. The
software was working perfectly. It answered instantly, confidently and wrongly, and confidence is
the part that costs you the afternoon.

Underneath sits a second habit worth naming, because half the ecosystem has it: running `/bin/ping`
and reading its output with regular expressions. That is treating a human interface as an API. The
output of `ping` is prose written for a tired admin at 2am, and it changes with locale, with
distribution, with the phase of the moon. We build alerting on top of a message that was never
addressed to us, then blame the network when the message changes.

The obvious, efficient answer is the one everybody reaches for: call the system binary, it is
already installed and battle-tested, why reinvent it. Set that aside for a second and look at what
it actually buys. One process per host. A parser that fails silently in a Turkish locale. And on
some platforms, a request for administrator rights, which people read not as a technical
requirement but as a claim about your character. Asking for root is cheap in engineering and
expensive in trust.

ipscout does less on purpose, and works in more places as a result. It sends ICMP from the process
you already have, through the unprivileged ping socket on Linux and macOS and through `iphlpapi.dll`
on Windows. Nothing is spawned. Nothing needs elevation. And when it genuinely cannot do the job, it
says so with an exception whose message names the fix, instead of handing you a tidy `False` and
letting you find out at 2am.

Go and try the one experiment that matters: take whatever probes your hosts today, revoke its ICMP
permission, and see whether the dashboard tells you the truth or tells you a story.

## The public API at a glance

Everything below is importable from `ipscout` and listed in `ipscout.__all__`. An `a`-prefixed twin
is the coroutine version of the same call. Results are frozen Pydantic models (`ResponseObject`,
`TraceHop`, `Banner`, `SnmpSystem`, `MacLookup`, `Neighbour`, `Interface`, `RouteInfo`,
`SubnetInfo`, `SweepScope`, ...) and fixed values are enums (`AddressFamily`, `PortState`,
`MacScope`, `MacMethod`, `ScanMethod`, `SnmpVersion`, ...).

| Call                                                         | Returns                     | What it answers                                                                 |
|--------------------------------------------------------------|-----------------------------|---------------------------------------------------------------------------------|
| `ping(target, times=4)` / `aping`                            | `ResponseObject`            | ICMP echo; raises on a setup problem unless `raise_on_error=False`              |
| `ping_many(targets)` / `aping_many`                          | `dict[str, ResponseObject]` | Many targets concurrently; `raise_on_error` defaults to `False` here            |
| `is_reachable(target)` / `ais_reachable`                     | `bool`                      | Alive by ICMP or TCP; never raises, a bad name is `False`                       |
| `icmp_available(family=AddressFamily.IPV4)`                  | `bool`                      | Whether this process can send ICMP                                              |
| `traceroute(target, max_hops=30)` / `atraceroute`            | `list[TraceHop]`            | The hops to a target                                                            |
| `trace_path(transport)` / `atrace_path`                      | `list[TraceHop]`            | The same walk over an echo transport you supply                                 |
| `path_mtu(target)`                                           | `int \| None`               | Largest unfragmented packet; `None` where the platform cannot report it         |
| `resolve(target)` / `reverse_dns(ip)`                        | `list[str]` / `str \| None` | Name to addresses; address to its PTR name                                      |
| `scan_ports(host, ports, method=ScanMethod.CONNECT)`         | `dict[int, PortState]`      | Open, closed or filtered per port; `ascan_ports` is the connect-only async twin |
| `parse_ports("22,80,8000-8100")`                             | `list[int]`                 | A port specification as the scan reads it                                       |
| `grab_banners(hosts, port, farewell=None)` / `agrab_banners` | `dict[str, Banner]`         | The first line each host sends; the CLI also expands networks                   |
| `read_snmp_system(hosts)` / `aread_snmp_system`              | `dict[str, SnmpSystem]`     | sysUpTime, sysName, sysDescr, sysObjectID; SNMP v1 (default) or v2c             |
| `lookup_mac(ip, active=False, fallback_to_cache=False)`      | `MacLookup`                 | The MAC with its scope (`DIRECT`, `NEXT_HOP`, `UNKNOWN`) and how it was learned |
| `get_mac_address(ip)`                                        | `str \| None`               | The MAC of an on-link host only; `None` for anything routed                     |
| `normalise_mac(mac)`                                         | `str \| None`               | Any common spelling as `aa:bb:cc:dd:ee:ff`, or `None`                           |
| `neighbours(family=None)`                                    | `tuple[Neighbour, ...]`     | The neighbour (ARP/NDP) cache                                                   |
| `arp_scan(network=None)`                                     | `tuple[Neighbour, ...]`     | Sweep, then every hardware address learned                                      |
| `find_ip_by_mac(mac, scan=False, network=None)`              | `list[str]`                 | The addresses holding a MAC; `network` needs `scan=True`                        |
| `sweep_scope(network=None, limit=4096)`                      | `SweepScope`                | What a sweep would cover, and what it leaves out as too wide                    |
| `set_neighbour(ip, mac, interface=None)`                     | `Neighbour`                 | Writes a permanent IPv4 entry, read back from the cache (needs elevation)       |
| `remove_neighbour(ip, interface=None)`                       | `bool`                      | Deletes an IPv4 entry; `False` when there was none (needs elevation)            |
| `local_interfaces()`                                         | `list[Interface]`           | Interfaces with their addresses                                                 |
| `local_networks()`                                           | `tuple[IPv4Network, ...]`   | The IPv4 subnets a default sweep covers                                         |
| `default_gateway(family=AddressFamily.IPV4)`                 | `RouteInfo \| None`         | The default route                                                               |
| `query_route(destination)`                                   | `RouteInfo \| None`         | The next hop toward one address                                                 |
| `subnet_info(interface=None)`                                | `tuple[SubnetInfo, ...]`    | Addressing, gateway, MTU and stored DHCP facts per subnet                       |
| `wake_on_lan(mac, broadcast="255.255.255.255", port=9)`      | `None`                      | Sends a magic packet to an IPv4 address                                         |
| `observe_dhcp(mac, interface=None, timeout=60, settle=12)`   | `list[str]`                 | Every address offered to a MAC, in order (needs elevation)                      |
| `observe_dhcp_session(mac, ...)`                             | `DhcpSession`               | The same watch as a context manager: `offers()`, `result()`, `stop()`           |
| `observe_dhcp_first_reachable(mac, tcp_port=22)`             | `str \| None`               | The first offered address that answers on a TCP port                            |
| `dhcp_capture_available()`                                   | `bool`                      | Whether this process may capture DHCP                                           |
| `print_info()`                                               | `None`                      | Prints the package metadata                                                     |

Every keyword and its bounds are in the docstrings, and [docs/usage.md](docs/usage.md) has worked
examples.

## More than ping

The same surface is available as a library, and most of it needs no elevation:

```python
import ipscout

ipscout.lookup_mac("203.0.113.9")  # a routed address: the router's MAC, scope NEXT_HOP
ipscout.find_ip_by_mac(mac, scan=True)  # sweep, then search the refreshed cache
ipscout.arp_scan("192.0.2.0/24")  # every hardware address on a subnet
ipscout.sweep_scope()  # what a default sweep covers, and what is too wide for it
ipscout.default_gateway()  # and query_route() for any destination
ipscout.subnet_info()  # addressing, gateway, stored DHCP facts
ipscout.scan_ports(host, "22,80,8000-8100")
ipscout.grab_banners(hosts, 21, farewell=b"QUIT\r\n")  # each host's first line, on one connection
ipscout.read_snmp_system(hosts)  # uptime, sysName, sysDescr, sysObjectID; a falling uptime is a restart
ipscout.path_mtu("example.com")
ipscout.wake_on_lan(mac, broadcast="192.0.2.255")
ipscout.observe_dhcp(mac, interface="br0")  # a machine that has no address yet (needs elevation)
ipscout.set_neighbour(ip, mac, interface="eth0")  # a static neighbour entry (needs elevation)
ipscout.remove_neighbour(ip, interface="eth0")  # and out again
```

A MAC address does not survive a router hop, so `lookup_mac` puts the scope in the answer and
`get_mac_address` returns `None` for anything routed rather than passing off the gateway's as the
host's. Every answer also says in `method` whether it was asked for (`active=True`) or read from the
cache, and `fallback_to_cache=True` reads the cache only when this host cannot ask actively.

A sweep with no network given covers the subnets this host is attached to that fit inside one
sweep's 4096-address budget, and names the ones left out - a container bridge on a `/16` is skipped
rather than cancelling the sweep, and a search that matched nothing while a network went uncovered
raises `IPScoutSweepIncompleteError` instead of reporting "not found".

One call is different in kind: `observe_dhcp` watches a DHCP handshake, so it is the only way here
to find a machine that is not up yet - everything else needs the target already answering. It
returns every address offered, in order, because a pool that hands out an address the guest
declines offers the working one afterwards and the last is the one that stuck. On macOS name the
guest's member port, not the bridge: a macOS bridge is refused with `IPScoutUnsupportedError`.

`set_neighbour` writes a permanent IPv4 entry mapping an address to a hardware address - the way an
embedded device such as a print server is first given an address, since it answers whatever address
the sender maps to its MAC - and returns the entry as read back from the cache; `remove_neighbour`
takes it out again. Writing needs root or `CAP_NET_ADMIN` on Linux, root on macOS and Administrator
on Windows, and an IPv6 address is refused with `IPScoutUnsupportedError`.

A half-open scan (`method=ScanMethod.SYN`, `--syn`) is IPv4 only, needs root or `CAP_NET_RAW` on
Linux and macOS, and raises `IPScoutUnsupportedError` on Windows, which blocks raw TCP sends. It
never falls back to a connect scan. Full worked examples are in [docs/usage.md](docs/usage.md).

## Output for machines

Every command takes a global `--json` / `-j`, which wraps the result in an envelope, or
`--json-bare`, which emits the payload at the top level for `jq`. Both go before the subcommand.

```bash
ipscout --json ping 127.0.0.1 -c 1
```

```json
{
  "ok": true,
  "command": "ping",
  "data": {
    "target": "127.0.0.1",
    "reached": true,
    "ip": "127.0.0.1",
    "number_of_pings": 1,
    "rtts_ms": [
      0.056
    ],
    "packets_sent": 1,
    "packets_received": 1,
    "family": "ipv4",
    "method": "icmp",
    "error": null,
    "time_min_ms": 0.056,
    "time_avg_ms": 0.056,
    "time_max_ms": 0.056,
    "jitter_ms": -1.0,
    "n_packets_lost": 0,
    "packets_lost_percentage": 0,
    "str_result": "[127.0.0.1] pinged 1 times, min: 0.06ms, avg: 0.06ms, max: 0.06ms, 0% Packet loss"
  },
  "error": null,
  "skipped": []
}
```

The envelope's fields:

- `ok`: `true` exactly when `error` is `null`.
- `command`: the subcommand, or `null` when the command line itself was refused before one ran.
- `data`: the command's result, `null` on failure.
- `error`: `{"type": <exception class name>, "message": <text>}` on failure, else `null`.
- `skipped`: the networks a sweeping command (`arp-scan`, `find-ip --scan`) left out; the same list
  is printed as a note on stderr in every mode.

Failures come back as data in the same envelope, not as a traceback in the stream you are parsing:

```bash
ipscout --json ping nothing.invalid
```

```json
{
  "ok": false,
  "command": "ping",
  "data": null,
  "error": {
    "type": "IPScoutResolutionError",
    "message": "cannot resolve 'nothing.invalid': Name or service not known"
  },
  "skipped": []
}
```

With `--json-bare` a failure prints the `error` object alone. Exit codes are independent of the
output format:

| Code | Meaning                                                                                                                                                                                                                               |
|------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0    | A positive answer: reached, found, or the command otherwise succeeded.                                                                                                                                                                |
| 1    | A negative answer: nothing answered, or no PTR record, MAC, route, neighbour entry, open port, greeting, SNMP answer, path MTU or DHCP offer was found. For a command over several hosts, only when none of them gave a positive one. |
| 2    | Error. A bad name, a missing permission, a capability this host lacks, or a malformed command line.                                                                                                                                   |

An unanticipated exception or a signal exits through `lib_cli_exit_tools`' own mapping instead,
for example 130 for Ctrl-C and 141 for a broken pipe.

## For LLMs and coding agents

The JSON envelope above is half the story. The other half is that an agent has to pick the right
tool in the first place, and the popular answers to "ping a host from Python" quietly need
administrator rights. So this repo is also a Claude Code plugin marketplace, and it ships a skill:

```
/plugin marketplace add bitranox/ipscout
/plugin install ipscout
```

The skill covers the parts an agent otherwise guesses at: that ICMP here needs no elevation and
spawns nothing, that setup problems raise while network conditions do not, that `--json` exists so a
failure arrives as data rather than a traceback, and which platform limits are real. It also names
the alternatives that fail the no-admin requirement and why, `icmplib` in particular, whose
`privileged=False` reads as "no elevation needed" and is overridden on Windows.

It documents only what this release actually exposes, and says so explicitly, so an agent asked for
a MAC address looks the API up instead of inventing a plausible call.

The same skill is available from the [bitranox marketplace](https://github.com/bitranox/bitranox-skills)
as `coding-python-network-probe`.

## Platform matrix

Measured on real CI runners, not assumed.

| Capability                    | Linux                                                      | macOS                                                                                                 | Windows                                       |
|-------------------------------|------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|-----------------------------------------------|
| ICMP ping, no admin           | yes, `SOCK_DGRAM`/`IPPROTO_ICMP`                           | yes, `SOCK_DGRAM`/`IPPROTO_ICMP`                                                                      | yes, `iphlpapi.dll` via ctypes                |
| Traceroute                    | yes, `IP_RECVERR` + `MSG_ERRQUEUE`                         | as root, raw ICMP socket; unprivileged raises `IPScoutUnsupportedError`                               | yes, `IP_TTL_EXPIRED_TRANSIT`                 |
| Async on the event loop       | yes, one socket per probe                                  | yes, one socket per probe                                                                             | no, `IcmpSendEcho` runs in an executor        |
| Interface listing             | yes, `getifaddrs`                                          | yes, `getifaddrs`                                                                                     | yes, `GetAdaptersAddresses`                   |
| Observing a DHCP handshake    | yes, `AF_PACKET`, needs root or `CAP_NET_RAW`              | yes, `/dev/bpf`, needs root; watch a member port, a bridge is refused (measured on a macOS runner VM) | yes, `SIO_RCVALL`, needs Administrator        |
| Static neighbour entry (IPv4) | yes, netlink `RTM_NEWNEIGH`, needs root or `CAP_NET_ADMIN` | yes, routing socket `RTM_ADD`, needs root (measured on a macOS runner VM)                             | yes, `CreateIpNetEntry2`, needs Administrator |

Ask the host itself rather than guessing, with `ipscout capabilities` (ICMP per family, traceroute,
DHCP capture) or `ipscout.icmp_available()` and `ipscout.dhcp_capture_available()`.

## Limitations worth knowing before you depend on it

**Traceroute on macOS needs root.** This was measured on a macOS runner: `MSG_ERRQUEUE` is not
defined there, and a plain receive on the unprivileged ICMP socket surfaces nothing, so an
unprivileged process never sees ICMP Time Exceeded. As root, `traceroute` opens a raw ICMP socket,
which receives it. Unprivileged, it raises `IPScoutUnsupportedError` rather than returning a column
of silent hops that would look like a broken network instead of a missing feature. Linux and Windows
need no privilege.

**Async on Windows is executor-backed.** `IcmpSendEcho` is a blocking C call with no asyncio
integration. `aping` behaves identically there, but a sweep of thousands is bounded by a thread pool
rather than running on one socket on one thread as it does on Linux and macOS.

**On a host with unprivileged ICMP disabled, ipscout raises.** Some CI runners and hardened Linux
boxes lock `net.ipv4.ping_group_range`. ipscout tries a raw socket second, and if that also fails it
raises `IPScoutPermissionError` whose message lists the three fixes: set
`sysctl -w net.ipv4.ping_group_range="0 2147483647"`, grant the process `CAP_NET_RAW`, or pass
`allow_tcp_fallback=True` to probe over TCP instead.

**The TCP fallback is not ICMP and is never chosen for you.** A TCP round trip includes the
handshake and a filtered port reads as unreachable on a healthy host, so every result carries a
`method` field and you have to opt in (`allow_tcp_fallback=True`, or `--tcp-fallback` on the CLI).
`is_reachable` is the single deliberate exception: it never raises and always tries TCP, because
that is the entire point of a yes-or-no shortcut.

**It is not zero-dependency.** Four runtime dependencies, listed under [Installation](#installation).

## Architecture

The package is layered, and `make test` enforces it with one import-linter `layers` contract
(`[tool.importlinter]` in `pyproject.toml`): a module imports only from the layers below its own,
and the modules sharing a layer do not import each other. The CLI (`cli`, with `serialize` and
`typed_click`) sits outside the contract, on top of the public package.

| Layer (top to bottom)                                                                                                                              | Responsibility                                                                     |
|----------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|
| `scan`, `subnet`, `portscan`, `banner`, `snmp`, `mtu`, `wol`, `dhcp`                                                                               | Sweeps and MAC search, subnet facts, ports, banners, SNMP, path MTU, WoL, DHCP     |
| `api`                                                                                                                                              | `ping`, `ping_many`, `is_reachable` and their async twins; owns the error contract |
| `traceroute`                                                                                                                                       | The hop walk                                                                       |
| `static_neighbours`                                                                                                                                | Writing and removing a static IPv4 neighbour entry                                 |
| `neighbours`                                                                                                                                       | Neighbour-cache reads and `lookup_mac`                                             |
| `leases_linux`                                                                                                                                     | The DHCP facts the OS's own client stored                                          |
| `interfaces`, `routes`                                                                                                                             | Choose the interface and route backend for this platform                           |
| `service`                                                                                                                                          | Sequences probes over a transport and aggregates the result                        |
| `factory`                                                                                                                                          | Chooses the transport for this platform, family and options                        |
| `transport_*`, `interfaces_*`, `routes_*`, `neighbours_*`, `dhcp_*`                                                                                | The per-platform backends (Linux, macOS, Windows, TCP)                             |
| `packet`, `bootp`, `snmpber`, `arp`, `tcpsyn`, `netlink`, `bsdroute`, `bpf`, `winapi`, `resolve`, `ports`, `deadline`, `pool`, `sockerr`, `unixio` | Wire formats, OS bindings and shared primitives                                    |
| `models`                                                                                                                                           | The Pydantic result models and enums                                               |
| `errors`                                                                                                                                           | The `IPScoutError` family                                                          |

[Module reference](docs/systemdesign/module_reference.md) describes each module.

## Further Documentation

- [Installation](docs/installation.md)
- [Usage](docs/usage.md)
- [Skill for coding agents](skills/python-network-probe/SKILL.md)
- [Development](docs/development.md)
- [Module Reference](docs/systemdesign/module_reference.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Our stance on AI](ai-stance.md)
- [AI transparency](ai-transparency.md)
- [License](LICENSE)
