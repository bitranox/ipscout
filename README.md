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

## Install

```bash
pip install ipscout
# or
uv pip install ipscout
```

Python 3.10 or newer. Runtime dependencies: `lib_cli_exit_tools`, `pydantic`, `rich-click`, `rtoml`.

Full instructions, including `uvx` and per-user installs, are in
[docs/installation.md](docs/installation.md).

## Quickstart, as a library

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

## Quickstart, from the shell

```bash
ipscout ping 127.0.0.1 -c 2
ipscout ping-many 127.0.0.1 ::1 -c 1
ipscout reachable example.com
ipscout traceroute 1.1.1.1 --max-hops 10
ipscout scan-ports 192.168.1.10 --ports 22,80,443,8000-8100
ipscout mac 8.8.8.8                     # the gateway's, labelled NEXT_HOP
ipscout find-ip dc:b2:2f:44:34:59 --scan
ipscout arp-scan --network 192.168.1.0/24
ipscout neighbours
ipscout gateway
ipscout subnet
ipscout mtu 8.8.8.8
ipscout wake aa:bb:cc:dd:ee:ff --broadcast 192.168.1.255
ipscout resolve localhost
ipscout reverse-dns 1.1.1.1
ipscout interfaces
ipscout capabilities
ipscout --help
```

`python -m ipscout` and `uvx ipscout` run the same entry point.

## More than ping

The same surface is available as a library, and most of it needs no elevation:

```python
import ipscout

ipscout.lookup_mac("8.8.8.8")  # the router's address, labelled NEXT_HOP
ipscout.find_ip_by_mac(mac, scan=True)  # sweep, then search the refreshed cache
ipscout.arp_scan("192.168.1.0/24")  # every hardware address on a subnet
ipscout.sweep_scope()  # what a default sweep covers, and what is too wide for it
ipscout.default_gateway()  # and query_route() for any destination
ipscout.subnet_info()  # addressing, gateway, stored DHCP facts
ipscout.scan_ports(host, "22,80,8000-8100")
ipscout.path_mtu("8.8.8.8")
ipscout.wake_on_lan(mac, broadcast="192.168.1.255")
ipscout.observe_dhcp(mac, interface="br0")  # a machine that has no address yet (needs elevation)
```

A MAC address does not survive a router hop, so `lookup_mac` puts the scope in the answer and
`get_mac_address` returns `None` for anything routed rather than passing off the gateway's as the host's. A
sweep with no network given covers the subnets this host is attached to that fit inside one sweep's
4096-address budget, and names the ones left out - a container bridge on a `/16` is skipped rather than
cancelling the sweep, and a search that matched nothing while a network went uncovered says so instead of
reporting "not found". One call is different in kind: `observe_dhcp` watches a DHCP handshake, so it is the
only way here to find a machine that is not up yet - everything else needs the target already answering. It
returns every address offered, in order, because a pool that hands out an address the guest declines offers
the working one afterwards and the last is the one that stuck. Full worked examples are in
[docs/usage.md](docs/usage.md).

## Output for machines

Every command takes a global `--json` / `-j`, which wraps the result in an envelope, or
`--json-bare`, which emits the payload at the top level for `jq`.

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
    "packets_sent": 1,
    "packets_received": 1,
    "family": "ipv4",
    "method": "icmp",
    "error": null,
    "time_avg_ms": 0.067,
    "packets_lost_percentage": 0,
    "str_result": "[127.0.0.1] pinged 1 times, min: 0.07ms, avg: 0.07ms, max: 0.07ms, 0% Packet loss"
  },
  "error": null,
  "skipped": []
}
```

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

Exit codes are independent of the output format:

| Code | Meaning                                                                   |
|------|---------------------------------------------------------------------------|
| 0    | Reached, or the command otherwise succeeded.                              |
| 1    | Not reached. Nothing answered, or a reverse lookup found no PTR record.   |
| 2    | Error. A bad name, a missing permission, a capability this host lacks, or a malformed command line. |

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

| Capability              | Linux                              | macOS                                | Windows                                |
|-------------------------|------------------------------------|--------------------------------------|----------------------------------------|
| ICMP ping, no admin     | yes, `SOCK_DGRAM`/`IPPROTO_ICMP`   | yes, `SOCK_DGRAM`/`IPPROTO_ICMP`     | yes, `iphlpapi.dll` via ctypes         |
| Traceroute              | yes, `IP_RECVERR` + `MSG_ERRQUEUE` | no, raises `IPScoutUnsupportedError` | yes, `IP_TTL_EXPIRED_TRANSIT`          |
| Async on the event loop | yes, one socket per probe          | yes, one socket per probe            | no, `IcmpSendEcho` runs in an executor |
| Interface listing       | yes, `getifaddrs`                  | yes, `getifaddrs`                    | yes, `GetAdaptersAddresses`            |
| Observing a DHCP handshake | yes, `AF_PACKET`, needs root    | no, raises `IPScoutUnsupportedError` | yes, `SIO_RCVALL`, needs Administrator |

Ask the host itself rather than guessing, with `ipscout capabilities` or `ipscout.icmp_available()`.

## Limitations worth knowing before you depend on it

**Traceroute does not work on macOS.** This was measured on a macOS runner: `MSG_ERRQUEUE` is not
defined there, and a plain receive on the ICMP socket surfaces nothing, so an unprivileged process
never sees ICMP Time Exceeded. `traceroute` raises `IPScoutUnsupportedError` rather than returning a
column of silent hops that would look like a broken network instead of a missing feature. Running as
root does not fix it, which is why it is a separate exception type from the permission one.

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
`method` field and you have to opt in. `is_reachable` is the single deliberate exception: it never
raises and always tries TCP, because that is the entire point of a yes-or-no shortcut.

**It is not zero-dependency.** Four runtime dependencies, listed above.

## Documentation

- [Installation](docs/installation.md)
- [Skill for coding agents](skills/python-network-probe/SKILL.md)
- [Usage](docs/usage.md)
- [Development](docs/development.md)
- [Module Reference](docs/systemdesign/module_reference.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Our stance on AI](ai-stance.md)
- [AI transparency](ai-transparency.md)
- [License](LICENSE)
