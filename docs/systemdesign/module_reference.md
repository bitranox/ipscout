# Module reference: ipscout

## Links and references

**Repository:** https://github.com/bitranox/ipscout
**PyPI:** https://pypi.org/project/ipscout/
**Documentation:** [README.md](../../README.md), [installation](../installation.md),
[usage](../usage.md), [development](../development.md), [CHANGELOG](../../CHANGELOG.md)

---

## Problem statement

Probing whether a host answers is the sort of thing that looks solved until you look at how it is
usually done. The common approach spawns the system `ping` binary and scrapes its output with
regular expressions. That has four consequences worth naming:

1. The output of `ping` is a message written for a human, so it changes with locale, distribution
   and version. A parser built on it fails silently on a machine configured differently.
2. One process per probe. A sweep of a thousand hosts is a thousand `fork`/`exec` pairs.
3. Raw sockets are the usual alternative, and they need root or `CAP_NET_RAW`.
4. Errors and network conditions collapse into one answer. A permission problem and a dead host
   read identically.

ipscout answers all four in-process. ICMP goes over an unprivileged socket on Linux and macOS and
through the IP Helper API on Windows, no subprocess is ever spawned, and the error contract keeps
setup problems separate from network conditions.

---

## Solution overview

1. **Unprivileged ICMP everywhere.** `SOCK_DGRAM`/`IPPROTO_ICMP` on Linux and macOS,
   `IcmpSendEcho` via `iphlpapi.dll` on Windows. A raw socket is tried only as a fallback, so
   running as root keeps working on a host where ping sockets are disabled.
2. **Transports behind a protocol.** The probing policy depends on the protocols in `ports.py` and
   never on a concrete backend.
3. **A strict error contract.** Setup problems raise a typed exception whose message names the fix.
   Network conditions come back as data.
4. **Frozen Pydantic results.** Every public callable returns a validated model, never a dict, and
   derived statistics are computed fields so a dump cannot drop them.
5. **One JSON boundary.** All CLI commands render through a single helper, so no command can
   support JSON on its success path and forget it elsewhere.

---

## Architecture

### Layer structure

The import-linter contract `Layered dependencies point one way only` is enforced in CI. Layers are
listed highest first; each may import only from those below it.

```
api          ping / aping / ping_many / aping_many / is_reachable / ais_reachable
traceroute   traceroute / atraceroute / trace_path / atrace_path
interfaces   local_interfaces
service      probe sequencing and aggregation
factory      picks the backend for this platform, family and options
transport_posix : transport_windows : transport_tcp : interfaces_posix : interfaces_windows
packet : resolve : ports : winapi
models
errors
```

`cli.py`, `serialize.py`, `typed_click.py` and `__main__.py` sit outside the contract as the CLI
adapter.

### Why the layers are split this way

**Transports sit behind a protocol, not behind a base class.** `ports.py` declares `EchoTransport`
and `AsyncEchoTransport` as `Protocol`s. `service.py` and `traceroute.py` are written against those
protocols and import no concrete backend, which is why their tests hand them a real in-process fake
rather than monkeypatching a module attribute. The substitution point is a constructor argument.
There is no `mock.patch` of this package's own internals anywhere in the suite.

**Only the factory knows the platform.** `factory.py` is the one module that branches on
`sys.platform`. Everything above it is platform-free and therefore runnable on any machine under
test. Everything below it is a single platform's implementation detail.

**The service owns policy, the transport owns transit.** How many echoes, how far apart, what counts
as reached is `service.py`. How one echo travels is a transport. Splitting them is what lets a probe
be paced identically across ICMP, TCP, POSIX and Windows.

**The API layer owns the error contract**, because it is the only layer that knows both what the
caller asked for and what the machine could do. A transport reports what happened, including
"nothing came back", and raises only when it cannot probe at all.

### Data flow, one ping

1. `api.ping` resolves the target once through `resolve.resolve_one`, which fixes the address
   family up front rather than guessing it later.
2. `api._prepare` builds a `service.PingRequest`. Pydantic field bounds reject a bad `times`,
   `timeout` or `interval` here, before any packet moves, identically for every caller path.
3. `factory.make_transport` picks the backend.
4. `service.run_ping` sends the echoes, paced against the run's start so a slow reply does not push
   every later echo later, and folds the outcomes into a `ResponseObject`.
5. On the CLI path, `cli._emit` renders it as text or as JSON through `serialize.dumps`.

---

## Token matching, and why the identifier is useless

An unprivileged datagram ICMP socket does not let the process choose its ICMP identifier. The kernel
overwrites that field with a value of its own derived from the socket, so the identifier that comes
back is not the one that was sent. Measured on Linux: an echo sent with identifier `0xBEEF` produced
a reply carrying `0x4C36`.

Matching replies on the identifier, which is what a textbook implementation does, would therefore
never match, and every healthy host would read as 100% loss. So every request embeds a random token
in its payload, behind an `IPSCOUT1` magic prefix, and a reply counts as ours only if the sequence
number and the payload token both come back intact.

That rule is independent of the kernel's rewriting, so the same matching logic is correct on
datagram sockets, on raw sockets, and on the Windows API backend. It also solves a second problem:
several processes on one host can hold ICMP sockets at once and may be handed copies of each other's
replies. A foreign reply fails the token check and is discarded rather than counted as an answer to
a probe nobody sent.

Two other wire-level facts are handled in `packet.py`:

- **A leading IP header may or may not be present.** Linux ping sockets deliver the ICMP message
  alone; macOS prepends the full IPv4 header, as BSD raw sockets do. Parsing the IP header as an
  ICMP header yields a type byte of `0x45`, which matches no ICMP type, so every reply would be
  discarded. The prefix is detected from the data, not from `sys.platform`: ICMPv4 type numbers are
  all below 16, so a first byte whose high nibble is 4 can only be an IPv4 version field.
- **IPv6 checksums are the kernel's job.** The ICMPv6 checksum covers a pseudo-header containing the
  source address, which user space does not reliably know, so the field is sent as zero.

---

## Measured platform matrix

Established by running the suite on real CI runners, not by reading documentation.

| Capability              | Linux                              | macOS                                | Windows                           |
|-------------------------|------------------------------------|--------------------------------------|-----------------------------------|
| ICMP echo, no elevation | `SOCK_DGRAM`/`IPPROTO_ICMP`        | `SOCK_DGRAM`/`IPPROTO_ICMP`          | `IcmpSendEcho` via `iphlpapi.dll` |
| Traceroute              | yes, `IP_RECVERR` + `MSG_ERRQUEUE` | no, raises `IPScoutUnsupportedError` | yes, `IP_TTL_EXPIRED_TRANSIT`     |
| Async model             | one socket on the event loop       | one socket on the event loop         | blocking C call in a thread pool  |
| Interface enumeration   | `getifaddrs`                       | `getifaddrs`                         | `GetAdaptersAddresses`            |
| Route lookup            | netlink `RTM_GETROUTE`             | not implemented                      | not implemented                   |

### Traceroute on macOS

Measured on a macOS runner: `MSG_ERRQUEUE` is not defined there, and a plain receive on the ICMP
socket returns nothing at all, so an unprivileged process never observes ICMP Time Exceeded.
`traceroute` raises `IPScoutUnsupportedError` rather than returning a column of silent hops, which
would look like a broken network instead of a missing capability. The exception type is distinct
from `IPScoutPermissionError` for a concrete reason: running as root fixes a permission problem and
does not fix this.

The refusal is taken from the transport's own `supports_ttl_discovery` rather than from
`sys.platform`, so the TCP transport is refused through the same code path for the same reason.

### The Linux socket-option fallback

CPython only began exposing `IP_RECVERR` and `IPV6_RECVERR` in 3.14. On 3.10 through 3.13 the
lookup came back empty and the capability check honestly answered "traceroute unsupported" on Linux.
`transport_posix.py` therefore falls back to the kernel ABI values (`IP_RECVERR` 11 from
`linux/in.h`, `IPV6_RECVERR` 25 from `linux/in6.h`). Those are fixed forever, since changing one
would break every compiled binary on the platform.

The failure was invisible twice over: absent on a 3.14 development machine, and absent in CI, whose
Linux runners refuse ICMP outright and skip those tests.

### Windows timing resolution

`IcmpSendEcho` reports round-trip time in whole milliseconds, so anything faster than 1 ms reads as
zero. `transport_windows.py` measures with `time.perf_counter` around the call and uses the API's
own value only as a fallback, which keeps loopback and LAN timings meaningful.

---

## Modules

### Public surface

| Module          | Role                                                                                                            |
|-----------------|-----------------------------------------------------------------------------------------------------------------|
| `__init__.py`   | Re-exports the public API so importers depend on the package, not its layout.                                   |
| `api.py`        | `ping`, `aping`, `ping_many`, `aping_many`, `is_reachable`, `ais_reachable`. Owns the error contract.           |
| `traceroute.py` | `traceroute`, `atraceroute`, `trace_path`, `atrace_path`, and the capability refusal.                           |
| `interfaces.py` | `local_interfaces`, dispatching to the per-OS backend.                                                          |
| `resolve.py`    | `resolve`, `resolve_one`, `reverse_dns`, `family_of`.                                                           |
| `factory.py`    | `make_transport`, `make_async_transport`, `icmp_available`. The only `sys.platform` branch in the probing path. |

### Core

| Module       | Role                                                                              |
|--------------|-----------------------------------------------------------------------------------|
| `errors.py`  | `IPScoutError` and its three subclasses. No dependencies.                         |
| `models.py`  | Frozen result models and the `str`-subclass enums.                                |
| `ports.py`   | `EchoResult`, `EchoTransport`, `AsyncEchoTransport`. The seams.                   |
| `packet.py`  | ICMP encode and decode. Total functions over bytes: no sockets, no clock, no I/O. |
| `service.py` | `PingRequest`, `run_ping`, `arun_ping`. Probe sequencing and aggregation.         |

### Platform backends

| Module                  | Role                                                                                                                     |
|-------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `transport_posix.py`    | ICMP over the unprivileged datagram socket, sync and asyncio, plus the raw-socket fallback and the permission diagnosis. |
| `transport_windows.py`  | ICMP through `IcmpSendEcho` / `Icmp6SendEcho2`, plus the executor-backed async variant.                                  |
| `transport_tcp.py`      | Reachability by full TCP connect. Never selected automatically.                                                          |
| `interfaces_posix.py`   | `getifaddrs`, handling the Linux/BSD `sockaddr` disagreement.                                                            |
| `interfaces_windows.py` | `GetAdaptersAddresses`.                                                                                                  |
| `winapi.py`             | ctypes bindings for `iphlpapi.dll`. Imports safely on every platform.                                                    |
| `routes_linux.py`       | Netlink `RTM_GETROUTE`, asking the kernel which route it would actually use.                                             |

### CLI adapter

| Module              | Role                                                                       |
|---------------------|----------------------------------------------------------------------------|
| `cli.py`            | The rich-click group, nine subcommands, `_emit` and `_fail`, and `main`.   |
| `serialize.py`      | `to_jsonable` and `dumps` at the output boundary.                          |
| `typed_click.py`    | Typed facade over rich-click's partially-typed decorators.                 |
| `__main__.py`       | `python -m ipscout`.                                                       |
| `__init__conf__.py` | Static package metadata, kept in sync with `pyproject.toml` by automation. |

---

## Result models

Every model is frozen with `extra="forbid"`. A probe result records something that already happened,
and mutating it can only make it disagree with reality.

| Model                | Fields                                                                                                                                                                                                                                                          |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ResponseObject`     | `target`, `reached`, `ip`, `number_of_pings`, `rtts_ms`, `packets_sent`, `packets_received`, `family`, `method`, `error`, plus the computed `time_min_ms`, `time_avg_ms`, `time_max_ms`, `jitter_ms`, `n_packets_lost`, `packets_lost_percentage`, `str_result` |
| `TraceHop`           | `ttl`, `address`, `rtt_ms`, `reached`, `hostname`                                                                                                                                                                                                               |
| `Interface`          | `name`, `ipv4`, `ipv6`, `mac`, `is_up`, `is_loopback`, `mtu`                                                                                                                                                                                                    |
| `InterfaceAddress`   | `address`, `prefix_len`                                                                                                                                                                                                                                         |
| `MacLookup`          | `ip`, `mac`, `scope`, `via_ip`, `interface`                                                                                                                                                                                                                     |
| `SubnetInfo`         | `interface`, `address`, `prefix_len`, `network`, `family`, `broadcast`, `gateway`, `dns_servers`, `domain`, `dhcp_server`, `lease_obtained`, `lease_expires`, `mtu`                                                                                             |
| `CapabilityReport`   | `icmp_ipv4`, `icmp_ipv6`, `traceroute`                                                                                                                                                                                                                          |
| `ReachabilityReport` | `target`, `reachable`                                                                                                                                                                                                                                           |
| `ResolveReport`      | `target`, `addresses`                                                                                                                                                                                                                                           |
| `ReverseDnsReport`   | `ip`, `hostname`                                                                                                                                                                                                                                                |
| `PackageInfo`        | `name`, `version`, `title`, `homepage`, `author`, `shell_command`                                                                                                                                                                                               |
| `JsonEnvelope`       | `ok`, `command`, `data`, `error`                                                                                                                                                                                                                                |
| `JsonError`          | `type`, `message`                                                                                                                                                                                                                                               |

`MacLookup` and `SubnetInfo` are exported result types for the local-network inspection layer. No
public callable returns one in this release.

Two model decisions worth knowing:

**Derived values are `@computed_field`, not plain properties.** The average round trip, the loss
percentage and the summary line are computed. A plain `@property` is invisible to serialisation, so
`model_dump()` would silently drop exactly the numbers a caller wants while producing a payload that
looks complete. Declaring them as computed fields puts them in the dump by construction.

**The enums subclass `str`.** Their members are strings, so the wire bytes are unchanged and no
conversion happens at the boundary. `StrEnum` is the modern spelling but arrived in 3.11, and this
package supports 3.10.

---

## The error contract

| Exception                 | Meaning                                            | Would root help |
|---------------------------|----------------------------------------------------|-----------------|
| `IPScoutError`            | Base class. Catch this for the whole family.       | n/a             |
| `IPScoutPermissionError`  | The process lacks a privilege the operation needs. | yes             |
| `IPScoutResolutionError`  | The target could not be turned into an address.    | no              |
| `IPScoutUnsupportedError` | No backend implements this here.                   | no              |

Keeping these apart is the point of `errors.py`: a missing ICMP permission and an unreachable
host call for different responses from the caller, so collapsing both into `reached=False` would
throw away the distinction that matters.

Permission messages name the concrete remediation rather than reporting refusal, because the fix
differs per platform and per operation. `is_reachable` and `ais_reachable` are the deliberate
exceptions to the whole contract: they never raise and always fall back to TCP, documented on their
own docstrings so nobody mistakes them for `ping(...).reached`.

---

## Testing approach

Tests drive the real modules through their real seams. A transport is injected as a constructor
argument, so the probing logic is exercised with an in-process fake rather than with a patched
module attribute. Nothing inside this package is monkeypatched anywhere in the suite; the single
`monkeypatch` call sets `sys.argv` for the `python -m` entry-point test, which is a genuine
external edge.

`packet.py` is a set of total functions over bytes, so the protocol layer is fully testable without
a network, without privileges and without a particular operating system. `winapi.py` structure
layouts are pinned by `tests/test_winapi_layout.py`, which runs on any platform because fixed-width
integer types make the layouts identical everywhere.

Doctests run under `--doctest-modules`, so the examples in the source are tests.

**Coverage gate:** `fail_under = 85` over `src/ipscout`. The four platform backends
(`transport_posix.py`, `transport_windows.py`, `interfaces_posix.py`, `interfaces_windows.py`) are
omitted from the percentage, not from testing. Each is exercised by per-OS marked suites in the CI
matrix, but each can only execute on one platform, so leaving them in makes every backend report as
dead weight on the two platforms that cannot run it and sinks the gate on every OS at once.

**Markers:** `os_agnostic`, `os_windows`, `os_macos`, `os_posix`, `os_linux`, `local_only`.

---

## Security considerations

- **No subprocess, ever.** Nothing is spawned, so there is no shell quoting, no `PATH` lookup and no
  locale-dependent output parsing anywhere in the package.
- **No elevation on the default paths.** The raw-socket fallback exists so a root process keeps
  working, never as the first choice.
- **Foreign replies are discarded.** The payload token stops another process's ICMP reply being
  counted as an answer to a probe this one never sent.
- **Bounds-checked structure walking.** `interfaces_posix.py` validates every field before reading
  it, because it walks memory handed over by libc; a malformed entry is skipped rather than trusted.
- **Fixed-width ctypes.** `c_ulong` is 4 bytes on Windows and 8 on 64-bit Linux, so every Windows
  structure field is declared with an explicit width. That keeps layouts identical everywhere and
  lets tests assert the sizes from Linux.
- **Dependency hygiene.** `pip-audit` and `bandit` run in CI; `codecov-cli` is commented out rather
  than deleted, because its `click<8.3.0` pin would drag click below the CVE-2026-7246 fix.

---

## Quick reference

```python
import ipscout

ipscout.ping("127.0.0.1", 2, interval=0)  # -> ResponseObject
ipscout.ping_many(["127.0.0.1", "::1"], times=1)  # -> dict[str, ResponseObject]
ipscout.is_reachable("127.0.0.1")  # -> bool, never raises
ipscout.traceroute("1.1.1.1", max_hops=10)  # -> list[TraceHop]
ipscout.resolve("localhost")  # -> list[str]
ipscout.reverse_dns("127.0.0.1")  # -> str | None
ipscout.local_interfaces()  # -> list[Interface]
ipscout.icmp_available()  # -> bool
```

```bash
ipscout ping 127.0.0.1 -c 2
ipscout --json ping 127.0.0.1 -c 1
ipscout --json-bare capabilities
python -m ipscout --help
```
