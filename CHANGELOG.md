# Changelog

All notable changes to this project will be documented in this file following
the [Keep a Changelog](https://keepachangelog.com/) format.

## [Unreleased]

## [1.0.0] - 2026-07-29

Initial release. `ipscout` probes hosts and inspects the local network entirely in-process: no
subprocess is spawned, and no administrator or root rights are needed on the default paths.

### Added

- **In-process ICMP, unprivileged.** Echo goes over `SOCK_DGRAM`/`IPPROTO_ICMP` (the kernel ping
  socket) on Linux and macOS, and through `IcmpSendEcho` in `iphlpapi.dll` via ctypes on Windows.
  Neither needs elevation; raw sockets, which do, are only a fallback for a host where ping sockets
  are disabled. Nothing shells out, so there is no per-probe process and no locale-dependent output
  to parse.
- **Errors and network conditions are separate channels.** Setup problems raise a typed exception
  whose message names the fix; network conditions come back as data, so a down host, a timeout and
  100% loss all return `reached=False`. Collapsing both into one flag would make a missing ICMP
  permission indistinguishable from a dead host. Pass `raise_on_error=False` to report failures on
  `.error` instead. `ping_many` and `aping_many` default to `raise_on_error=False`, because one bad
  name in a sweep of two hundred should not destroy the other 199 results.
- **Async API.** `aping`, `aping_many`, `ais_reachable`, `atraceroute` and `atrace_path`. Genuinely
  asynchronous on Linux and macOS, where the ICMP socket is registered with the event loop, so a
  sweep of thousands runs on one thread. On Windows `IcmpSendEcho` is a blocking C call with no
  asyncio integration, so the async path is executor-backed: identical behaviour, different scaling.
- **Concurrent sweeps.** `ping_many` and `aping_many`, with bounded concurrency (default 64).
- **Traceroute.** `traceroute`, `atraceroute`, `trace_path` and `atrace_path`. Supported on Linux
  (`IP_RECVERR` plus `MSG_ERRQUEUE`) and Windows (`IP_TTL_EXPIRED_TRANSIT`). Not supported on macOS:
  measured on a macOS runner, neither `MSG_ERRQUEUE` nor a plain receive surfaces ICMP Time Exceeded
  to an unprivileged process, so it raises `IPScoutUnsupportedError` rather than returning a column
  of silent hops that would read as a broken network.
- **Local network inspection.** `local_interfaces` via `getifaddrs` on POSIX and
  `GetAdaptersAddresses` on Windows.
- **Name resolution helpers.** `resolve` and `reverse_dns`, with the address family decided once and
  carried explicitly on the result instead of being guessed per call.
- **Capability reporting.** `icmp_available(family)` and the `capabilities` CLI command, so a caller
  can find out what this host can do without provoking an error first.
- **A TCP fallback that is never silent.** `allow_tcp_fallback=True` probes over a full TCP connect
  when ICMP is unavailable, and every result carries a `method` field, so a TCP answer can never be
  mistaken for an ICMP round trip. `is_reachable` is the deliberate exception to the error contract:
  it never raises and always tries TCP.
- **Hardware addresses, answered with their scope.** `lookup_mac`, `get_mac_address`,
  `neighbours`, `normalise_mac`. A MAC does not survive a router hop, so a routed address can only
  ever yield the next-hop router's, and `lookup_mac` says so through `MacScope.NEXT_HOP` and
  `via_ip` rather than passing it off as the host's. `get_mac_address` stays strict and answers
  `None` for anything routed. Backed by netlink `RTM_GETNEIGH` on Linux, a `NET_RT_FLAGS` sysctl
  dump on macOS and `GetIpNetTable2` on Windows, all passive and unprivileged.
- **Active address resolution.** `resolve_active`, and `active=True` on the two lookups. Sends a
  real ARP request or ICMPv6 neighbour solicitation instead of reading the cache: `AF_PACKET` on
  Linux, BPF on macOS, `SendARP` and `ResolveIpNetEntry2` on Windows. Needs root or `CAP_NET_RAW`
  everywhere except Windows IPv4, and raises `IPScoutPermissionError` naming the remedy rather
  than falling back to a stale cache entry.
- **Reverse search by hardware address.** `find_ip_by_mac` and `arp_scan`. No protocol asks "who
  has this MAC" - RARP is dead - so these sweep and then read what the kernel learned. The search
  returns a list because one address legitimately holds several, commonly an IPv4 and an IPv6
  link-local on one NIC. A sweep wider than 4096 addresses is refused, naming the network at fault.
- **Routes.** `query_route` and `default_gateway`, via netlink `RTM_GETROUTE`, a BSD routing-socket
  `RTM_GET`, and `GetBestRoute2`. Each asks the kernel what route it would actually use rather than
  re-implementing longest-prefix matching. `default_gateway` selects the zero-length destination
  prefix from the table: asking for the route to `0.0.0.0` looks equivalent and is not, because the
  unspecified address matches the local table first and answers with loopback.
- **Subnets, without sending DHCP traffic.** `subnet_info`, `local_networks`. Addressing comes from
  the calls the interface listing already makes, the gateway from the route lookup, and the DHCP
  fields from the lease store the OS's own client wrote. Those fields may be unset off Linux; the
  addressing fields work everywhere. `Interface.mtu` is now populated on POSIX too.
- **Port scanning, in three states.** `scan_ports`, `ascan_ports`, `parse_ports`. `CLOSED` means
  something refused, which proves a host is there; `FILTERED` means nothing answered. A half-open
  SYN scan (`ScanMethod.SYN`) distinguishes them without completing a handshake, and needs a raw
  socket; Windows has blocked raw TCP sends since XP SP2, so it is unavailable there at any
  privilege level. Both methods hold only `concurrency` probes alive at a time, so a full-range
  scan is bounded in memory rather than allocating a task per port.
- **Wake-on-LAN.** `wake_on_lan`. Returns nothing, because nothing acknowledges a magic packet: a
  successful send means only that it left this host.
- **Path MTU.** `path_mtu`. Queries the kernel on Linux, and bisects with the don't-fragment flag
  on Windows and the BSDs. Returns `None` where a platform cannot say, which is an answer rather
  than a failure - an MTU sizes packets, so a guessed one is a silent black hole.
- **A CLI with seventeen commands.** `ping`, `ping-many`, `reachable`, `traceroute`, `resolve`,
  `reverse-dns`, `interfaces`, `gateway`, `neighbours`, `mac`, `find-ip`, `arp-scan`, `subnet`,
  `scan-ports`, `mtu`, `wake`, `info`. Global `--json`/`-j` emits an envelope
  (`ok`, `command`, `data` or `error`); `--json-bare` emits the payload at top level for `jq`. Exit
  codes: 0 reached, 1 not reached, 2 error.
- **Typed errors.** `IPScoutError` plus `IPScoutPermissionError`, `IPScoutResolutionError` and
  `IPScoutUnsupportedError`. The permission and unsupported cases are separate types because running
  as root fixes one and does not fix the other.
- **Frozen Pydantic result models.** `ResponseObject`, `TraceHop`, `Interface`, `InterfaceAddress`,
  `MacLookup`, `SubnetInfo`, `CapabilityReport`, plus the CLI report types. Derived statistics are
  computed fields, so a model dump carries them rather than silently dropping them.
- **A Claude Code skill, shipped with the package.** The repo is a single-plugin marketplace
  (`.claude-plugin/`) carrying `skills/python-network-probe/`, so an LLM agent can install it
  from any project and get the no-admin story, the error contract, the JSON output and the
  measured platform limits rather than guessing at an API. Mirrored in the bitranox marketplace
  as `coding-python-network-probe`.
- **Enums for the fixed value sets.** `AddressFamily`, `ProbeMethod`, `MacScope`, `CommandName`.
- **Token-based reply matching.** An unprivileged datagram ICMP socket does not let the process
  choose its ICMP identifier; the kernel rewrites it. Measured on Linux, an echo sent with identifier
  `0xBEEF` came back carrying `0x4C36`. Replies are therefore matched on the sequence number plus a
  random token embedded in the payload, which is correct on datagram sockets, raw sockets and the
  Windows backend alike, and which discards another process's replies rather than counting them.
- **Kernel ABI fallback for `IP_RECVERR` / `IPV6_RECVERR`.** CPython only exposed these constants
  from 3.14. Without the fallback to the kernel values (11 and 25), traceroute would report itself
  unsupported on Linux for every Python from 3.10 to 3.13.

### Requirements

Python 3.10 or newer. Runtime dependencies: `lib_cli_exit_tools>=2.3.4` (earlier releases discarded
Click's return value, which collapsed the not-reached exit code of 1 into 0), `pydantic`,
`rich-click`, `rtoml`.
