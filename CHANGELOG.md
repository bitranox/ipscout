# Changelog

All notable changes to this project will be documented in this file following
the [Keep a Changelog](https://keepachangelog.com/) format.

## [Unreleased]

### Fixed

- **One hardware address on two interfaces no longer lists its address twice.** A single MAC can
  legitimately sit on several interfaces - a synthetic NIC and its VF present the same one - so the
  neighbour cache holds an entry per interface and `find_ip_by_mac` returned the address once per
  entry. The length of that list read as a count of addresses while being a count of interfaces.
  Each address is now listed once, in the order first seen; the distinct addresses one MAC holds
  are all still returned, which is the case the function exists for.
- **`lookup_mac` reads the entry learned on the interface that carries the frame.** It picked the
  first cache entry matching the address and ignored the interface, though it had already resolved
  the route that names one. An address is only unique per interface: a link-local address names a
  different machine on each link, and a multi-homed host can hold the same address on two of them,
  so the first entry could report an unrelated machine's hardware address with nothing marking it
  as wrong. With no interface known, or no entry on it, the previous behaviour stands.

- **An IPv6 link-local address can be reached at all.** Every probe to one reported the target as
  unreachable, whatever the host: the zone that says which link an address belongs to was dropped
  during resolution (`getaddrinfo` moves it into the sockaddr's scope id, and only the address was
  kept), and the transports then sent to a 2-tuple, which is scope id zero, meaning no link. So a
  reachable host read as down - the one thing the error contract exists to prevent. Measured
  against a real neighbour: the system ping answered in 1.01 ms while `ping()` returned
  `reached=False`. The zone now survives resolution and travels in the sockaddr, verified on Linux
  and on real Windows, where the reply came back in 0.8 ms through `Icmp6SendEcho2`.
- **A link-local address written without a zone is refused by name.** It cannot be sent anywhere,
  so it is a question that cannot be asked rather than a host that is down, and the message says
  how to write it.
- **Every way of writing a zone wrongly now says which way.** Four distinct mistakes - a zone on an
  IPv4 address, a trailing `%` naming no interface, two zones on one address, and a zone holding
  characters an address cannot carry - all arrived as `resolver returned an unparseable address`,
  which reports what the resolver did rather than what the caller got wrong, or as a bare
  `cannot resolve`, which reads as a name that does not exist. Each is now refused at the boundary
  with its own message. The two-zone case is the one to expect: appending an interface to an
  answer that already carries one is the natural reflex, and every address this library hands back
  now carries one. The generic message survives only as a backstop, and says it is one; the
  comment claiming the case could not happen is gone, since it was what let four real inputs share
  one useless message.
- **A zoned address no longer defeats the passive lookups.** `lookup_mac` compared the scoped text
  against a cache that holds bare addresses and so reported a known neighbour as unknown, and
  `query_route` fed it to `inet_pton`, whose refusal was caught and returned as "no route". Both
  now take the zone off first, and `lookup_mac` uses it as the interface to answer from - which is
  what a caller is saying by writing it.

- **What a search returns is what a probe accepts.** `find_ip_by_mac` handed back a bare
  link-local address, which every probe then refused, while the interface it needed sat in the very
  cache entry the answer came from: the library returned something its own calls reject, having
  discarded the missing piece on the way out. Link-local results now carry the interface they were
  learned on, so they can be passed straight back in. Every other address is byte-identical to
  before, since a zone is meaningless for them.

### Added

- **`Neighbour.scoped`, the entry's address in the form a probe accepts.** The joined RFC 4007
  form for a link-local entry, and plainly the address for every other, so a caller never rebuilds
  it - or gets the IPv4 case, where a zone is meaningless, wrong. A computed field, so it is in
  `model_dump()` rather than being dropped from a payload that looks complete.
- **`Interface.index`, the interface index the kernel knows.** It is the only spelling of an
  interface usable as a zone on every platform: Windows reports a friendly `name` here
  (`Ethernet 4`) that neither `getaddrinfo` nor `if_nametoindex` recognises, both of which speak a
  different namespace (`ethernet_32775`) - measured on a real Windows host, where an interface name
  as a zone fails resolution outright.

### Changed

- **The skill states that both directions of the MAC-to-interface mapping are many-to-one.** A new
  section in `python-network-probe`: one hardware address can sit on several interfaces, so
  `local_interfaces()` is keyed by name and each record carries its own `mac` rather than a
  MAC-to-one-interface map; and one address can name several machines, so `lookup_mac` answers from
  the interface the frame would leave by and reports which one that was. Mirrored into
  `bitranox-skills`.

## [1.4.0] 2026-07-31 16:30:04


### Added

- **A macOS capture backend, through `/dev/bpf`.** `observe_dhcp` now works on all three
  platforms. macOS has no `AF_PACKET`; it has the BSD packet filter, the same facility `tcpdump`
  uses and one this package already opens to resolve neighbours actively. The plumbing moved into
  a shared `bpf` module rather than being copied, for the reason `unixio` already records: the
  first copy was written into the macOS neighbour backend and the next caller re-derived it. This
  was that next caller.

  Two things the BSD filter needs that the Linux one does not. A read returns SEVERAL frames at
  once, packed with per-record headers and 4-byte alignment, so the surplus is held and handed out
  on later calls - dropping it would lose exactly the reply being waited for, since a DHCP exchange
  arrives in a burst. And a device reports its framing through `BIOCGDLT`: loopback uses `DLT_NULL`,
  which prefixes a protocol family rather than an Ethernet header, so a non-Ethernet link type is
  refused by name instead of quietly decoding the wrong bytes.

### Changed

- **The macOS device path ships untested on real hardware, and says so in the module, the skill and
  the docs.** No CI runner may open a BPF device - measured, `/dev/bpf0` is refused with EACCES on
  every macos-latest lane - and it was written without a Mac to hand. What IS proven is everything
  that does not need the device: the ioctl encoding is pinned against the values in `<net/bpf.h>`,
  including that `BIOCPROMISC` is an `_IO` request carrying no argument, and the record splitting is
  pinned against hand-built buffers. Linux remains the backend to trust; it is exercised as root on
  a developer box and against a real bridge.
- **The `fcntl` typed facade accepts a request with no argument.** Its Protocol declared the ioctl
  argument as required, which a BSD `_IO` request does not take. Widened to match what the module
  really accepts, rather than suppressing the type error at the one call site that needed it.
## [1.3.0] 2026-07-31 14:42:32

### Added

- **`observe_dhcp()`, `observe_dhcp_session()` and `observe_dhcp_first_reachable()`: find a machine
  that does not have an address yet.** Every other way this package finds a host needs it already up
  and answering - a neighbour entry only exists after real traffic, a sweep needs the host to answer
  ARP, and a lease describes this host rather than one handed to somebody else. A machine that has
  just been started has none of those and asks for an address about a second later, so watching that
  exchange is the only way to catch it. The session form is the important one: it opens the capture
  on entry, so the machine can be started inside the block and a missing privilege surfaces before
  anything is started rather than as an empty list two minutes later.
- **Every offer is returned, in the order seen, not just the first.** A pool that hands out an
  address the guest declines after duplicate-address detection offers a working one seconds later,
  and both land in the same exchange. Returning the first is how a perfectly reachable machine gets
  reported as never having booted. What that costs is that the answer is a list to check rather than
  an address to use, and that the one which stuck is usually last, not first;
  `observe_dhcp_first_reachable()` walks it and returns as soon as a candidate answers.
- **`result()` waits for the exchange to go quiet, not for the whole window.** It answers once
  `settle` seconds pass with no new address, each new one restarting that clock, bounded by
  `timeout`. Nothing appearing at all costs the full window, because only the whole window can
  establish absence. The cost is a second time knob and a floor of `settle` seconds on every call:
  iterate `session.offers()` when that is too slow, rather than shortening `timeout`, which cuts off
  the second offer and re-creates the problem above.
- **A machine that never appears returns `[]`; a capture that could not run raises.** The same split
  `IPScoutSweepIncompleteError` already draws, for the same reason: "did not appear" and "could not
  look" are different facts and a caller has to be able to tell them apart.
- **`dhcp_capture_available()`, and `dhcp_capture` on `capabilities`.** Ask before provoking an
  error, as `icmp_available()` already allows.

### Changed

- **This is the first capability that needs elevation on the platform it works on, and the first
  that reads traffic addressed to other hosts.** Linux uses `AF_PACKET` and needs root or
  `CAP_NET_RAW`; Windows uses `SIO_RCVALL` on a raw socket and needs Administrator but no driver.
  macOS raises `IPScoutUnsupportedError`: the mechanism exists there, but no CI runner is
  privileged enough to test it, so shipping it would mean shipping code nobody has run. Unlike
  every other privileged operation here there is no unprivileged route to the same answer - the
  error message says that rather than implying one exists.
- **What the two backends promise is not the same, and the docs say so rather than letting the
  shared name imply otherwise.** Linux binds to the interface named, so a bridge shows the frames
  it forwards to its guests - the case this was built for. Windows sees what reaches this host's
  own interface, which on a Hyper-V virtual switch excludes other guests unless the port mirrors.
  On Windows `interface=` also accepts an IPv4 address, because `SIO_RCVALL` binds to an address
  rather than to a device. It also
  puts the interface into promiscuous mode, which is not decorative: on a bridge a reply is
  forwarded to the guest's own port, and a Linux client does not set the broadcast flag that would
  make it visible otherwise, so without it the capture sees only address-less requests and reports a
  healthy machine as absent. The join is reference-counted by the kernel and released with the
  socket, so a crash cannot leave the interface promiscuous.
- **The CLI gained `observe-dhcp`**, and the command tables in `docs/usage.md` and
  `module_reference.md` are correct again - they claimed nine and seventeen commands while there
  were eighteen.
- **The package summary is qualified rather than absolute.** It read "no subprocess, no admin
  rights"; it now reads "no subprocess, and no admin rights on the default paths". The no-subprocess
  half is unchanged and absolute. The privilege half never was: a SYN scan, an active MAC lookup and
  traceroute on macOS have always needed elevation, and `observe_dhcp` is the first capability with
  no unprivileged route to the same answer at all, so an unqualified claim had become the kind of
  headline a reader would have to discover was wrong.

## [1.2.1] - 2026-07-30

### Changed

- **Version line raised past the shipped skill's.** The Claude Code plugin in
  `.claude-plugin/plugin.json` was at 1.2.0 while the package was at 1.1.0, because the skill
  ships more often than the package it documents. bmk now slaves the plugin version to the
  package version, and that sync must never move an install backward, so the package version
  is raised past it once here. No functional change.

## [1.1.0] - 2026-07-30

### Changed

- **A default sweep no longer fails over one oversized subnet.** `arp_scan()` and
  `find_ip_by_mac(..., scan=True)` with no network given now sweep every subnet this host is
  attached to that fit inside one sweep's budget of 4096 addresses - counted across all of them
  together, spent in the order the host reports them - and report the ones left out instead of
  refusing the whole call. A container bridge on a `/16` is present on a large share of Linux dev
  and CI hosts, so the documented default path failed on first use for a reason unrelated to the
  caller's target. Naming a network explicitly still raises when it is too wide: that is a request,
  not a default. What the change costs is stated rather than hidden - see the new errors below.
- **Naming ground to sweep without asking for a sweep is refused.**
  `find_ip_by_mac(mac, network=...)` and the new `scope=` form used to ignore that argument unless
  `scan=True` was also given, answering from the cache while the caller believed the named network
  had been covered. Both now raise `ValueError`. Nothing conflicted and nothing was printed, which
  is what made the no-op invisible.
- **`local_networks()` reports the subnets a sweep covers.** Loopback was already left out; a `/31`
  and a `/32` now are too, since they hold this host plus at most one point-to-point peer and a
  sweep of them cannot find anybody new. `subnet_info()` still reports those addresses, and naming
  such a network explicitly still sweeps it.

### Added

- **`sweep_scope()` and `SweepScope`.** Ask what a sweep would cover before running it: which
  networks it probes, which it leaves out, the address budget that decided the split, and whether
  coverage is complete. `networks` and `skipped` hold parsed `IPv4Network` / `IPv6Network` objects
  rather than CIDR text, so the sweep reads their size and membership directly; the JSON form is the
  same CIDR strings, and `limit` records the budget the split was made under. The result is a plan
  `arp_scan(scope=...)` and `find_ip_by_mac(..., scope=...)` run as it stands, so inspecting
  coverage and sweeping it are one flow rather than two independent computations.
  `local_networks(interfaces)` and `sweep_scope(interfaces=...)` accept the interface list to read,
  which is what makes the whole default path testable without patching. `find-ip` carries the same
  record in its payload, and the JSON envelope grew a `skipped` field for it, so a machine reader
  can tell a partial answer from a complete one without parsing prose.
- **`IPScoutSweepError` with `IPScoutSweepTooWideError` and `IPScoutSweepIncompleteError`.** The
  first replaces the bare `ValueError` for a sweep with nothing left to probe. The second is new
  behaviour: a search that skipped a network and matched nothing in the rest refuses to answer,
  because "not found" would claim ground the sweep never reached. Both also derive from
  `ValueError`, which these callables have always raised, so an existing `except` keeps working.

### Fixed

- **`find-ip --network` without `--scan` is refused rather than dropped.** The flag was silently
  ignored and the command reported `ok: true` with a cache-only answer, so a caller had no way to
  tell the named network was never swept.
- **A malformed invocation exits 2, not 1.** Exit 1 is documented as "not reached", so a usage error
  - mutually exclusive flags, a flag that needs another - told a script the host had gone silent
  when the real problem was the command line. Click's own exit code is used where it states one.
- **The CLI no longer prints a Python class name at a human.** A handled failure rendered as
  `Error: ValueError: <message>`; the message alone already names the remedy, and the machine-
  readable `type` field is where a reader can branch on the class.
- **`--json-bare` reports failures as JSON.** It emitted human text on the error path, breaking the
  one promise the flag makes: that stdout holds the payload and nothing else. It now emits the bare
  `{type, message}` object, and an exception escaping a command is serialised in the same shape.

### Internal

- The `capabilities` rendering iterates its report's own fields instead of building a dict to read
  them back out, and `_emit` takes a model, a sequence of models or a mapping onto them rather than
  `Any`, so nothing untyped can reach the output boundary.
- The ctypes DLL handle and the adapter structures are typed (`iphlpapi() -> ctypes.CDLL`,
  `_IpAdapterAddresses` on the parameters that already received it), retiring eight `Any`
  annotations with no suppression added.

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
- **An integration lane that reaches the real internet.** Nine tests marked `integration` probe
  public hosts: a live ICMP round trip, a sweep whose results stay paired with their targets, a
  real traceroute with identified hops, a port scan, name resolution and its reverse, the path MTU,
  and the routed-MAC rule against an actual route. Each skips cleanly when there is no route out,
  so an offline machine reports skipped rather than failed. Run with `make testintegration`; the
  rest of the suite stays hermetic against loopback and synthetic buffers.
- **Kernel ABI fallback for `IP_RECVERR` / `IPV6_RECVERR`.** CPython only exposed these constants
  from 3.14. Without the fallback to the kernel values (11 and 25), traceroute would report itself
  unsupported on Linux for every Python from 3.10 to 3.13.

### Requirements

Python 3.10 or newer. Runtime dependencies: `lib_cli_exit_tools>=2.3.4` (earlier releases discarded
Click's return value, which collapsed the not-reached exit code of 1 into 0), `pydantic`,
`rich-click`, `rtoml`.
