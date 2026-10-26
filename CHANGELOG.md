# Changelog

All notable changes to this project will be documented in this file following
the [Keep a Changelog](https://keepachangelog.com/) format.

## [Unreleased]

### Added

- `subnet_info(interfaces=...)`: describe the given interfaces instead of reading this host's,
  as `local_networks(interfaces=...)` already does.
- `InterfaceAddress.cidr` / `.network`, `SubnetInfo.cidr` and `Neighbour.address`: the text and
  parsed views of a record's address as plain properties, so they do not appear in JSON output.
  `models.interface_cidr` / `interface_network` are the one derivation behind them.
- One home for facts several modules restated: `AddressFamily.of_socket_family`,
  `models.names_a_neighbour`, `models.require_settle` / `Settle`, `models.FamilyAddress`,
  `models.MAX_ICMP_FIELD16`, `models.BLANK_TARGET_MESSAGE` / `is_blank_target`,
  `models.LIMITED_BROADCAST`, `packet.ipv4_header_length`, `resolve.MAX_INTERFACE_INDEX` /
  `interface_name`, `deadline.MIN_WAIT` / `blocking_wait` / `seconds_left`, `unixio.packet_family`,
  `arp.require_mac` / `packed_mac` / `await_answer` / `send_neighbour_solicitation`,
  `winapi.sockaddr_inet` / `packed_to_ipv4`, `bsdroute.AF_LINK` (now exported), the shared refusal
  texts and `setcap_command` in `errors`, and `wol.WakeSettings`.

### Changed

- One refusal for a hardware address everywhere: "'x' is not a hardware address". It replaces
  "not a hardware address: 'x'" (`wake_on_lan`, `build_magic_packet`, `find_ip_by_mac`, the DHCP
  watch) and "'x' is not a 6-byte Ethernet hardware address" (the ARP and neighbour-solicitation
  builders).
- `wake_on_lan` and the DHCP watch (`DhcpSession`, `observe_dhcp_session`, `observe_dhcp`,
  `observe_dhcp_first_reachable`) check their arguments through a settings model, as every other
  entry point does. A refusal reads "wake-on-LAN refused its arguments: <field>: <reason>" or
  "DHCP watch refused its arguments: <field>: <reason>", every bad argument in one message joined
  by "; ", instead of the first one alone. A bool, a string or a float where an int is due
  (`port=True`, `port=9.0`), and a string or bool `timeout` or `settle`, are refused with
  `ValueError` before anything is sent; a bool port used to be sent to port 1, a string timeout
  raised `TypeError`, and a bool settle was accepted. An int `timeout` is stored as a float, so its
  refusal echoes it as `0.0` where it used to say `0`. `wake_on_lan` also refuses an `IPv4Address`
  object as `broadcast`; pass the text. `observe_dhcp_first_reachable` checks its window as its own
  argument ("first-reachable DHCP watch refused its arguments: timeout: ..."), reported once, not
  again under the `settle` it hands on.
- The settle refusal writes its bound as 2147483, as the timeout refusal does, instead of
  "2.14748e+06"; `ObserveDhcpReport` refuses a bad `settle` with that sentence rather than
  pydantic's.
- The network of an IPv6 address with a zone is reported without the zone at every prefix length:
  at /128 it used to keep it (`fe80::1%eth0/128`, now `fe80::1/128`). A record that carries the
  zoned form still validates.
- `set_neighbour` and the other static-entry helpers refuse a non-literal address with "'x' is not
  an IP address literal" instead of "'x' is not an IP address".
- `tcpsyn.build_syn`, `arp.build_arp_request` and the static neighbour entry writers refuse a
  non-canonical IPv4 address (shorthand such as "127.1") with `ValueError` instead of packing the
  address `inet_aton` guessed.
- `ipscout traceroute --timeout`, `ipscout observe-dhcp --timeout` and `--settle` refuse a bad
  value while the command line is parsed, naming the option (exit code 2 as before; the JSON error
  type is `BadParameter` and `command` is null). `--max-hops` reports pydantic's wording instead
  of Click's range text, its `--help` no longer prints the range, and `3.0` is read as 3, as the
  other integer options already do.
- `DhcpReply` refuses a bad `server_ip` or `offered_ip` with "'x' is not an IP address literal" or
  "'x' is not an ipv4 address" instead of the `ipaddress` module's wording.
- `syn_scan` sends one SYN per distinct port and reports the ports in order, as `scan_ports` does;
  it still takes a list only.
- `sweep_scope` given both a bad `limit` and a bad network reports the limit first; both are
  `ValueError`.
- The last read before a deadline in the active neighbour lookup and the SYN scan waits at least
  1 ms instead of 10 ms, the floor the DHCP capture already used.
- Windows: `transport_windows.ipv6_destination` refuses a malformed literal with `ValueError`
  instead of `OSError`; the ICMP echo transports and `neighbours_windows.resolve_active` refuse a
  malformed, wrong-family or (for the latter) zoned address when constructed or called, before
  anything is loaded or sent, instead of failing on the first probe or reporting nobody answered;
  `winapi.string_to_ipv4` refuses shorthand such as "127.1". `neighbours.resolve_active` refuses a
  zone naming no interface on Windows too, as it does elsewhere.
- macOS: a `PermissionError` while preparing an IPv6 neighbour solicitation (the interface lookup
  or the multicast option), not only while sending it, is reported as `IPScoutPermissionError`.

### Removed

- `ports.MIN_CAPTURE_WAIT`: use `deadline.MIN_WAIT` (the same value) or `deadline.blocking_wait`.

### Fixed

- A `getaddrinfo` result of neither IP family is skipped instead of being reported as IPv4.
- `tcpsyn.read_reply` refuses a packet whose version nibble is not 4, as the other IPv4 parsers do.

## [2.3.0] 2026-10-26 12:19:25

### Added

- `lookup_mac(ip, active=True, fallback_to_cache=True)` (and the same on `get_mac_address`, plus
  `ipscout mac --active --fallback-to-cache`): ask actively, and read the neighbour cache instead
  only when this host cannot ask, meaning no privilege (`IPScoutPermissionError`), or no interface
  or route that can carry the request, or a send or read that failed (`IPScoutUnsupportedError`). An active ask nobody answered stays an
  active answer and is never replaced by a cache entry; a host name and a zone naming no interface
  still raise. `fallback_to_cache=True` without `active=True` raises `ValueError`.
- `MacMethod` (`ACTIVE`, `CACHE`) and `MacLookup.method`: every MAC answer says whether it was asked
  for or read from the cache, and `ipscout mac` prints and emits it. `--strict` keeps it too, and now
  also carries the interface of a direct answer.

### Fixed

- An active MAC lookup no longer reports a request it could not make as "nobody answered":
  - On Windows, a `SendARP` or `ResolveIpNetEntry2` failure other than no reply (no route to the
    address, among others) and a missing `iphlpapi.dll` now raise `IPScoutUnsupportedError`.
    They used to return `None`. Only `ERROR_BAD_NET_NAME` reads as no reply.
  - On Linux and macOS, a send or receive that fails after the socket opens (the interface went
    away, the link is down) now raises `IPScoutUnsupportedError` too, instead of returning `None`.
- `lookup_mac(..., active=True)` resolves a zone before anything is sent on every platform, by
  index or by either Windows name (the friendly one `local_interfaces()` reports, or the
  `if_nametoindex` one), and raises `IPScoutResolutionError` when it names no interface. Before,
  the routed branch and Windows never looked at the zone, so a typo passed unseen. The cache read
  now matches on the interface the zone resolves to, so a numeric zone such as `%2` finds the
  entry on that link rather than whichever link holds the address.
- On Windows, an active lookup of an address with no route raises `IPScoutUnsupportedError`
  instead of reporting nobody answered: `SendARP` gives the same status for both.

## [2.2.0] 2026-10-26 11:06:07

### Added

- `read_snmp_system` / `aread_snmp_system` and the `ipscout snmp-system` command: the SNMP system
  group (sysUpTime, sysName, sysDescr, sysObjectID) of many hosts, one GET each, SNMPv1 or v2c as the
  caller chooses. Each host gets an `SnmpSystem` record with an `SnmpState` (ANSWERED, SILENT,
  REFUSED, ERROR, UNREACHABLE) instead of an exception; under v1 a value the agent lacks is asked
  around and reported as `None`. The uptime tells a restart (it fell) from mere reachability.
- `ipscout.deadline`: the per-host deadline helpers, shared by the banner grab and the SNMP read.
- `packet.max_payload_size(family)` and `packet.require_payload_size(payload_size, family)`: the
  one per-family payload bound, which `ping` and `build_echo_request` both apply.
- `models.RoundTrip` (a finite round trip of 0 or more milliseconds), `api.HostNames` /
  `api.require_host_names` (a collection of host names, refusing one bare string),
  `traceroute.TracerouteSettings` and `traceroute.DEFAULT_MAX_HOPS`, `bpf.MAX_BPF_DEVICES`, and a
  `method` field on `portscan.PortScanSettings`.
- `ipscout.models.require_port`, `Port`, `MIN_PORT` and `MAX_PORT`: the one port-range check
  (1-65535) every entry point and record taking a port number now applies.
- `ipscout.packet.MAX_PAYLOAD_SIZE_IPV4` (65507) and `MAX_PAYLOAD_SIZE_IPV6` (65527): the most ICMP
  payload one echo can carry.
- `AddressFamily.ip_version` and `AddressFamily.of_version()`.
- `ipscout.portscan.DEFAULT_TIMEOUT` (1.0 s per port), and `DEFAULT_CONCURRENCY` exported from
  `ipscout.api` and `ipscout.scan`; the CLI options take their defaults from these.
- Argument models and checks every entry point shares: `banner.BannerSettings`,
  `portscan.PortScanSettings`, `scan.SweepSettings`; `models.Timeout` / `require_timeout` (above 0,
  at most 2147483 s, finite), `models.MAX_TIMES` (65535, the 16-bit echo sequence),
  `models.MAX_HOP_LIMIT` (255), `models.parse_address` / `require_address`, `models.needs_zone`,
  `pool.Concurrency` / `require_concurrency` (at least 1), and `errors.validation_problems` /
  `refused_arguments`, which word every argument refusal the same way.
- `models.DEFAULT_TIMEOUT` (2.0 s, re-exported by `service`), `models.DISCARD_PORT`,
  `AddressFamily.unspecified_address`, `packet.MAX_IP_LENGTH`, `packet.UDP_HEADER_SIZE`,
  `packet.IPV4_MIN_HEADER_SIZE`, `arp.normalise_mac` (where `neighbours.normalise_mac` now comes
  from), `arp.format_hardware_address`, `arp.FRAME_RECEIVE_SIZE`, `ports.CAPTURE_RECEIVE_BUFFER`,
  `ports.MIN_CAPTURE_WAIT`, `wol.DEFAULT_BROADCAST`, `scan.refuse_a_partial_scope`,
  `scan.sweep_argument_refusal`.
- Windows backend helpers: `winapi.IpStatus` (an `IntEnum` of the IP_STATUS codes with their text),
  `win_family` / `family_from_win`, `sockaddr_in6`, `sockaddr_inet_address`, `address_text`,
  `reply_buffer_size`, `DEFAULT_TTL`, `ICMP_REPLY_HEADROOM`, `MAX_ADAPTER_ADDRESS_LENGTH`,
  `NO_ERROR`, `MS_LAYOUT`; `transport_windows.ipv6_destination` and `echo_outcome`;
  `neighbours_windows.declared_mac`. macOS route-socket helpers in `bsdroute`: `RTM_GET`,
  `NO_METRICS`, `pack_sockaddr_in6`, `open_route_socket`.

### Changed

- Every argument refusal reads `<operation> refused its arguments: <argument>: <reason>` (one part
  per bad argument) and is a plain `ValueError` with pydantic's report kept as `__cause__`. `ping`
  raised the `pydantic.ValidationError` itself, and with `raise_on_error=False` its `.error` held
  pydantic's text, error-type tags and a docs URL; the CLI printed the same text.
- Arguments that were accepted and then misreported are refused before anything is sent:
  `concurrency` below 1 (silently run as 1); a `timeout` of zero, below zero, infinite or above
  2147483 s in `ping`, `traceroute`, `scan_ports`, `syn_scan`, `arp_scan` and `grab_banners` (a zero
  timeout reported open ports as `FILTERED`, a sweep returned the cache as its result, a traceroute
  walked 30 silent hops, and 1e12 raised `OverflowError` mid-probe); `times` above 65535; a negative
  `payload_size`; `max_hops` above 255; a sweep `limit` below 1; an empty `farewell` (silently not
  sent); a NaN or infinite `DhcpSession` window.
- Address arguments are parsed at entry: `query_route` and `lookup_mac` refuse a host name, a
  malformed literal, a literal of the other family or a zone on an IPv4 address with `ValueError`
  (they returned `None` / `UNKNOWN`, the same as "no route"); `wake_on_lan` refuses a broadcast that
  is empty, `0.0.0.0`, a name or not IPv4 (an empty one sent the packet to this host and reported it
  sent); `scan_ports` resolves the host once and uses that address for every port (a name was
  resolved per port, and the SYN path passed the name to `inet_aton`); an unresolvable host raises
  `IPScoutResolutionError` instead of reporting every port `FILTERED`.
- Records refuse values no producer makes: `ResponseObject` (counts 0-65535, received at most sent
  and matching the answered round trips, `reached` exactly when something answered, `ip` of its
  `family`, a non-empty `error`), `TraceHop.ttl` 1-255, `InterfaceAddress` / `SubnetInfo` prefix
  length within the family, `mtu` above 0, `Interface.index` at least 1, `SweepScope.limit` at least
  1, `ObserveDhcpReport` windows, `JsonEnvelope` (`ok` exactly when `error` is absent),
  `ParsedReply` field widths, `EchoPayload.token` exactly 8 bytes, and `DhcpReply` (canonical MAC,
  a non-zero IPv4 offer, a 32-bit transaction id). `build_echo_request` refuses a token of the wrong
  length and a sequence or identifier outside 0-65535.
- A `ping` that fails before sending reports what it knew: the resolved address and family when
  resolution succeeded (it reported `0.0.0.0` / IPv4 for an IPv6 target), and 0 pings sent.
- `bootp.offers_from_frames(mac=...)` accepts any written form of the address; another spelling
  than lowercase-colon silently matched nothing.
- CLI: a bad option value is a usage error (exit 2, naming the option) before any probe, checked
  through the library's own argument types; `ping-many -c 0` exited 1 with every row failed.
  `wake`, `gateway --to` and `mac` with a bad argument exit 2 naming the command (they escaped with
  exit 1 or 22 and `command: null`). `traceroute --max-hops` is limited to 1-255. In human mode a
  usage error shows Click's usage text instead of a traceback.

- Every port number is held to 1-65535 the same way, with the message
  `port out of range 1-65535: N`. `scan_ports` / `ascan_ports` / `syn_scan` refuse a port LIST
  holding an out-of-range port with `ValueError` (only a specification string was checked);
  `grab_banners` / `agrab_banners` keep refusing a bad port, now in that wording; and
  `PortResult`, `Banner` and `WakeReport` refuse one at construction, where pydantic's
  `greater than or equal to 1` wording used to appear.
- `ping` / `aping` / `ping_many` check `tcp_port` on every call, also when no TCP fallback is
  used: out of range it raises, or with `raise_on_error=False` is reported on `.error`. It used
  to be ignored unless the fallback engaged.
- On Windows, `path_mtu()` sends its don't-fragment probes with TTL 128, Windows' own default, as
  `ping` does. It used 64, so a target more than 64 hops away could not be probed.
- `Banner` requires `error` exactly when the state is `UNREACHABLE` and refuses an empty one. It
  used to forbid `error` on the other states but allowed an `UNREACHABLE` banner without a reason.

- More arguments are checked strictly before anything is sent, in the
  `<operation> refused its arguments: <argument>: <reason>` shape:
  - `ping` / `aping` / `ping_many` / `is_reachable`: `times=True` sent one echo and `timeout="1"`
    waited a second; both are refused now (`is_reachable`, which never raises, answers `False`).
  - `ping_many` / `aping_many` and `grab_banners` / `agrab_banners`: one string passed as the host
    collection (`ping_many("printer.lan")`) probed each character as a host; it is refused, and so
    is a host that is not a string (a raw pydantic error from `Banner` before). `ping_many` checks
    `concurrency` before it takes anything from the targets; the refusal used to come after the
    targets iterable was consumed, as `concurrency must be at least 1, got 0`.
  - `traceroute` / `atraceroute` / `trace_path` / `atrace_path`: `max_hops=True` walked one hop and
    `3.0` or `"5"` raised `TypeError`; a non-bool `resolve_names` (`"no"` switched lookups on) and a
    `timeout` of the wrong type are refused. The messages change from
    `max_hops must be 1-255, got 256` (and `max_hops must be at least 1, got 0` in 2.1.0) to
    `traceroute refused its arguments: max_hops: Input should be less than or equal to 255`. The
    arguments are checked before the name is resolved, so a bad `max_hops` with an unresolvable
    name is a `ValueError`, no longer `IPScoutResolutionError`.
  - `scan_ports` / `ascan_ports` / `syn_scan` with a port LIST: `[True]` and `[80.5]` scanned port
    1 and 80 and keyed the result `True` / `80.5`; they are refused, and a list port out of range
    now reads `port scan refused its arguments: ports.0: port out of range 1-65535: 0` (a
    specification string keeps the bare `port out of range 1-65535: 0`).
    `scan_ports(method="syn")` with a plain string silently ran a connect scan; it is refused.
  - `observe_dhcp_first_reachable`: a `probe_timeout` of 0, negative, NaN or text, or a `tcp_port`
    outside 1-65535, watched the whole window and returned `None` (port 0 silently dropped the TCP
    attempt); they are refused before the capture opens.
  - `DhcpSession` / `observe_dhcp`: a `settle` above 2147483 s is refused. A `timeout` of 0 reads
    `timeout must be above 0 and at most 2147483 seconds, got 0` (2.1.0:
    `timeout must be positive, got 0: a window of zero could never see anything`).
  - `get_mac_address`, `lookup_mac` and `resolve_active`: text that is not an address literal
    raises `ValueError`. In 2.1.0 `get_mac_address("nonsense")` returned `None`, and with
    `active=True` raised `IPScoutUnsupportedError` (no route). `resolve_active` checks its
    `timeout` (0 returned `None` without waiting, -1 raised a raw `Timeout value out of range`).
  - `SweepScope.from_networks("192.0.2.0/24", ...)` (one network as text) is refused instead of
    being split into characters.
- `resolve_active` and `lookup_mac(active=True)` on Linux and macOS honour an RFC 4007 zone
  (`fe80::1%eth0`, by name or index): the request goes out on that interface. The zoned text used to
  make the backend's `inet_pton` fail, and `None` came back with nothing sent. A zone naming no
  interface raises `IPScoutResolutionError`. On Windows the zone is still not used.
- `build_echo_request` refuses a `payload_size` its family cannot carry with the same message
  `ping` uses (`10**12` raised `MemoryError`, 70000 a raw pydantic error, and IPv4 65508-65527 was
  built). `build_arp_request` / `build_neighbour_solicitation` refuse a sender address that is not
  six bytes (`"aa:bb"` was zero-padded into the frame).
- Records refuse more values no producer makes: `EchoResult.rtt_ms` NaN, infinite or negative, a
  round trip without a source (or the reverse), `ttl_expired` without an answer; `TraceHop` reached
  or named without an address, a round trip without an address, an empty `hostname`;
  `Interface` with an empty name, an address filed under the other family, a hardware address not
  in lowercase colon form or all zero, an MTU above 0xFFFFFFFF; `Neighbour` whose `ip` is not a
  bare literal of its `family` or whose `mac` is not `aa:bb:cc:dd:ee:ff`; `MacLookup` whose
  `via_ip` and `NEXT_HOP` scope disagree, `DIRECT` without a MAC or `UNKNOWN` with one;
  `SubnetInfo` whose network is not the one its address sits on, whose broadcast is not that
  network's, or whose gateway is not of its family; `SweepScope` networks covering more than its
  limit; `FindIpReport` with `scanned` and `scope` disagreeing; `ObserveDhcpReport` and
  `WakeReport` with a non-canonical MAC, unbounded windows, or a broadcast that is not a usable
  IPv4 address.
- `SubnetInfo.network` is an `IPv4Network` / `IPv6Network` instead of text. JSON output is
  unchanged; Python callers reading it as a string need `str(...)`.
- CLI: `wake`, `find-ip` and `observe-dhcp` report the MAC as `aa:bb:cc:dd:ee:ff` whatever spelling
  was typed (they echoed the input).

### Fixed

- TCP fallback probes over IPv6 (`TcpEchoTransport`, `AsyncTcpEchoTransport`) could reach an IPv4
  listener: an IPv4-mapped target (`::ffff:a.b.c.d`) connected through IPv4 on Linux and macOS,
  and on macOS with Python 3.15 a plain IPv4 literal did too, so the host read as reachable over
  IPv6. The probe socket now sets `IPV6_V6ONLY`, and such a target reads as unanswered.
- Windows `local_interfaces()`: an adapter with no friendly name was named `b'{GUID}'` (the repr
  of the bytes) and one with no name at all `''`; it is now `{GUID}`, or `ifindex-<n>` /
  `adapter-<position>` when even that is missing.
- macOS `dhcp_capture_available()`: a busy `/dev/bpf0` answered `False` although a capture would
  claim the next free device; it now tries the same pool a capture does.
- `reverse_dns` answers `None` for an empty PTR name, which a traceroute with `resolve_names=True`
  would otherwise have failed on.
- `aping`, `aping_many`, `ais_reachable` and `atraceroute` resolve their target in a worker
  thread, and `atrace_path(resolve_names=True)` looks up each hop's name there too. They called
  `getaddrinfo` / `gethostbyaddr` on the event-loop thread, so one slow name server stalled every
  other task in the loop: in `aping_many`, one slow name held up the whole sweep.
- `is_reachable` / `ais_reachable` resolve the target once and probe that one address on both the
  ICMP and the TCP attempt; they resolved twice, so round-robin DNS could make the two attempts
  probe different hosts. ICMP versus TCP is now chosen for the family the target resolved to, not
  for IPv4, and a socket error from either attempt answers `False` instead of escaping. A
  `tcp_port` outside 1-65535 raised an uncaught `OverflowError` from the connect; it now makes only
  the TCP attempt answer `False`, so a host that answers ICMP still reads as reachable.
- `ping` / `aping` / `ping_many` refuse a `payload_size` above 65507 bytes for an IPv4 target or
  65527 for IPv6 (raised, or on `.error` with `raise_on_error=False`). Such an echo cannot be sent,
  and the failed send was reported as a live host that never answered.
- `wake_on_lan` refuses a port outside 1-65535 with `ValueError`. It raised an uncaught
  `OverflowError` from the socket layer, which the CLI printed as a traceback.
- An interface whose sysfs MTU reads 0 is listed with no MTU instead of failing the listing.

### Removed

Backend-module names replaced by the shared definitions above. Nothing in the top-level `ipscout`
namespace is removed or changed.

- `winapi.IP_SUCCESS`, `IP_DEST_NET_UNREACHABLE`, `IP_DEST_HOST_UNREACHABLE`, `IP_REQ_TIMED_OUT`,
  `IP_TTL_EXPIRED_TRANSIT`: use `winapi.IpStatus` members, which compare equal to the same numbers.
- `neighbours_linux`, `neighbours_windows`, `bsdroute` and `tcpsyn` no longer define their own
  `format_mac`, `MAC_LENGTH` and `checksum`; they import `arp.format_mac`, `arp.MAC_LENGTH` and
  `packet.checksum` (the same RFC 1071 sum) and drop them from `__all__`. An old import still
  resolves, except that `neighbours_windows.format_mac` now takes one argument: for a
  length-prefixed buffer use `neighbours_windows.declared_mac(raw, length)`.
- `neighbours_windows.resolve_active(ip)` takes the family as a second argument; an IPv4 address in
  a non-dotted-quad form such as `192.0.2` resolves to nothing instead of being read as `192.0.0.2`.

## [2.1.0] 2026-10-24 17:18:42

### Added

- `grab_banners` / `agrab_banners`: read the first line each of many hosts sends on one TCP port,
  connecting, reading, optionally sending a `farewell` such as `b"QUIT\r\n"`, and closing on ONE
  connection per host, so a device that refuses a second connect right after a session is still
  read. Each host gets a `Banner` whose `BannerState` is `GREETED` (with `line`), `SILENT`,
  `REFUSED` or `UNREACHABLE` (with `error`); a name that does not resolve is a result, not an
  exception. One `timeout` per host covers resolution, connect and read; results keep input order.
- `ipscout banners HOSTS... --port N`, the 22nd subcommand. A `HOSTS` item written as a network
  expands to its hosts within the sweep bound; `--farewell` decodes `\r`, `\n`, `\t` and `\\`.
  Exits 1 when no host greeted.

### Fixed

- `ping_many` / `aping_many` return their mapping in the order the targets were given, as documented.
  It was in completion order, so a target that timed out ahead of one that answered came after it.
- The TCP fallback (`allow_tcp_fallback`, `is_reachable`) counts a refused connection as an answer
  in every spelling a platform uses for it. It recognised only `ConnectionRefusedError`, so a refusal
  arriving as a bare `OSError` with `ECONNREFUSED`, or with the Windows numbering 10061 / 1225,
  reported a live host as unanswered.
- In `--json` and `--json-bare` modes, an invalid option value is reported with the option's name
  (`Invalid value for '--timeout': ...`). The JSON error message carried only Click's bare text,
  which did not say which option was wrong.

## [2.0.0] 2026-10-24 12:32:19

### Changed

- **Breaking:** `factory.make_transport` and `factory.make_async_transport` take
  `method: ProbeMethod = ProbeMethod.ICMP` in place of `use_tcp: bool = False`. A caller passing
  `use_tcp=True` passes `method=ProbeMethod.TCP` instead; a caller passing neither is unaffected.
- **Breaking:** `packet.build_echo_request`, `packet.is_echo_reply` and `packet.is_time_exceeded`
  take `family: AddressFamily` in place of `is_ipv6: bool` (`build_echo_request` defaults to
  `AddressFamily.IPV4`, as `is_ipv6=False` did). The bytes they build and the answers they give are
  unchanged.
- **Breaking:** `cli.CliContext` no longer has a `traceback` field. Nothing read it: `main()` takes the
  setting from the command line, because the error it governs can escape before the context exists.
  `--traceback` / `--no-traceback` work as before.
- `neighbours_macos` no longer lists `iter_bpf_frames` in `__all__`; it lives in `ipscout.bpf`.
- Functions that returned a fixed-shape record as a bare tuple now return a named tuple. Each is
  still a tuple, so unpacking, indexing and comparison with a plain tuple keep working; only the
  `repr` changed:
  - `resolve.resolve_one` returns `ResolvedTarget(address, family)`;
  - `resolve.split_zone` returns `ScopedAddress(address, zone)`;
  - `packet.build_echo_request` returns `EchoRequest(datagram, token)`;
  - `tcpsyn.read_reply` returns `PortReply(port, state)`;
  - `neighbours_linux.parse_neighbour_dump` returns `NeighbourDumpChunk(entries, done)`;
  - `bpf.open_bpf_device` returns `BpfDevice(descriptor, buffer_length)`.
- `trace_path` and `atrace_path` read the transport's `supports_ttl_discovery` property directly. A
  transport object without it, which the `EchoTransport` protocol already rejects at type-check
  time, now raises `AttributeError` instead of being treated as unable to discover hops.

### Fixed

- `resolve.zone_index` takes a zone as an index only when it is 1 to 10 ASCII digits no larger than a
  sockaddr scope can hold. A superscript-digit zone raised a bare `ValueError`, one written in another
  script's digits (Arabic-Indic two) was silently read as index 2, an index past what a sockaddr holds
  was probed anyway, so `ipscout ping` reported the host as not reached (exit 1), and a run of
  thousands of digits hit `int()`'s digit limit. Each is now an `IPScoutResolutionError` naming the
  zone (CLI exit 2), as is a name with an embedded NUL.

### Internal

- The CLI carries its output shape as one `OutputMode` enum (human, envelope, bare) instead of two
  booleans; `--json`, `-j` and `--json-bare` and every output they produce are unchanged.
- The neighbour-write backends name the change they report on (`add`/`remove`) with a
  `NeighbourChange` enum instead of a string; the error messages are unchanged.
- Private helpers that returned bare tuples (in `neighbours`, `neighbours_linux`, `tcpsyn`,
  `bootp`, `interfaces_posix`, `interfaces_windows` and `transport_posix`) return named tuples too.

## [1.7.0] 2026-10-23 23:14:12

### Added

- `set_neighbour(ip, mac, *, interface=None)` writes a permanent (static) IPv4 neighbour entry and
  returns it as read back from the neighbour cache; `remove_neighbour(ip, *, interface=None)` deletes
  one and returns whether there was one. Both are native, with no subprocess: netlink
  `RTM_NEWNEIGH`/`RTM_DELNEIGH` on Linux, `CreateIpNetEntry2`/`DeleteIpNetEntry2` on Windows, and
  `RTM_ADD`/`RTM_DELETE` on a routing socket on macOS. Writing needs root or `CAP_NET_ADMIN` on Linux,
  root on macOS and Administrator on Windows, and a refusal raises `IPScoutPermissionError` naming the
  remedy. Without `interface=`, `set_neighbour` picks the one interface whose subnet holds the address.
  IPv6 raises `IPScoutUnsupportedError`; a multicast, broadcast or zero address or MAC raises
  `ValueError`. The macOS path is untested on real hardware: its message encoding is pinned byte for
  byte, the system call is not.
- CLI subcommands `set-neighbour IP MAC [--interface]` and `remove-neighbour IP [--interface]`, with
  the usual `--json` / `--json-bare` envelope; `remove-neighbour` exits 1 when there was no entry.

### Tests

- A `host_mutating` marker for tests that change this host's network state. Such a test runs only
  with `IPSCOUT_HOST_WRITE_TESTS=1` (wired in `tests/conftest.py`, pinned by
  `tests/test_platform_markers.py`), so no CI runner writes its neighbour table - the Windows one is
  elevated and would otherwise do it on every push.

## [1.6.2] 2026-10-15 17:13:03

### Fixed

- The source distribution ships only the package, its tests, its docs, `README.md`, `LICENSE`,
  `CHANGELOG.md` and `pyproject.toml` (an include list). Earlier sdists also carried every other
  root file and, in a local build, anything hidden only through `.git/info/exclude` or a nested
  `.gitignore`. `tests/test_packaging.py` builds the sdist and wheel and checks both; `hatchling`
  joins the dev extra for it.

### Changed

- Ruff selects `C90` (mccabe), so a function over cyclomatic complexity 10, the house hard limit,
  now fails `make test`; before, nothing enforced it.

### Tests

- The `os_windows`, `os_macos`, `os_linux` and `os_posix` markers now skip a test off its platform
  (`pytest_runtest_setup` in `tests/conftest.py`); registered in `pyproject.toml` alone they skipped
  nothing, so a test trusting its marker ran everywhere. `tests/test_platform_markers.py` pins it.

## [1.6.1] 2026-10-12 22:49:02

### Added
- Python 3.15 is a supported version: declared in the classifiers, so CI and `make test-all` run it.
- `uv.lock` is committed, and `[tool.uv] exclude-newer` sets a cooldown that keeps releases younger
  than it out of the lock. CI installs exactly the locked tree on push and pull request; the nightly
  scheduled run still resolves afresh to catch upstream breakage early.

### Changed
- The install section explains why installing with uv protects against supply-chain attacks and why
  a plain `pip install` from PyPI does not.
- `rtoml` floor raised to 0.14.0, the first release with Python 3.15 wheels.

## [1.6.0] 2026-08-01 01:08:25

## [1.6.0] 2026-08-01

### Added

- **`family=` on the three calls that return addresses**, matching the twelve probing functions
  that already had it: `find_ip_by_mac`, `neighbours` and `arp_scan` now take
  `family=AddressFamily.IPV4` / `IPV6`, and `find-ip`, `arp-scan` and `neighbours` take `-4` /
  `-6` on the command line, spelled as on `resolve`. One hardware address commonly holds an IPv4
  AND an IPv6 link-local, and they come back in the order the cache learned them, so a caller
  taking the first entry of an unfiltered list was letting that order decide - and got a
  link-local whenever one happened to be learned first. Keyword-only and defaulting to `None`,
  so the unfiltered behaviour is unchanged.

  Unlike `resolve`, asking for a family the target does not hold returns an EMPTY result rather
  than raising: empty already means "not known here" for these calls, and "that MAC holds no
  IPv6" is an ordinary finding, not a failure.


## [1.5.0] 2026-07-31 23:04:58

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
