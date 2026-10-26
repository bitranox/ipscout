# Usage

Task-oriented guide to the library and the CLI. Every example here was run before it was written
down.

- [Ping one host](#ping-one-host)
- [Sweep many hosts](#sweep-many-hosts)
- [Async](#async)
- [Traceroute](#traceroute)
- [Is it reachable at all](#is-it-reachable-at-all)
- [Local interfaces](#local-interfaces)
- [Resolve and reverse-resolve](#resolve-and-reverse-resolve)
- [The CLI](#the-cli)
- [JSON output](#json-output)
- [Error handling](#error-handling)
- [Public surface](#public-surface)

## Ping one host

```python
import ipscout

result = ipscout.ping("127.0.0.1", 2, interval=0)

result.reached  # True
result.ip  # '127.0.0.1'
result.packets_sent  # 2
result.packets_received  # 2
result.n_packets_lost  # 0
result.packets_lost_percentage  # 0
result.time_min_ms  # fastest round trip in ms
result.time_avg_ms  # mean round trip in ms
result.time_max_ms  # slowest round trip in ms
result.jitter_ms  # population stdev, or -1.0 with fewer than two replies
result.family  # AddressFamily.IPV4
result.method  # ProbeMethod.ICMP
result.str_result  # the one-line summary, in its documented format
```

`ResponseObject` is frozen and every derived value is a real model field, so `model_dump()` carries
the statistics rather than dropping them.

The full signature:

```python
ipscout.ping(
    target,                      # hostname or IP literal
    times=4,                     # echoes to send
    *,
    timeout=2.0,                 # seconds to wait per reply
    interval=0.2,                # seconds between the start of consecutive echoes
    family=None,                 # AddressFamily.IPV4 / IPV6, or None for the resolver preference
    payload_size=56,             # bytes of ICMP payload, at most 65507 (IPv4) / 65527 (IPv6)
    allow_tcp_fallback=False,    # probe over TCP when ICMP is unavailable
    tcp_port=443,                # port the TCP fallback uses; checked (1-65535) on every call
    raise_on_error=True,         # False reports failures on .error instead of raising
)
```

Forcing a family, and using the TCP fallback on a host without ICMP permission:

```python
import ipscout

v6 = ipscout.ping("::1", 1, family=ipscout.AddressFamily.IPV6)
print(v6.reached, v6.family.value)

fallback = ipscout.ping("example.com", 1, allow_tcp_fallback=True, tcp_port=443)
print(fallback.reached, fallback.method.value)  # method tells you which protocol answered
```

A TCP result is never substituted silently. `allow_tcp_fallback=True` engages only when ICMP is
*unavailable* to the process, and the `method` field records what actually happened.

## Sweep many hosts

```python
import ipscout

results = ipscout.ping_many(["127.0.0.1", "::1", "localhost"], times=1, concurrency=32)

for target, result in results.items():
    print(target, result.reached, result.error)
```

The result is a dict keyed by target, in the order the targets were given. Duplicates collapse.
`raise_on_error` defaults to `False` here, unlike `ping`: one bad name among two hundred should not
destroy the other 199 results, so the failure lands on that target's own `.error` instead.

`ping_many` refuses to run inside a running event loop, where it would deadlock. Await
`aping_many` there.

## Async

```python
import asyncio
import ipscout


async def main():
    one = await ipscout.aping("127.0.0.1", 1)
    many = await ipscout.aping_many(["127.0.0.1", "::1"], times=1, concurrency=64)
    alive = await ipscout.ais_reachable("127.0.0.1")
    return one.reached, {t: r.reached for t, r in many.items()}, alive


print(asyncio.run(main()))
```

`aping` and `aping_many` take the same arguments as their synchronous counterparts and honour the
same contract. On Linux and macOS the ICMP socket is registered with the event loop, so a sweep of
thousands runs on one thread. On Windows `IcmpSendEcho` is a blocking C call with no asyncio
integration, so the async path is executor-backed. Behaviour is identical; scaling is not.

Echoes within one target stay sequential and paced even in the async path, so timings stay
comparable. Concurrency happens between targets.

## Traceroute

```python
import ipscout

hops = ipscout.traceroute("1.1.1.1", max_hops=10, timeout=2.0)

for hop in hops:
    print(hop.ttl, hop.address, hop.rtt_ms, hop.reached, hop.hostname)
```

Each `TraceHop` carries `ttl`, `address`, `rtt_ms`, `reached` and `hostname`. A silent hop is
recorded with `address=None` rather than dropped, because a firewall ignoring one hop in an
otherwise complete path is information, and dropping it would misnumber every hop after it. The walk
stops at the first hop that is the target itself.

`resolve_names=True` adds a reverse-DNS lookup per responding hop. It is off by default because it
costs a DNS round trip per hop.

The async form:

```python
import asyncio
import ipscout

hops = asyncio.run(ipscout.atraceroute("127.0.0.1", max_hops=3, timeout=2.0))
print([(h.ttl, h.address, h.reached) for h in hops])
# [(1, '127.0.0.1', True)]
```

Hops stay sequential rather than concurrent: the walk has to stop at the hop that answers, and
firing all thirty at once would probe far past the target on every short path.

If you already own a transport, `trace_path` and `atrace_path` drive it directly:

```python
import ipscout
from ipscout.factory import make_hop_transport
from ipscout.resolve import resolve_one

address, family = resolve_one("127.0.0.1")
with make_hop_transport(address, family) as transport:
    hops = ipscout.trace_path(transport, max_hops=3, timeout=1.0)
print([(h.ttl, h.address, h.reached) for h in hops])
# [(1, '127.0.0.1', True)]
```

**Traceroute on macOS needs root.** Unprivileged, it raises `IPScoutUnsupportedError`; see
[Error handling](#error-handling).

## Is it reachable at all

```python
import ipscout

ipscout.is_reachable("127.0.0.1")  # True
ipscout.is_reachable("nothing.invalid")  # False
```

This is the deliberate exception to the error contract. It never raises, and it always tries TCP
when ICMP does not answer or is unavailable. That is what makes it a shortcut.

It is not `ping(target).reached`. `ping` reports whether *ICMP* succeeded and raises on a bad name;
`is_reachable` reports whether the host is alive by any route and answers `False` for a bad name.
Use `ping` when that distinction matters.

## Local interfaces

```python
import ipscout

for item in ipscout.local_interfaces():
    print(item.name, item.index, item.is_up, item.is_loopback, item.mac, item.mtu)
    for address in item.ipv4:
        print("  v4", address.address, address.prefix_len)
    for address in item.ipv6:
        print("  v6", address.address, address.prefix_len)
```

Interfaces that are down are included, since a down interface is a fact worth reporting rather than
an omission. The POSIX backend uses `getifaddrs`, the Windows backend uses `GetAdaptersAddresses`,
and both return the same frozen `Interface` record.

`index` is the interface index the kernel knows, and it is what to write as the zone of an IPv6
link-local address - `ping(f"fe80::1%{item.index}")`. Prefer it over `name`: on Windows the name
is the adapter's friendly name (`Ethernet 4`), which neither `getaddrinfo` nor `if_nametoindex`
recognises, so it is not usable as a zone there.

## Reaching an IPv6 link-local address

A `fe80::` address is only unique on one link, so it has to say which one. Every call that takes an
address takes the zone with it, and one written without a zone is refused by name rather than
reported as an unreachable host:

```python
import ipscout

eth0 = next(item for item in ipscout.local_interfaces() if item.name == "eth0")
ipscout.ping(f"fe80::200:5eff:fe00:5310%{eth0.index}")
ipscout.lookup_mac(f"fe80::200:5eff:fe00:53af%{eth0.index}")

ipscout.ping("fe80::1")  # IPScoutResolutionError: needs the interface to send on
```

An interface **name** works as a zone on Linux and macOS, and `neighbours()` and `query_route()`
report names from a namespace that works on Windows too, but only the index is portable across all
three.

## Resolve and reverse-resolve

```python
import ipscout

ipscout.resolve("localhost")  # ['127.0.0.1', '::1']
ipscout.resolve("::1", family=ipscout.AddressFamily.IPV6)  # ['::1']
ipscout.reverse_dns("127.0.0.1")  # 'localhost'
ipscout.reverse_dns("this is not an address")  # None
```

`resolve` deduplicates and preserves resolver order. Asking for a family the target does not have
raises `IPScoutResolutionError` rather than returning an empty list, because an empty list reads as
"host down". `reverse_dns` returns `None` when there is no PTR record, since a missing PTR record is
a normal state of the world.

## Hardware addresses, and whose they are

A MAC address does not survive a router hop. The frame sent toward a routed address carries the
next-hop router's address; the remote host's own never appears in any packet arriving here. So the
scope is part of the answer:

```python
import ipscout

answer = ipscout.lookup_mac("8.8.8.8")
answer.mac, answer.scope, answer.via_ip
# ('00:00:5e:00:53:01', <MacScope.NEXT_HOP: 'next_hop'>, '192.0.2.1')

ipscout.get_mac_address("8.8.8.8")  # None - refuses to pass off the gateway's
ipscout.get_mac_address("192.0.2.5")  # '00:00:5e:00:53:05' for an on-link host
```

`lookup_mac` never raises on the passive path: an address this host has no route to, or has simply
not spoken to, comes back as `MacScope.UNKNOWN`.

The passive path reads the neighbour cache, which knows only hosts this machine has already talked
to and can still hold one that has gone. `active=True` sends a real ARP request or neighbour
solicitation instead. That needs root or `CAP_NET_RAW` on Linux and macOS (Windows IPv4 needs
nothing), and without them it raises rather than quietly reading the cache. When a caller wants an
answer either way, `fallback_to_cache=True` reads the cache instead, but only when this host cannot
ask: no privilege (`IPScoutPermissionError`), or no interface or route that can carry the request,
or a send or read that failed (`IPScoutUnsupportedError`). Every record says which one answered in
`method`. On Windows IPv4 the active path is `SendARP`, which answers from Windows' own ARP table
when it holds the address and sends a request only when it does not:

```python
answer = ipscout.lookup_mac("192.0.2.7", active=True, fallback_to_cache=True)
if answer.method is ipscout.MacMethod.CACHE:
    print("only the cache was read: an empty answer does not mean the address is free")
```

An active ask that nobody answers is reported as `method=ACTIVE` with `mac=None` and is never
replaced by a cache entry, since "nothing answers this address now" is exactly what a stale entry
would contradict. A host name still raises `ValueError` and a zone naming no interface still raises
`IPScoutResolutionError`, with the fallback on or off. `fallback_to_cache=True` without
`active=True` raises `ValueError`. On the command line it is
`ipscout mac 192.0.2.7 --active --fallback-to-cache`.

## The neighbour cache, and searching it

`neighbours()` reports what the kernel already learned, so a host that has never been contacted
does not appear. `arp_scan()` sweeps first and then reads, which is why it finds more:

```python
for entry in ipscout.neighbours():
    entry.ip, entry.mac, entry.interface, entry.state, entry.scoped

found = ipscout.arp_scan("192.0.2.0/24")
```

`scoped` is the entry's address in the form a probe accepts: for a link-local entry it carries the
interface the entry was learned on, and for every other address it is `ip` unchanged. Use it rather
than joining the two yourself, which gets the IPv4 case - where a zone is meaningless - wrong.
`find_ip_by_mac` already returns that form, so its answers go straight back into `ping`.

There is no protocol that asks "who has this MAC" - RARP is dead - so the reverse search sweeps and
searches the refreshed cache. It returns a list because one hardware address legitimately holds
several addresses, commonly an IPv4 and an IPv6 link-local on the same NIC:

```python
ipscout.find_ip_by_mac("00:00:5e:00:53:42", scan=True)
# ['192.0.2.104', 'fe80::200:5eff:fe00:5342']
```

Any written form compares equal - `00:00:5e:00:53:01`, `00-00-5E-00-53-01` and `0000.5e00.5301` are
the same address. `network=` and `scope=` apply only when `scan=True`; giving one without it is
refused rather than ignored, since without a sweep there is only the cache to search.

`arp_scan()` with no argument sweeps the subnets this host is attached to that fit inside one
sweep's budget of 4096 addresses, counted across all of them together. A container bridge on a
`/16` holds far more than that on its own, so it is left out rather than cancelling the sweep - and
it is named, because a result assembled from part of the ground is not the same answer:

```python
ipscout.sweep_scope()
# SweepScope(limit=4096, networks=(IPv4Network('192.0.2.0/24'),), skipped=(IPv4Network('172.17.0.0/16'),), complete=False)
```

The fields hold parsed networks, so you can ask one for its size or test membership without
re-parsing text. They still cross the JSON boundary as the same CIDR strings, and a value that is
not a network is refused when the record is built. `limit` is the budget that decided the split,
recorded on the record so a reader never has to assume which one applied.

A scope is a plan you can run, so "ask, then decide, then sweep" is one flow rather than two
guesses:

```python
scope = ipscout.sweep_scope(limit=1024)  # a tighter budget than the default
if scope.complete:
    entries = ipscout.arp_scan(scope=scope)  # sweep exactly what was inspected
```

`arp_scan` and `find_ip_by_mac` take either `network=` or `scope=`, never both - a silent
precedence rule would leave you reading a result about ground you did not ask about.

`limit` must be at least 1, `timeout` above 0 and at most `MAX_TIMEOUT`, and `concurrency` at least 1; anything
else raises `ValueError` naming the argument before a probe is sent. A zero timeout would refuse
every probe and hand back the cache as it already stood, as though the sweep had found it.

`local_networks(interfaces)` and `sweep_scope(interfaces=...)` also accept the interface list to
read, for describing a host other than this one:

```python
from ipscout import Interface, InterfaceAddress

elsewhere = [Interface(name="eth0", ipv4=(InterfaceAddress(address="198.51.100.5", prefix_len=24),), is_up=True)]
ipscout.local_networks(elsewhere)  # (IPv4Network('198.51.100.0/24'),)
```

Ask that before sweeping and you know what the answer will and will not cover. Two consequences
worth knowing:

- The budget is spent in the order the host reports its interfaces, so a subnet that would fit on
  its own is still skipped once the networks before it have used the 4096 up. Naming it with
  `--network` sweeps it on its own.
- `arp_scan("172.17.0.0/16")` still raises `IPScoutSweepTooWideError`: naming a network explicitly
  is a request, and one that cannot be honoured is refused rather than quietly ignored. Name a
  narrower CIDR inside it instead.
- `find_ip_by_mac(mac, scan=True)` raises `IPScoutSweepIncompleteError` when it matched nothing and
  a network was skipped. "Not found" would claim ground the sweep never reached. A search that does
  find something returns it, though the list can be short an address that hardware holds on the
  network left out.

## Writing a static neighbour entry

A device answers whatever address the sender's neighbour cache maps to its hardware address. That
is how many print servers and other embedded devices are given an address the first time: map a
chosen IPv4 address to the device's MAC with a static entry, talk to that address, then take the
entry out again.

```python
entry = ipscout.set_neighbour("192.0.2.7", "00:00:5e:00:53:07", interface="eth0")
try:
    ipscout.ping("192.0.2.7", 1)  # the device owning that MAC answers
finally:
    ipscout.remove_neighbour("192.0.2.7", interface="eth0")
```

- **It needs privilege**, unlike every read here: root or `CAP_NET_ADMIN` on Linux, root on macOS,
  Administrator on Windows. Without it the call raises `IPScoutPermissionError` naming the remedy.
- **IPv4 only.** An IPv6 address raises `IPScoutUnsupportedError`. A multicast, broadcast or
  unspecified address, and an all-zero, broadcast or multicast MAC, raise `ValueError` before
  anything is written.
- **The interface** is its index as digits (portable everywhere) or its name; on Windows either the
  friendly name `local_interfaces()` reports or the one `neighbours()` reports. Left out,
  `set_neighbour` picks the one interface whose IPv4 subnet holds the address, and refuses when
  none or several do.
- **The return value is read back from the cache**, so it proves the kernel holds the entry rather
  than only that the call returned. An existing entry for the address on that interface, learned or
  static, is replaced.
- **`remove_neighbour` returns `False` when there was no entry.** Without `interface=` it reads the
  cache first (no privilege needed) and deletes the address on every interface listed; naming the
  interface always asks the kernel, so it needs the privilege even when there is nothing to delete.
- **A static entry outlives the process** and overrides what the network answers until it is
  removed or the host reboots, so remove it in a `finally`.

Every platform writes natively: netlink `RTM_NEWNEIGH`/`RTM_DELNEIGH` on Linux,
`CreateIpNetEntry2`/`DeleteIpNetEntry2` on Windows, and `RTM_ADD`/`RTM_DELETE` on a routing socket
on macOS, as `arp -s` does. The macOS path has not been run on real hardware: its message encoding
is pinned byte for byte by tests, but no CI runner is root on macOS.

## Watching a DHCP handshake

Everything above needs the target already up and answering. A machine that has
just been started has no address, answers no ARP, and has no neighbour entry -
and it asks for an address about a second after the start command. Watching
that exchange is the only way to catch it.

```python
import ipscout

with ipscout.observe_dhcp_session(mac, interface="br0", timeout=150) as watch:
    start_the_machine()  # the handshake happens ~1s into this
    addresses = watch.result()
# ['198.51.100.36', '198.51.100.51']
```

Start the session *before* the machine. A one-shot `observe_dhcp(mac,
interface="br0")` begins capturing when it is called, which is already too late
if the start command went first; it is there for a machine that is booting
anyway. Opening the capture on entry is also what makes a missing privilege
surface before you start anything, rather than as an empty list two minutes
later.

**Every offer is returned, in the order seen, and the last one is usually the
address that stuck.** A pool that hands out an address the guest declines after
duplicate-address detection offers a working one seconds later, and both land in
the same exchange. Taking `addresses[0]` is exactly how a reachable machine gets
reported as never having booted. Check each, or let the wrapper do it:

```python
ipscout.observe_dhcp_first_reachable(mac, interface="br0")
# '198.51.100.51', or None if nothing answered
```

That returns as soon as a candidate answers, so a successful lookup skips the
settle wait entirely. The two outcomes cost very different amounts of time,
though: `None` runs the whole `timeout` out, because giving up earlier would
mean declaring a machine absent while its window was still open.
For a custom stopping rule, iterate `session.offers()`, which yields each new
address as it arrives; `result()` still reports all of them afterwards.

`result()` blocks until 12 seconds pass with no new address (`settle`), or until
`timeout` runs out - so 12 seconds is a floor on every call. If that is too slow,
use `offers()`; do not shorten `timeout`, which cuts off the second offer and
re-creates the problem above. Nothing appearing at all costs the full `timeout`,
because only the whole window can establish absence, and it returns `[]` rather
than raising: a machine that did not appear is a different fact from a capture
that could not run.

Needs elevation on every platform: root or `CAP_NET_RAW` on Linux, root on
macOS, Administrator on Windows. Ask `ipscout.dhcp_capture_available()` first.
The macOS backend's device path has not been run on real hardware - no CI runner
may open a BPF device - so treat it as new; on macOS name a bridge or physical
interface rather than `lo0`, which is not Ethernet-framed and is refused. The interface goes into promiscuous mode for the session's lifetime,
which is not optional in practice: on a bridge a reply is forwarded to the
guest's own port and a Linux client does not set the broadcast flag that would
make it visible otherwise.

The backends do not all see the same traffic, and it is worth knowing which you
are on. Linux binds `AF_PACKET` and macOS a `/dev/bpf` device to the interface
you name, so pointing either at a bridge shows the frames the bridge forwards to
its guests. Windows uses
`SIO_RCVALL` on a raw socket, which shows what reaches this host's own
interface - on a Hyper-V virtual switch that does **not** include other guests'
traffic unless the port is configured to mirror it. On Windows `interface=` may
be an adapter name or the IPv4 address to bind, since `SIO_RCVALL` binds to an
address rather than to a device.

## Routes and subnets

```python
ipscout.default_gateway()  # RouteInfo(gateway='192.0.2.1', interface='eth0', ...)
ipscout.query_route("8.8.8.8")  # how this host would reach one address
ipscout.local_networks()  # the IPv4 subnets a default sweep covers

for subnet in ipscout.subnet_info():
    subnet.interface, subnet.address, subnet.network, subnet.broadcast, subnet.gateway, subnet.mtu
```

`local_networks()` is the sweep view rather than the full picture: it leaves out loopback, where a
sweep would find only this host, and any `/31` or `/32`, which hold this host plus at most one
point-to-point peer. `subnet_info()` still reports those addresses, and naming such a network
explicitly still sweeps it.

`subnet_info()` sends no DHCP traffic. The addressing comes from the same system calls the interface
listing makes, and the DHCP fields are read from the lease store the OS's own client wrote - so they
may be unset on macOS and Windows. The addressing fields work everywhere.

## Port scanning

```python
states = ipscout.scan_ports("192.0.2.10", "22,80,443,8000-8100")
open_ports = [port for port, state in states.items() if state is ipscout.PortState.OPEN]
```

Three states, not a boolean. `CLOSED` means something actively refused, which proves a host is
there; `FILTERED` means nothing answered. Conflating them hides the firewall a scan is asked to
find. On Windows a connect scan cannot draw that line - a closed port goes quiet rather than
refusing - so it reports `FILTERED` where the other two report `CLOSED`.

A half-open SYN scan distinguishes them everywhere it can run, and needs a raw socket:

```python
ipscout.scan_ports(host, "1-1024", method=ipscout.ScanMethod.SYN)
# IPScoutPermissionError unprivileged, naming CAP_NET_RAW and the connect alternative
```

Both methods hold only `concurrency` probes alive at a time, so a full-range scan is bounded in
memory rather than allocating a task per port.

A name is resolved once, before the first probe, and every port is asked of that one address. A
name that does not resolve raises `IPScoutResolutionError` rather than reporting every port
`FILTERED`, which would read as a firewall. `timeout` must be above 0 and at most `MAX_TIMEOUT` and
`concurrency` at least 1: a zero timeout reports an open port `FILTERED`, so it raises `ValueError` instead.

## Reading a banner

Many services announce themselves the moment a client connects: an FTP or SMTP server sends a `220`
line, an SSH server its version string. `grab_banners` reads that first line from many hosts at once,
which is how a device is identified by what it says rather than by which port it has open:

```python
results = ipscout.grab_banners(["192.0.2.10", "192.0.2.11"], 21, farewell=b"QUIT\r\n")
for host, banner in results.items():
    if banner.line is not None and banner.line.startswith("220 Print Server"):
        print(host, banner.line)  # 192.0.2.10 220 Print Server Ready.
```

Match the part of the greeting that names the device: every FTP server sends a `220` line.

Each `Banner` carries one of four states. `GREETED` holds the decoded first line in `line`, and only
a `GREETED` result has one, so `banner.line is not None` is the same test and narrows the type; `SILENT`
means the host accepted the connection and sent nothing before the deadline; `REFUSED` means the port
actively refused; `UNREACHABLE` puts the reason in `error`, and also covers a name that did not
resolve, so one bad name never costs the other results.

Everything for one host happens on a single connection: connect, read up to the first newline (at
most `max_line_bytes`, 512 by default), send `farewell` if given and a line was read, close. Some
embedded servers refuse a new connection for a moment after each session, so scanning for open
ports first and connecting again to read misses exactly the devices a banner identifies.

`timeout` (3.0 s by default) is one deadline per host for resolving, connecting and reading
together. The arguments are checked before anything connects, and one `ValueError` names every bad
one: `timeout` must be above 0 and at most `MAX_TIMEOUT`, `max_line_bytes` and `concurrency` at least 1, and
`farewell` not empty, since an empty one could only be skipped. A refused connection is reported rather than retried; retry it yourself when the device is
known to need it. `agrab_banners` is the same on the event loop.

## Reading a device's SNMP system group

Most network printers, switches and print servers run an SNMP agent. `read_snmp_system` asks each
host for four values in one GET: how long the agent has run, the name an administrator gave the
device, its free-text description and the vendor's identifier for the model.

```python
results = ipscout.read_snmp_system(["192.0.2.10", "192.0.2.11"])
for host, system in results.items():
    if system.state is ipscout.SnmpState.ANSWERED:
        print(host, system.name, system.uptime_seconds)  # 192.0.2.10 PRINTER 83186.4
```

The uptime is the restart detector: read it before an action that restarts the device and again
afterwards, and a smaller value means it restarted. It wraps to 0 after about 497 days.

Each `SnmpSystem` carries one of five states. `ANSWERED` holds the values, each `None` when the
agent does not have it; `SILENT` means nothing arrived before the deadline, which is what a
host that is down, a host without an agent and a wrong community all look like; `REFUSED` means the
host answered with ICMP port unreachable, so it is up and has no agent on that port; `ERROR` and
`UNREACHABLE` put the reason in `error`.

`version` is `SnmpVersion.V1` (the default) or `SnmpVersion.V2C`, and there is no automatic fallback:
an agent that speaks only the other version stays silent, and silence cannot be told apart from a
host that is down. Under v1 a GET fails as a whole when the agent lacks one of the values, so the
read asks again without it and reports it as `None`. The `community` defaults to `public` and never
appears in an error. `timeout` (3.0 s by default) is one deadline per host for resolving and the
whole exchange. `aread_snmp_system` is the same on the event loop.

## Waking a host, and the path to it

```python
ipscout.wake_on_lan("00:00:5e:00:53:01", broadcast="192.0.2.255")
ipscout.path_mtu("8.8.8.8")  # 1500, or None where the platform cannot say
```

`wake_on_lan` returns nothing because nothing acknowledges a magic packet: a successful send means
only that it left this host. Poll `is_reachable` to find out whether the target woke.

`broadcast` (default `ipscout.wol.DEFAULT_BROADCAST`, the limited broadcast `255.255.255.255`) must be an IPv4
address other than `0.0.0.0`. An empty string or `0.0.0.0` would send the packet to this host and
report it sent, and a name says nothing about which segment is meant, so each raises `ValueError`
before anything is sent. A send that fails raises `IPScoutError`.

`path_mtu` returning `None` is an answer rather than a failure. An MTU sizes packets, so a guessed
one produces a silent black hole.

## The CLI

23 commands. `ipscout`, `python -m ipscout` and `uvx ipscout` are the same entry point.

| Command            | What it does                                                            |
|--------------------|-------------------------------------------------------------------------|
| `ping`             | Ping a host and report what came back.                                  |
| `ping-many`        | Ping many hosts concurrently.                                           |
| `reachable`        | Answer whether a host responds, by ICMP or failing that TCP.            |
| `traceroute`       | Report the path packets take to a host.                                 |
| `resolve`          | Resolve a hostname to its addresses.                                    |
| `reverse-dns`      | Resolve an address back to a hostname.                                  |
| `interfaces`       | List local network interfaces.                                          |
| `gateway`          | Show the default route, or the next hop toward one address.             |
| `neighbours`       | List the neighbour cache: which addresses this host has learned.        |
| `mac`              | Show the hardware address for an address, and whose it is.              |
| `find-ip`          | Find which addresses currently hold a hardware address.                 |
| `arp-scan`         | Sweep a network, then report every hardware address it learned.         |
| `set-neighbour`    | Write a permanent IPv4 neighbour entry. Needs privilege.                |
| `remove-neighbour` | Delete an IPv4 neighbour entry; exits 1 when there was none.            |
| `subnet`           | Show addressing, gateway and stored DHCP facts per subnet.              |
| `scan-ports`       | Report which ports are open, closed or filtered.                        |
| `banners`          | Read the first line each host sends on a TCP port.                      |
| `snmp-system`      | Read uptime, name, description and object id over SNMP.                 |
| `mtu`              | Show the largest packet that reaches a target unfragmented.             |
| `wake`             | Send a wake-on-LAN magic packet.                                        |
| `observe-dhcp`     | Watch a DHCP handshake for the addresses offered to a hardware address. |
| `capabilities`     | Report what this host can actually do.                                  |
| `info`             | Print resolved package metadata.                                        |

Global options, which live on the group so they compose with every subcommand:

| Option                       | Effect                                                                    |
|------------------------------|---------------------------------------------------------------------------|
| `--json`, `-j`               | Emit a JSON envelope: `{ok, command, data`\|`error, skipped}`.            |
| `--json-bare`                | Emit the JSON payload at top level, without the envelope.                 |
| `--traceback/--no-traceback` | Show a full Python traceback on unexpected errors. Default `--traceback`. |
| `--version`                  | Print the version and exit.                                               |
| `-h`, `--help`               | Show help and exit.                                                       |

`--json` and `--json-bare` are mutually exclusive.

Per-command options:

| Command            | Options                                                                                                                                    |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| `ping`             | `--times/-c` (4), `--timeout` (2.0), `--interval` (0.2), `-4`, `-6`, `--tcp-fallback`, `--tcp-port` (443)                                  |
| `ping-many`        | `--times/-c` (4), `--timeout` (2.0), `--concurrency` (64)                                                                                  |
| `reachable`        | `--timeout` (2.0), `--tcp-port` (443)                                                                                                      |
| `traceroute`       | `--max-hops` (30), `--timeout` (2.0), `-4`, `-6`, `--resolve-names`                                                                        |
| `resolve`          | `-4`, `-6`                                                                                                                                 |
| `reverse-dns`      | none beyond the global flags                                                                                                               |
| `interfaces`       | none beyond the global flags                                                                                                               |
| `banners`          | `--port` (required), `--timeout` (3.0), `--concurrency` (64), `--max-line-bytes` (512), `--farewell`, `-4`, `-6`                           |
| `snmp-system`      | `--version` (v1), `--community` (public, or `IPSCOUT_SNMP_COMMUNITY`), `--port` (161), `--timeout` (3.0), `--concurrency` (64), `-4`, `-6` |
| `observe-dhcp`     | `--interface` (the default route's), `--timeout` (60.0), `--settle` (12.0)                                                                 |
| `set-neighbour`    | `--interface` (the one whose subnet holds IP)                                                                                              |
| `remove-neighbour` | `--interface` (every interface the cache lists IP on)                                                                                      |
| `capabilities`     | none beyond the global flags                                                                                                               |
| `info`             | none beyond the global flags                                                                                                               |

`-4` and `-6` are mutually exclusive.

An option value the library would refuse - `--times 0`, `--timeout 0`, `--concurrency 0`, a port
outside 1-65535, `--max-hops` outside 1-255 - is a usage error: exit 2, naming the option and the
reason, before anything is sent. The bounds are the library's own, read from the same declarations
the library checks, so the two cannot disagree.

```bash
ipscout ping 127.0.0.1 -c 2
# [127.0.0.1] pinged 2 times, min: 0.04ms, avg: 0.04ms, max: 0.04ms, 0% Packet loss

ipscout ping-many 127.0.0.1 ::1 -c 1      # a table of target, reached, loss, avg ms, error
ipscout traceroute 1.1.1.1 --max-hops 10 --resolve-names
ipscout reachable example.com             # 'yes' or 'no'
ipscout resolve localhost -4
ipscout reverse-dns 127.0.0.1
ipscout interfaces
ipscout gateway                           # the default route, or --to an address
ipscout neighbours                        # the ARP/NDP cache
ipscout mac 8.8.8.8                       # with its scope: direct or next_hop
ipscout find-ip 00:00:5e:00:53:42 --scan  # which addresses hold a MAC
ipscout arp-scan --network 192.0.2.0/24   # sweep, then read what was learned
ipscout subnet                            # addressing, gateway, stored DHCP facts
ipscout scan-ports 192.0.2.10 --ports 22,80,443,8000-8100
ipscout banners 192.0.2.0/24 --port 21 --farewell 'QUIT\r\n'   # each host's greeting; networks expand
ipscout snmp-system 192.0.2.10 192.0.2.0/28 --timeout 2          # uptime, name, description, object id
IPSCOUT_SNMP_COMMUNITY=private ipscout --json snmp-system 192.0.2.10 --version v2c
ipscout mtu 8.8.8.8
ipscout wake 00:00:5e:00:53:01 --broadcast 192.0.2.255
ipscout observe-dhcp 02:00:5e:10:00:00 --interface br0   # needs root; last line is the bound address
ipscout capabilities
ipscout info
```

Pass an SNMP community through `IPSCOUT_SNMP_COMMUNITY` rather than `--community`: a command-line
argument is visible to every user in the process list. An empty `IPSCOUT_SNMP_COMMUNITY` counts as unset, so
`public` is sent; an empty `--community` is refused.

Exit codes are independent of the output format:

| Code | Meaning                                                                                             |
|------|-----------------------------------------------------------------------------------------------------|
| 0    | Reached, or the command otherwise succeeded.                                                        |
| 1    | Not reached. Nothing answered, or a reverse lookup found no PTR record.                             |
| 2    | Error. A bad name, a missing permission, a capability this host lacks, or a malformed command line. |

`ping-many` exits 1 only when no target at all was reached.

## JSON output

`--json` wraps the result so a reader parsing only stdout gets a boolean it can always see, rather
than an exit code it may not have captured:

```bash
ipscout --json reachable 127.0.0.1
```

```json
{
  "ok": true,
  "command": "reachable",
  "data": {
    "target": "127.0.0.1",
    "reachable": true
  },
  "error": null,
  "skipped": []
}
```

`skipped` names any network a sweeping command could not cover. It sits on the envelope because
`arp-scan` returns a bare list with nowhere inside it to say so, and a reader has to be able to tell
a complete answer from a partial one. The same note goes to stderr in every output mode, so a
`--json-bare` pipeline still sees it without anything extra landing on stdout.

`--json-bare` drops the envelope, which is what you want in a `jq` pipeline:

```bash
ipscout --json-bare resolve localhost
```

```json
{
  "target": "localhost",
  "addresses": [
    "127.0.0.1",
    "::1"
  ]
}
```

```bash
ipscout --json-bare interfaces | jq -r '.[] | select(.is_up) | .name'
ipscout --json ping 127.0.0.1 -c 1 | jq '.data.time_avg_ms'
```

Errors are serialised into the same envelope rather than printed as a traceback into a stream you
are parsing:

```bash
ipscout --json ping nothing.invalid   # exit code 2
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

`--json-bare` reports a failure as the error object alone, keeping its promise that stdout holds the
payload and nothing else:

```bash
ipscout --json-bare ping nothing.invalid   # exit code 2
```

```json
{
  "type": "IPScoutResolutionError",
  "message": "cannot resolve 'nothing.invalid': Name or service not known"
}
```

## Error handling

The contract in one sentence: setup problems raise, network conditions do not. A host that is down,
a packet that times out, a link losing everything all come back as a `ResponseObject` with
`reached=False`. Missing ICMP permission, an unresolvable name, or a nonsensical argument raise,
because no amount of retrying fixes them.

| Exception                     | Raised when                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | What to do about it                                     |
|-------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------|
| `IPScoutResolutionError`      | The target does not resolve, or has no address in the demanded family.                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Fix the name, or drop the `-4`/`-6` restriction.        |
| `IPScoutPermissionError`      | Neither an unprivileged nor a raw ICMP socket could be opened.                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Apply one of the fixes in the message. Root would help. |
| `IPScoutUnsupportedError`     | No backend implements this here, such as traceroute on unprivileged macOS.                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Use another capability. Root would not help.            |
| `IPScoutSweepTooWideError`    | Every network a sweep was given holds more addresses than it probes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Name a narrower network.                                |
| `IPScoutSweepIncompleteError` | A sweep skipped a network and matched nothing in the rest, so "not found" would overstate it.                                                                                                                                                                                                                                                                                                                                                                                                                                       | Name a narrower network inside the skipped one.         |
| `ValueError`                  | An argument is out of range or not what it names: `times`, `timeout`, `interval`, `payload_size`, `tcp_port`, `concurrency`, `max_hops`, a port, a scan `method` or a sweep `limit`, including a value of the wrong type (`True` for a count, `"1"` for a timeout); one string where a collection of hosts or networks belongs; an address argument that is not an IP literal of the asked-for family (`query_route`, `lookup_mac`, `resolve_active`). The message reads `<operation> refused its arguments: <argument>: <reason>`. | Fix the argument.                                       |

Every ipscout error derives from `IPScoutError`, so one `except` catches the family without also
catching unrelated `OSError` noise. The two sweep errors additionally derive from `ValueError`,
which is what those callables have always raised, so a caller written against that keeps working.

```python
import ipscout

try:
    result = ipscout.ping("some.host.example", 4)
except ipscout.IPScoutPermissionError as exc:
    print(f"cannot send ICMP from this process: {exc}")
except ipscout.IPScoutResolutionError as exc:
    print(f"bad target: {exc}")
except ipscout.IPScoutError as exc:
    print(f"ipscout could not run this probe: {exc}")
else:
    print("down" if not result.reached else f"up, {result.time_avg_ms:.2f}ms")
```

The distinction between the permission error and the unsupported error is load-bearing. Running as
root fixes a permission problem and does not fix an unsupported one.

```python
import ipscout

try:
    hops = ipscout.traceroute("example.com")
except ipscout.IPScoutUnsupportedError as exc:
    # macOS reaches this: neither MSG_ERRQUEUE nor a plain receive surfaces
    # ICMP Time Exceeded to an unprivileged process there.
    print(f"traceroute is not available on this platform: {exc}")
```

To find out before provoking an error, ask the host:

```python
import ipscout

ipscout.icmp_available()  # True when ICMP v4 could be used right now
ipscout.icmp_available(ipscout.AddressFamily.IPV6)  # availability genuinely differs per family
```

`ipscout capabilities` is the CLI form and additionally reports whether traceroute works here.

To report failures on the result instead of raising, for one call, pass `raise_on_error=False`:

```python
import ipscout

muted = ipscout.ping("nothing.invalid", raise_on_error=False)
print(muted.reached, muted.error)
# False cannot resolve 'nothing.invalid': Name or service not known
```

## Public surface

Everything below is exported from the package root, and every name in `ipscout.__all__` is listed
here or, for the exceptions, in the paragraph below the tables.

| Name                           | Kind      | Purpose                                                           |
|--------------------------------|-----------|-------------------------------------------------------------------|
| `agrab_banners`                | coroutine | The same banner grab, on the event loop.                          |
| `ais_reachable`                | coroutine | The same contract, on the event loop.                             |
| `aping`                        | coroutine | The same, without blocking the event loop.                        |
| `aping_many`                   | coroutine | Probe many targets concurrently.                                  |
| `aread_snmp_system`            | coroutine | The same SNMP read, on the event loop.                            |
| `arp_scan`                     | function  | Sweep a network, then report what the kernel learned.             |
| `ascan_ports`                  | coroutine | The same, on the event loop.                                      |
| `atrace_path`                  | coroutine | The same, over an async transport.                                |
| `atraceroute`                  | coroutine | The same, on the event loop.                                      |
| `default_gateway`              | function  | The route used when nothing more specific matches.                |
| `find_ip_by_mac`               | function  | Which addresses currently hold a hardware address.                |
| `get_mac_address`              | function  | The direct layer-2 address, or None for anything routed.          |
| `grab_banners`                 | function  | The first line each host sends on a TCP port, on one connection.  |
| `icmp_available`               | function  | Whether an ICMP probe could be made right now, per family.        |
| `is_reachable`                 | function  | Total yes-or-no shortcut. Never raises, always falls back to TCP. |
| `local_interfaces`             | function  | Every local network interface.                                    |
| `local_networks`               | function  | The IPv4 subnets a default sweep covers.                          |
| `lookup_mac`                   | function  | A hardware address answered with its scope attached.              |
| `neighbours`                   | function  | Every entry in this host's neighbour cache.                       |
| `normalise_mac`                | function  | One canonical form, so any written form compares equal.           |
| `parse_ports`                  | function  | Turn a 22,80,8000-8100 specification into port numbers.           |
| `path_mtu`                     | function  | The largest packet that reaches a target unfragmented.            |
| `ping`                         | function  | Probe one target and report what came back.                       |
| `ping_many`                    | function  | Probe many targets concurrently from synchronous code.            |
| `print_info`                   | function  | Print the package metadata block.                                 |
| `query_route`                  | function  | How this host would reach one destination.                        |
| `read_snmp_system`             | function  | Uptime, name, description and object id of many hosts, over SNMP. |
| `resolve`                      | function  | Turn a name or literal into a list of addresses.                  |
| `remove_neighbour`             | function  | Delete an IPv4 neighbour entry. Needs privilege.                  |
| `reverse_dns`                  | function  | Turn an address back into a name, or None.                        |
| `scan_ports`                   | function  | What state each of a set of ports is in.                          |
| `set_neighbour`                | function  | Write a permanent IPv4 neighbour entry. Needs privilege.          |
| `subnet_info`                  | function  | Addressing, gateway and stored DHCP facts per subnet.             |
| `sweep_scope`                  | function  | Which networks a sweep would cover, and which it would not.       |
| `trace_path`                   | function  | Walk the hop limit over a transport the caller owns.              |
| `traceroute`                   | function  | Report the path packets take to a target.                         |
| `observe_dhcp`                 | function  | Every address a DHCP server offers a machine, in order seen.      |
| `observe_dhcp_first_reachable` | function  | The first offered address that answers, or None.                  |
| `observe_dhcp_session`         | function  | The same, startable before the machine is started.                |
| `dhcp_capture_available`       | function  | Whether this host may capture at all.                             |
| `DhcpSession`                  | class     | The running capture: result(), offers(), stop().                  |
| `wake_on_lan`                  | function  | Send a wake-on-LAN magic packet.                                  |

Result models, all frozen Pydantic models with `extra="forbid"`:

| Name                 | Returned by                                      |
|----------------------|--------------------------------------------------|
| `Banner`             | grab_banners, agrab_banners                      |
| `CapabilityReport`   | the capabilities CLI command                     |
| `Interface`          | local_interfaces                                 |
| `InterfaceAddress`   | the ipv4 and ipv6 fields of Interface            |
| `LeaseInfo`          | the DHCP fields folded into SubnetInfo           |
| `MacLookup`          | lookup_mac                                       |
| `Neighbour`          | neighbours, arp_scan, set_neighbour              |
| `PackageInfo`        | the info CLI command                             |
| `ReachabilityReport` | the reachable CLI command                        |
| `ResolveReport`      | the resolve CLI command                          |
| `ResponseObject`     | ping, aping, ping_many, aping_many               |
| `ReverseDnsReport`   | the reverse-dns CLI command                      |
| `RouteInfo`          | query_route, default_gateway                     |
| `SnmpSystem`         | read_snmp_system, aread_snmp_system              |
| `SubnetInfo`         | subnet_info                                      |
| `SweepScope`         | sweep_scope                                      |
| `TraceHop`           | traceroute, atraceroute, trace_path, atrace_path |

Enums, all `str` subclasses so their members are already strings on the wire:

| Name             | Members                                                |
|------------------|--------------------------------------------------------|
| `AddressFamily`  | IPV4, IPV6                                             |
| `BannerState`    | GREETED, SILENT, REFUSED, UNREACHABLE                  |
| `CommandName`    | one member per CLI subcommand                          |
| `MacMethod`      | ACTIVE, CACHE                                          |
| `MacScope`       | DIRECT, NEXT_HOP, UNKNOWN                              |
| `NeighbourState` | REACHABLE, STALE, PERMANENT, INCOMPLETE, FAILED, OTHER |
| `PortState`      | OPEN, CLOSED, FILTERED                                 |
| `ProbeMethod`    | ICMP, TCP                                              |
| `ScanMethod`     | CONNECT, SYN                                           |
| `SnmpState`      | ANSWERED, SILENT, REFUSED, ERROR, UNREACHABLE          |
| `SnmpVersion`    | V1, V2C                                                |

Exceptions: `IPScoutError`, `IPScoutPermissionError`, `IPScoutResolutionError`,
`IPScoutUnsupportedError`, `IPScoutSweepError` and its two subclasses `IPScoutSweepTooWideError` and
`IPScoutSweepIncompleteError`. Every public callable reports failure through this hierarchy, so
`except IPScoutError` catches all of them.

For a module-by-module breakdown, see [systemdesign/module_reference.md](systemdesign/module_reference.md).
