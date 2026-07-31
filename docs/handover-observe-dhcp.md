# Handover: resolve a MAC by OBSERVING the DHCP handshake

Status: proposed, not implemented. Written 2026-07-31 from a real caller that has to hand-roll
this today.

## The gap

Every resolution method ipscout has needs the target to be **already up and answering**:

| Method                           | Needs                                                                    |
|----------------------------------|--------------------------------------------------------------------------|
| `find_ip_by_mac(mac)`            | a neighbour-cache entry, which only exists after real IPv4 traffic       |
| `find_ip_by_mac(mac, scan=True)` | the host to answer ARP, so it must already hold an address               |
| `LeaseInfo`                      | describes THIS host's own lease, not an address handed to some other MAC |

There is a window where none of those can work. A VM that has just been started has no address
yet, is not answering ARP, and has no neighbour entry. It DHCPs about **one second** after the
start command. The only way to learn its address in that window is to watch the exchange as it
happens.

That is not a niche case. It is the normal path for anything that boots a machine and then has
to reach it: a test harness, a provisioning tool, a CI runner spawning VMs.

## What the caller does today

A VM test harness runs its own capture and parses the text:

```
setsid timeout <secs> tcpdump -i <interface> -n -e -vv -l 'udp and (port 67 or port 68)' > <cap> &
```

then parses `Your-IP` / `Client-Ethernet-Address` pairs out of the output. It is the only
packet-capture code left in that package, and the parse had five separate boot/DHCP resolution
defects in a single session before it was pinned down.

## Proposed surface

Match the existing style (`find_ip_by_mac` in `scan.py`, keyword-only options, a list return):

```python
def observe_dhcp(
    mac: str,
    *,
    interface: str | None = None,
    timeout: float = 60.0,
) -> list[str]:
    """Return every address offered to a hardware address, in the order seen."""
```

and a matching CLI verb, consistent with the others:

```
ipscout observe-dhcp <mac> --interface br0 --timeout 60 --json
```

### Two contract details that must be built in

These are the parts that cost the caller real debugging. Please do not simplify them away.

**1. Return EVERY distinct offer, in order. Not the first.**

A churned or poisoned DHCP pool offers addresses the guest DAD-declines before it binds a
working one, and both land in the same exchange. Returning the first offer is exactly how a
perfectly reachable machine gets reported as never having booted. The caller must be able to
try each candidate and keep the one that answers.

The caller then does its own reachability check on each candidate; ipscout already has
`reachable` / port probing, so a convenience wrapper that returns the first REACHABLE offer
would be welcome as a second function, but the raw list must stay available.

**2. It has to be startable BEFORE the triggering event.**

A one-shot `observe_dhcp(...)` that begins capturing when called is too late: by the time the
caller has issued its start command and called in, the handshake is over. The usable shape is a
context manager or a start/collect pair:

```python
with ipscout.observe_dhcp_session(mac, interface="br0", timeout=150) as session:
    start_the_machine()          # the handshake happens ~1s into this
    addresses = session.result() # blocks until seen, or the timeout
```

The one-shot form is still worth having for the case where the machine is already booting.

## Implementation notes

- There is precedent in the repo for raw packet work: `packet.py`, `wol.py`, `transport_posix.py`.
  Whether this is a raw `AF_PACKET` socket or a `tcpdump` subprocess is an implementation
  choice; a native socket avoids a tcpdump dependency, but note that tcpdump buffering was a
  real trap for the caller (it needed `-l`, line-buffered, or the capture file stayed empty).
- Needs root or `CAP_NET_RAW`. `IPScoutPermissionError` already exists and is the right failure.
- The parse itself is small. The rules that matter, learned the hard way in the caller's own
  parser:
  - a new packet starts at an `HH:MM:SS.` timestamp, and the `your-ip` seen so far belongs to
    the PREVIOUS packet, so it must be reset at that boundary or it leaks across packets;
  - `Your-IP` (yiaddr) precedes `Client-Ethernet-Address` within one packet, so the pairing is
    "remember the last your-ip, emit it when the matching client address appears";
  - `0.0.0.0` is the client's REQUEST, not an offer, and must be skipped;
  - de-duplicate, but preserve first-seen order.

### Fixture for the tests

A capture excerpt with two offers for one MAC (the first declined, the second bound). The
correct answer is `["198.51.100.36", "198.51.100.51"]`, in that order.

```
03:35:58.268486 IP 198.51.100.1.67 > 198.51.100.36.68: BOOTP/DHCP, Reply, length 322
	  Your-IP 198.51.100.36
	  Client-Ethernet-Address 02:00:5e:10:00:00
03:36:04.113921 IP 198.51.100.1.67 > 198.51.100.51.68: BOOTP/DHCP, Reply, length 322
	  Your-IP 198.51.100.51
	  Client-Ethernet-Address 02:00:5e:10:00:00
```

Worth covering as well: a request packet (`Your-IP 0.0.0.0`) is ignored; a reply for a
DIFFERENT MAC is ignored; a retransmitted identical offer appears once; a truncated capture
does not raise.

## Acceptance

- `observe_dhcp` and the session form both return every distinct offer in order.
- A machine that never DHCPs inside the timeout returns an empty list rather than raising, so
  "did not appear" is distinguishable from "could not observe" (which should raise, matching
  how `IPScoutSweepIncompleteError` already separates those two for the sweep).
- Documented in the shipped skill, since anything absent from it does not get used.

## Who wants it

A VM regression harness that boots a machine and must reach it moments later. With this in
place it drops its tcpdump invocation and its parser, and is left with no packet-capture code
at all. It is the only caller known so far, but the shape is general: anything that starts a
machine and then has to find it hits the same window.
