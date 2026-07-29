"""Integration lane: does this actually work against the real internet.

Everything else in the suite probes loopback, the local segment, or synthetic
buffers, which is what makes it fast and hermetic. None of it answers the
question a user asks first - does it reach a host across the internet and come
back with the truth.

Every test here skips cleanly when there is no route out, so a machine offline
or behind a firewall reports skipped rather than failed. That is the same rule
the ICMP tests follow for a host without the ping socket: a missing capability
is not a defect.
"""

from __future__ import annotations

import socket

import pytest

import ipscout
from ipscout.models import AddressFamily, MacScope, PortState

pytestmark = pytest.mark.integration

#: Public anycast resolvers, chosen because they answer ICMP, are reachable
#: from almost anywhere, and are not somebody's private host.
PUBLIC_V4 = "1.1.1.1"
PUBLIC_ALT = "8.8.8.8"

#: A routable address that RFC 5737 reserves for documentation, so nothing
#: answers and nobody is bothered by the probe.
NEVER_ANSWERS = "203.0.113.1"


def _require_internet() -> None:
    """Skip unless this host can open a TCP connection to the public internet."""

    try:
        with socket.create_connection((PUBLIC_V4, 443), timeout=3.0):
            return
    except OSError:
        pytest.skip("no route to the public internet from this host")


def _require_icmp() -> None:
    """Skip unless unprivileged ICMP is available here."""

    if not ipscout.icmp_available():
        pytest.skip("unprivileged ICMP unavailable on this host")


@pytest.mark.integration
def test_a_public_host_answers_with_plausible_timings() -> None:
    _require_internet()
    _require_icmp()

    result = ipscout.ping(PUBLIC_V4, 3, timeout=3.0)

    assert result.reached, result
    assert result.packets_received > 0
    # A real round trip over the internet: not instant, not eternal.
    assert 0.0 < result.time_avg_ms < 5000.0, result.str_result
    assert result.time_min_ms <= result.time_avg_ms <= result.time_max_ms
    assert result.method is ipscout.ProbeMethod.ICMP


@pytest.mark.integration
def test_a_documentation_address_stays_silent_without_raising() -> None:
    # The contract that matters most in production: a host that does not answer
    # is data, not an exception.
    _require_internet()
    _require_icmp()

    result = ipscout.ping(NEVER_ANSWERS, 1, timeout=2.0)

    assert result.reached is False
    assert result.packets_lost_percentage == 100
    assert result.error is None


@pytest.mark.integration
def test_a_sweep_of_public_hosts_pairs_each_result_with_its_target() -> None:
    _require_internet()
    _require_icmp()

    results = ipscout.ping_many([PUBLIC_V4, PUBLIC_ALT, NEVER_ANSWERS], times=1, timeout=3.0)

    assert set(results) == {PUBLIC_V4, PUBLIC_ALT, NEVER_ANSWERS}
    for target, result in results.items():
        assert result.target == target, "a sweep must not attribute a result to the wrong host"
    assert results[NEVER_ANSWERS].reached is False


@pytest.mark.integration
def test_a_real_name_resolves_and_reverses() -> None:
    _require_internet()

    addresses = ipscout.resolve("one.one.one.one", family=AddressFamily.IPV4)

    assert PUBLIC_V4 in addresses
    # A PTR may or may not exist; if it does it must be a name, not an address.
    name = ipscout.reverse_dns(PUBLIC_V4)
    assert name is None or "." in name


@pytest.mark.integration
def test_a_public_address_is_reached_through_the_gateway() -> None:
    # The routed-MAC rule, against a real route rather than a fixture: the
    # answer for a public address is the next hop, never the host itself.
    _require_internet()

    answer = ipscout.lookup_mac(PUBLIC_V4)

    assert answer.scope is MacScope.NEXT_HOP
    assert answer.via_ip not in (None, PUBLIC_V4)
    assert ipscout.get_mac_address(PUBLIC_V4) is None


@pytest.mark.integration
def test_a_public_web_port_is_open_and_an_unused_one_is_not() -> None:
    _require_internet()

    states = ipscout.scan_ports(PUBLIC_V4, [443, 47001], timeout=3.0)

    assert states[443] is PortState.OPEN
    assert states[47001] is not PortState.OPEN


@pytest.mark.integration
def test_the_path_to_a_public_host_reports_a_plausible_mtu() -> None:
    _require_internet()

    value = ipscout.path_mtu(PUBLIC_V4)

    if value is None:
        pytest.skip("this platform does not report a path MTU")
    # Smaller than the minimum any host must carry would be nonsense; larger
    # than a jumbo frame means something was misread.
    assert 576 <= value <= 9000, value


@pytest.mark.integration
def test_reachability_falls_back_to_tcp_for_a_host_that_ignores_icmp() -> None:
    # is_reachable is total by design, and this is the case it exists for.
    _require_internet()

    assert ipscout.is_reachable(PUBLIC_V4, timeout=3.0) is True
    assert ipscout.is_reachable("nothing.invalid", timeout=2.0) is False


@pytest.mark.integration
def test_the_path_to_a_public_host_has_hops() -> None:
    _require_internet()
    _require_icmp()

    try:
        hops = ipscout.traceroute(PUBLIC_V4, max_hops=8, timeout=2.0)
    except ipscout.IPScoutUnsupportedError:
        pytest.skip("this platform cannot observe expired hops unprivileged")

    assert hops, "a traceroute over the internet should report at least one hop"
    assert all(hop.ttl > 0 for hop in hops)
    # Something along the way must have identified itself, or the run says
    # nothing at all about the path.
    assert any(hop.address for hop in hops), [h.model_dump() for h in hops]
