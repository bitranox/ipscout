"""Restricting an address-returning call to one family.

Twelve probing functions already take ``family``; the three that RETURN addresses did not, so
a caller who wanted "the IPv4 this MAC holds" had to filter strings itself. That filtering is
where the trap is: one hardware address legitimately holds an IPv4 AND an IPv6 link-local, the
cache lists them in the order they were learned, and a caller taking the first entry gets a
link-local whenever one happened to be learned first. The order is not a promise, so the family
has to be askable.

The selection itself is checked on entries chosen here, through the pure functions the public
calls use (``scan.addresses_held_by``, ``scan.entries_in_scope``), so nothing of the package is patched. That
each public call passes ``family`` through is checked against the host's REAL cache: asking for
the family a hardware address does not hold is what fails when the argument is dropped, so the
check discriminates whatever the cache happens to contain.
"""

from __future__ import annotations

import inspect
import ipaddress
import json

import pytest
from click.testing import CliRunner

import ipscout
from ipscout import scan
from ipscout.cli import cli
from ipscout.models import AddressFamily, Neighbour, SweepScope
from ipscout.neighbours import of_family

BOTH_FAMILIES = (
    Neighbour(ip="192.0.2.10", mac="aa:bb:cc:dd:ee:ff", interface="eth0"),
    Neighbour(ip="fe80::1", mac="aa:bb:cc:dd:ee:ff", interface="eth0", family=AddressFamily.IPV6),
    Neighbour(ip="192.0.2.11", mac="11:22:33:44:55:66", interface="eth0"),
)

FAMILY_VERSIONS = ((AddressFamily.IPV4, 4), (AddressFamily.IPV6, 6))


def _version(address: str) -> int:
    """The IP version of an address as these calls return it, a zone suffix included."""

    return ipaddress.ip_address(address.split("%", 1)[0]).version


def _a_cached_entry(*, version: int | None = None) -> Neighbour:
    """Return an entry from the real neighbour cache, or skip when it holds none to use."""

    for entry in ipscout.neighbours():
        if entry.mac and (version is None or entry.address.version == version):
            return entry
    pytest.skip("this host's neighbour cache holds no entry to ask about")


@pytest.mark.os_agnostic
def test_asking_for_one_family_returns_only_that_family() -> None:
    # The whole point: a caller who is going to ssh to the answer must be able to say so,
    # rather than pick the first entry and hope the cache learned the IPv4 first.
    assert scan.addresses_held_by(BOTH_FAMILIES, "aa:bb:cc:dd:ee:ff", AddressFamily.IPV4) == ["192.0.2.10"]
    assert scan.addresses_held_by(BOTH_FAMILIES, "aa:bb:cc:dd:ee:ff", AddressFamily.IPV6) == ["fe80::1%eth0"]


@pytest.mark.os_agnostic
def test_asking_for_no_family_is_unchanged() -> None:
    # Additive: the default must keep returning both, in the order first seen.
    assert scan.addresses_held_by(BOTH_FAMILIES, "aa:bb:cc:dd:ee:ff", None) == ["192.0.2.10", "fe80::1%eth0"]


@pytest.mark.os_agnostic
def test_a_family_that_hardware_does_not_hold_is_empty_not_an_error() -> None:
    # DELIBERATELY UNLIKE resolve(), which raises when a NAME has no address in the family.
    # There, empty would be indistinguishable from "host down". Here an empty list already
    # has a settled meaning - "not known here" - and "that MAC holds no IPv6" is an ordinary
    # finding, not a failure. Raising would also break every caller that treats [] as normal.
    assert scan.addresses_held_by(BOTH_FAMILIES, "11:22:33:44:55:66", AddressFamily.IPV6) == []


@pytest.mark.os_agnostic
def test_find_ip_by_mac_passes_the_family_through() -> None:
    # Against the real cache. Whatever families this hardware address holds, it lacks at least
    # one of the two or holds both; either way one of these asks returns the other family's
    # address if `family` is not handed on, so the check cannot pass on a dropped argument.
    mac = str(_a_cached_entry().mac)

    for family, version in FAMILY_VERSIONS:
        assert all(_version(address) == version for address in ipscout.find_ip_by_mac(mac, family=family)), family


@pytest.mark.os_agnostic
def test_the_neighbour_cache_can_be_asked_for_one_family() -> None:
    # Against the REAL cache: `neighbours` picks its backend by an import inside the function,
    # so substituting one would pin a platform rather than the behaviour. The invariant holds
    # whatever this host happens to know - every entry returned is in the family asked for, and
    # asking for neither still returns everything.
    everything = ipscout.neighbours()
    if not everything:
        pytest.skip("this host's neighbour cache is empty")

    for family, version in FAMILY_VERSIONS:
        selected = ipscout.neighbours(family=family)
        assert all(ipaddress.ip_address(entry.ip).version == version for entry in selected)
        assert len(selected) == sum(1 for e in everything if ipaddress.ip_address(e.ip).version == version)

    v4 = ipscout.neighbours(family=AddressFamily.IPV4)
    v6 = ipscout.neighbours(family=AddressFamily.IPV6)
    assert len(v4) + len(v6) == len(everything)


@pytest.mark.os_agnostic
def test_a_sweep_answers_only_for_its_networks_in_the_family_asked() -> None:
    # A scope may hold networks of both families, and the cache the sweep then reads holds
    # both, so the same filter has to be available on the way out. 192.0.2.11 is in the
    # entries but outside the scope, so it must not come back either.
    scope = SweepScope(limit=16, networks=(ipaddress.IPv4Network("192.0.2.10/32"), ipaddress.IPv6Network("fe80::/126")))
    covered = scan.entries_in_scope(BOTH_FAMILIES, scope)

    assert [entry.ip for entry in covered] == ["192.0.2.10", "fe80::1"]
    assert [entry.ip for entry in of_family(covered, AddressFamily.IPV4)] == ["192.0.2.10"]
    assert [entry.ip for entry in of_family(covered, AddressFamily.IPV6)] == ["fe80::1"]


@pytest.mark.os_agnostic
def test_arp_scan_passes_the_family_through() -> None:
    # A real sweep of one IPv4 neighbour this host already knows: a single echo to an address
    # on the local link. The scope holds only that address, so asking for IPv6 must come back
    # empty; with `family` dropped, the neighbour itself would come back.
    entry = _a_cached_entry(version=4)
    scope = SweepScope(limit=16, networks=(ipaddress.IPv4Network(f"{entry.ip}/32"),))

    assert ipscout.arp_scan(scope=scope, family=AddressFamily.IPV6, timeout=0.05) == ()


@pytest.mark.os_agnostic
def test_the_family_argument_is_keyword_only_everywhere() -> None:
    # Positional would be a second way to say the same thing, and on find_ip_by_mac it would
    # sit next to `scan`, where a stray True/family swap is silent.
    for fn in (ipscout.find_ip_by_mac, ipscout.arp_scan, ipscout.neighbours):
        parameter = inspect.signature(fn).parameters["family"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY, fn.__name__
        assert parameter.default is None, fn.__name__


@pytest.mark.os_agnostic
def test_the_cli_selects_a_family_and_refuses_both() -> None:
    # The CLI spelling matches `resolve`, which already had -4/-6, so there is one way to say
    # this across the tool rather than a second vocabulary for the MAC-based commands. The
    # family check runs against the real cache, as for the library call above.
    mac = str(_a_cached_entry().mac)
    runner = CliRunner()

    for flag, version in (("-4", 4), ("-6", 6)):
        # --json-bare is a GROUP option, so it precedes the subcommand.
        result = runner.invoke(cli, ["--json-bare", "find-ip", mac, flag])
        assert result.exit_code in {0, 1}, result.output
        assert all(_version(address) == version for address in json.loads(result.output)["addresses"]), flag

    both = runner.invoke(cli, ["find-ip", mac, "-4", "-6"])
    assert both.exit_code != 0
    assert "mutually exclusive" in both.output
