"""Restricting an address-returning call to one family.

Twelve probing functions already take ``family``; the three that RETURN addresses did not, so
a caller who wanted "the IPv4 this MAC holds" had to filter strings itself. That filtering is
where the trap is: one hardware address legitimately holds an IPv4 AND an IPv6 link-local, the
cache lists them in the order they were learned, and a caller taking the first entry gets a
link-local whenever one happened to be learned first. The order is not a promise, so the family
has to be askable.
"""

from __future__ import annotations

import ipaddress

import pytest

import ipscout
from ipscout.models import AddressFamily, Neighbour

BOTH_FAMILIES = (
    Neighbour(ip="192.0.2.10", mac="aa:bb:cc:dd:ee:ff", interface="eth0"),
    Neighbour(ip="fe80::1", mac="aa:bb:cc:dd:ee:ff", interface="eth0"),
    Neighbour(ip="192.0.2.11", mac="11:22:33:44:55:66", interface="eth0"),
)


@pytest.fixture
def cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Serve a fixed neighbour cache, so the assertions are about filtering only."""

    def fixed_cache() -> tuple[Neighbour, ...]:
        return BOTH_FAMILIES

    monkeypatch.setattr(ipscout.scan, "neighbours", fixed_cache)


@pytest.mark.os_agnostic
@pytest.mark.usefixtures("cache")
def test_asking_for_one_family_returns_only_that_family() -> None:
    # The whole point: a caller who is going to ssh to the answer must be able to say so,
    # rather than pick the first entry and hope the cache learned the IPv4 first.
    assert ipscout.find_ip_by_mac("aa:bb:cc:dd:ee:ff", family=AddressFamily.IPV4) == ["192.0.2.10"]
    assert ipscout.find_ip_by_mac("aa:bb:cc:dd:ee:ff", family=AddressFamily.IPV6) == ["fe80::1%eth0"]


@pytest.mark.os_agnostic
@pytest.mark.usefixtures("cache")
def test_asking_for_no_family_is_unchanged() -> None:
    # Additive: the default must keep returning both, in the order first seen.
    assert ipscout.find_ip_by_mac("aa:bb:cc:dd:ee:ff") == ["192.0.2.10", "fe80::1%eth0"]


@pytest.mark.os_agnostic
@pytest.mark.usefixtures("cache")
def test_a_family_that_hardware_does_not_hold_is_empty_not_an_error() -> None:
    # DELIBERATELY UNLIKE resolve(), which raises when a NAME has no address in the family.
    # There, empty would be indistinguishable from "host down". Here an empty list already
    # has a settled meaning - "not known here" - and "that MAC holds no IPv6" is an ordinary
    # finding, not a failure. Raising would also break every caller that treats [] as normal.
    assert ipscout.find_ip_by_mac("11:22:33:44:55:66", family=AddressFamily.IPV6) == []


@pytest.mark.os_agnostic
def test_the_neighbour_cache_can_be_asked_for_one_family() -> None:
    # Against the REAL cache: `neighbours` picks its backend by an import inside the function,
    # so substituting one would pin a platform rather than the behaviour. The invariant holds
    # whatever this host happens to know - every entry returned is in the family asked for, and
    # asking for neither still returns everything.
    everything = ipscout.neighbours()
    if not everything:
        pytest.skip("this host's neighbour cache is empty")

    for family, version in ((AddressFamily.IPV4, 4), (AddressFamily.IPV6, 6)):
        selected = ipscout.neighbours(family=family)
        assert all(ipaddress.ip_address(entry.ip).version == version for entry in selected)
        assert len(selected) == sum(1 for e in everything if ipaddress.ip_address(e.ip).version == version)

    v4 = ipscout.neighbours(family=AddressFamily.IPV4)
    v6 = ipscout.neighbours(family=AddressFamily.IPV6)
    assert len(v4) + len(v6) == len(everything)


@pytest.mark.os_agnostic
def test_a_sweep_can_be_asked_for_one_family(monkeypatch: pytest.MonkeyPatch) -> None:
    # arp_scan sweeps IPv4 either way - there is no IPv6 sweep - but the cache it then reads
    # holds both, so the same filter has to be available on the way out.
    def fixed_sweep(scope: object, *, concurrency: int = 0, timeout: float = 0.0) -> tuple[Neighbour, ...]:
        return BOTH_FAMILIES

    monkeypatch.setattr(ipscout.scan, "_sweep", fixed_sweep)

    v4 = ipscout.arp_scan(network="192.0.2.0/24", family=AddressFamily.IPV4)

    assert [entry.ip for entry in v4] == ["192.0.2.10", "192.0.2.11"]


@pytest.mark.os_agnostic
def test_the_family_argument_is_keyword_only_everywhere() -> None:
    # Positional would be a second way to say the same thing, and on find_ip_by_mac it would
    # sit next to `scan`, where a stray True/family swap is silent.
    import inspect

    for fn in (ipscout.find_ip_by_mac, ipscout.arp_scan, ipscout.neighbours):
        parameter = inspect.signature(fn).parameters["family"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY, fn.__name__
        assert parameter.default is None, fn.__name__


@pytest.mark.os_agnostic
@pytest.mark.usefixtures("cache")
def test_the_cli_selects_a_family_and_refuses_both() -> None:
    # The CLI spelling matches `resolve`, which already had -4/-6, so there is one way to say
    # this across the tool rather than a second vocabulary for the MAC-based commands.
    from click.testing import CliRunner

    from ipscout.cli import cli

    runner = CliRunner()

    # --json-bare is a GROUP option, so it precedes the subcommand.
    v4 = runner.invoke(cli, ["--json-bare", "find-ip", "aa:bb:cc:dd:ee:ff", "-4"])
    assert v4.exit_code == 0, v4.output
    assert "192.0.2.10" in v4.output
    assert "fe80" not in v4.output

    both = runner.invoke(cli, ["find-ip", "aa:bb:cc:dd:ee:ff", "-4", "-6"])
    assert both.exit_code != 0
    assert "mutually exclusive" in both.output
