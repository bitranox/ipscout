"""Resolution stories, including the two failures that must stay distinguishable."""

from __future__ import annotations

import pytest

from ipscout.errors import IPScoutResolutionError
from ipscout.models import AddressFamily
from ipscout.resolve import family_of, resolve, resolve_one, reverse_dns

#: A name reserved by RFC 6761 to never resolve, so this needs no network.
NEVER_RESOLVES = "nothing.invalid"


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("literal", "expected"),
    [
        ("192.168.1.1", AddressFamily.IPV4),
        ("0.0.0.0", AddressFamily.IPV4),  # noqa: S104 - classifying a literal, not binding
        ("::1", AddressFamily.IPV6),
        ("fe80::1", AddressFamily.IPV6),
    ],
)
def test_a_literal_address_is_classified_without_asking_the_network(literal: str, expected: AddressFamily) -> None:
    assert family_of(literal) is expected


@pytest.mark.os_agnostic
@pytest.mark.parametrize("not_a_literal", ["example.test", "", "999.999.999.999", "not an address"])
def test_a_hostname_is_not_mistaken_for_a_literal(not_a_literal: str) -> None:
    assert family_of(not_a_literal) is None


@pytest.mark.os_agnostic
def test_loopback_resolves_to_itself_in_both_families() -> None:
    assert resolve("127.0.0.1") == ["127.0.0.1"]
    assert resolve("::1") == ["::1"]


@pytest.mark.os_agnostic
def test_resolution_reports_the_family_alongside_the_address() -> None:
    assert resolve_one("127.0.0.1") == ("127.0.0.1", AddressFamily.IPV4)
    assert resolve_one("::1") == ("::1", AddressFamily.IPV6)


@pytest.mark.os_agnostic
def test_a_zone_survives_resolution() -> None:
    # A link-local address names a different machine on each interface, so the
    # zone is part of the address, not decoration. Dropping it here is what
    # left every link-local probe unable to say which link it meant.
    assert resolve("fe80::1%1") == ["fe80::1%1"]
    assert resolve_one("fe80::1%1") == ("fe80::1%1", AddressFamily.IPV6)


@pytest.mark.os_agnostic
def test_a_zone_the_resolver_will_not_parse_still_survives() -> None:
    # Measured on Windows: getaddrinfo there refuses an interface NAME as a
    # zone and accepts only an index, so the two platforms would disagree
    # about which addresses exist. Resolution keeps the zone as written and
    # leaves checking the interface to the send, which is what needs it.
    assert resolve("fe80::1%Ethernet 4") == ["fe80::1%Ethernet 4"]


@pytest.mark.os_agnostic
def test_a_zone_on_an_ipv4_address_says_that_is_what_is_wrong() -> None:
    # A zone belongs to an IPv6 link-local address and to nothing else, so this
    # is a misunderstanding worth naming. It used to arrive as "resolver
    # returned an unparseable address", which describes the resolver's
    # behaviour rather than the caller's mistake.
    with pytest.raises(IPScoutResolutionError, match="IPv4 address"):
        resolve("127.0.0.1%eth0")


@pytest.mark.os_agnostic
def test_an_address_ending_in_a_bare_separator_says_the_interface_is_missing() -> None:
    with pytest.raises(IPScoutResolutionError, match="names no interface"):
        resolve("fe80::1%")


@pytest.mark.os_agnostic
@pytest.mark.parametrize("zone", ["../etc", "a/b"])
def test_a_zone_that_cannot_name_an_interface_is_refused_as_such(zone: str) -> None:
    with pytest.raises(IPScoutResolutionError, match="not a usable interface"):
        resolve(f"fe80::1%{zone}")


@pytest.mark.os_agnostic
def test_an_address_carrying_two_zones_is_refused_as_the_malformed_thing_it_is() -> None:
    # What adding a zone to an address that already has one produces. It has
    # to be named, because the reflex on seeing an unreachable link-local is
    # to append an interface, and doing that to an answer from
    # find_ip_by_mac - which already carries one - lands here.
    with pytest.raises(IPScoutResolutionError, match="one interface"):
        resolve("fe80::1%eth0%2")


@pytest.mark.os_agnostic
def test_a_link_local_address_without_a_zone_is_refused_by_name() -> None:
    # It cannot be sent anywhere: with no interface there is no link to send
    # on. Probing it anyway returns reached=False, which reads as "the host is
    # down" and hides a question that was never asked.
    with pytest.raises(IPScoutResolutionError, match="interface"):
        resolve_one("fe80::1")


@pytest.mark.os_agnostic
def test_an_ordinary_address_needs_no_zone() -> None:
    # Only a link-local address is ambiguous without one; the refusal must not
    # spread to the addresses that are complete on their own.
    assert resolve_one("::1") == ("::1", AddressFamily.IPV6)
    assert resolve_one("169.254.1.1") == ("169.254.1.1", AddressFamily.IPV4)


@pytest.mark.os_agnostic
def test_an_unknown_name_raises_rather_than_reading_as_a_down_host() -> None:
    # Reporting reached=False here would make a typo in a hostname
    # indistinguishable from an outage.
    with pytest.raises(IPScoutResolutionError, match="cannot resolve"):
        resolve(NEVER_RESOLVES)


@pytest.mark.os_agnostic
def test_asking_for_a_family_the_target_lacks_says_exactly_that() -> None:
    # Distinct from "no such name": the fix is to drop the -4/-6 flag, not to
    # correct the hostname, so the messages must differ.
    with pytest.raises(IPScoutResolutionError, match="has no ipv6 address"):
        resolve("127.0.0.1", family=AddressFamily.IPV6)

    with pytest.raises(IPScoutResolutionError, match="has no ipv4 address"):
        resolve("::1", family=AddressFamily.IPV4)


@pytest.mark.os_agnostic
def test_results_carry_no_duplicates() -> None:
    addresses = resolve("localhost")

    assert len(addresses) == len(set(addresses))


@pytest.mark.os_agnostic
def test_a_missing_ptr_record_is_an_answer_not_an_error() -> None:
    # Most addresses have no reverse record; that is normal, not exceptional.
    assert reverse_dns("this is not an address") is None
    assert reverse_dns("203.0.113.200") is None


@pytest.mark.os_agnostic
def test_loopback_has_a_reverse_name() -> None:
    assert reverse_dns("127.0.0.1") is not None


@pytest.mark.os_agnostic
@pytest.mark.parametrize("blank", ["", "   ", "\t", "\n"])
def test_a_blank_target_is_refused_on_every_platform(blank: str) -> None:
    # Found by CI on Windows, where getaddrinfo("") happily resolves to the
    # local host, so is_reachable("") answered True. Resolvers disagree here,
    # so the rejection has to be ours rather than theirs.
    with pytest.raises(IPScoutResolutionError, match="must not be empty"):
        resolve(blank)


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("literal", "wrong_family"),
    [("127.0.0.1", AddressFamily.IPV6), ("::1", AddressFamily.IPV4), ("192.168.1.1", AddressFamily.IPV6)],
)
def test_a_literal_is_never_coerced_into_the_other_family(literal: str, wrong_family: AddressFamily) -> None:
    # Found by CI on macOS, where getaddrinfo returns a v4-mapped ::ffff: form
    # instead of failing as it does on Linux. Neither is a usable address of
    # the requested family, so the answer must be the same on both.
    with pytest.raises(IPScoutResolutionError, match="has no"):
        resolve(literal, family=wrong_family)
