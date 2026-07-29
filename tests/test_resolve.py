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
