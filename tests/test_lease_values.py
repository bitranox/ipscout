"""What a lease store says reaches a record only as an address literal.

A lease file is written by another program, and a damaged or hand-edited one
can hold anything where an address belongs. The record's address fields are
bounded, so the parsers keep only the literals and drop the rest rather than
failing the whole lease over one bad value.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ipscout.arp import normalise_mac
from ipscout.leases_linux import parse_dhclient_lease, parse_networkd_lease
from ipscout.models import AddressFamily, LeaseInfo, Neighbour, SubnetInfo

pytestmark = pytest.mark.os_agnostic

_NOT_ADDRESSES = ["dhcp.example", "192.0.2.300", "garbage", "fe80::1%eth0%x"]


@pytest.mark.parametrize("value", _NOT_ADDRESSES)
def test_a_networkd_lease_drops_a_server_or_router_that_is_not_an_address(value: str) -> None:
    lease = parse_networkd_lease(f"SERVER_ADDRESS={value}\nROUTER={value}\nDNS={value} 192.0.2.53\n")

    assert (lease.dhcp_server, lease.router, lease.dns_servers) == (None, None, ("192.0.2.53",))


@pytest.mark.parametrize("value", _NOT_ADDRESSES)
def test_a_dhclient_lease_drops_a_server_or_router_that_is_not_an_address(value: str) -> None:
    lease = parse_dhclient_lease(
        f"""
        lease {{
          option dhcp-server-identifier {value};
          option routers {value},192.0.2.1;
          option domain-name-servers {value},192.0.2.53;
        }}
        """
    )

    # The router list's first literal is the router, so the bad entry before
    # it no longer hides it.
    assert (lease.dhcp_server, lease.router, lease.dns_servers) == (None, "192.0.2.1", ("192.0.2.53",))


def test_the_first_router_that_is_an_address_is_the_router() -> None:
    lease = parse_dhclient_lease("lease { option routers 192.0.2.1,198.51.100.1; }")

    assert lease.router == "192.0.2.1"


def test_literals_of_both_families_are_kept() -> None:
    lease = parse_networkd_lease("SERVER_ADDRESS=192.0.2.1\nROUTER=192.0.2.1\nDNS=192.0.2.53 2001:db8::53\n")

    assert (lease.dhcp_server, lease.router, lease.dns_servers) == ("192.0.2.1", "192.0.2.1", ("192.0.2.53", "2001:db8::53"))


@pytest.mark.parametrize("field", ["dhcp_server", "router"])
def test_a_lease_record_refuses_a_server_that_is_not_an_address(field: str) -> None:
    with pytest.raises(ValidationError, match="is not an IP address literal"):
        LeaseInfo.model_validate({field: "dhcp.example"})


def test_a_lease_record_refuses_a_dns_server_that_is_not_an_address() -> None:
    with pytest.raises(ValidationError, match="is not an IP address literal"):
        LeaseInfo(dns_servers=("192.0.2.53", "dns.example"))


@pytest.mark.parametrize("field", ["dhcp_server", "dns_servers"])
def test_a_subnet_record_refuses_a_lease_value_that_is_not_an_address(field: str) -> None:
    value = ("dns.example",) if field == "dns_servers" else "dhcp.example"
    record = {"interface": "lab0", "address": "192.0.2.7", "prefix_len": 24, "network": "192.0.2.0/24", field: value}

    with pytest.raises(ValidationError, match="is not an IP address literal"):
        SubnetInfo.model_validate(record)


@pytest.mark.parametrize("spelling", ["00-00-5E-00-53-01", "0000.5e00.5301", "00:00:5E:00:53:01", "00:00:5e:00:53:01"])
def test_every_spelling_normalise_mac_accepts_yields_what_a_record_accepts(spelling: str) -> None:
    # models cannot import arp, so the record's MAC check restates the form
    # normalise_mac writes; this pins the two together.
    mac = normalise_mac(spelling)

    assert mac is not None
    assert Neighbour(ip="192.0.2.7", mac=mac, family=AddressFamily.IPV4).mac == mac
