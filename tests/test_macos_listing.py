"""Whether the macOS neighbour dump lists an address, on the interface asked about.

The static-entry writers on macOS only delete what the dump lists, so a host
route that is not a neighbour cannot be removed through them. The predicate
is pure over the parsed entries, so it runs on every OS; only the interface
name lookup touches this host, through an index that names no interface.
"""

from __future__ import annotations

import socket

import pytest

from ipscout.models import AddressFamily, Neighbour
from ipscout.neighbours_macos import lists_neighbour
from ipscout.resolve import MAX_INTERFACE_INDEX

pytestmark = pytest.mark.os_agnostic

_MAC = "00:00:5e:00:53:01"


def _known_index() -> tuple[int, str]:
    index, name = socket.if_nameindex()[0]
    return index, name


def _unknown_index() -> int:
    known = {index for index, _name in socket.if_nameindex()}
    return next(index for index in range(MAX_INTERFACE_INDEX - 1, 0, -1) if index not in known)


def test_an_entry_on_the_interface_asked_about_is_listed() -> None:
    index, name = _known_index()
    entries = [Neighbour(ip="192.0.2.7", mac=_MAC, interface=name, family=AddressFamily.IPV4)]

    assert lists_neighbour(entries, "192.0.2.7", ifindex=index) is True


def test_an_entry_on_another_interface_is_not_listed_for_this_one() -> None:
    index, _name = _known_index()
    entries = [Neighbour(ip="192.0.2.7", mac=_MAC, interface="other0", family=AddressFamily.IPV4)]

    assert lists_neighbour(entries, "192.0.2.7", ifindex=index) is False


def test_nothing_is_listed_on_an_interface_that_does_not_exist() -> None:
    # Before, an unknown index read as "no name", which matched every entry
    # with no interface, so a removal there deleted that entry.
    entries = [Neighbour(ip="192.0.2.7", mac=_MAC, interface=None, family=AddressFamily.IPV4)]

    assert lists_neighbour(entries, "192.0.2.7", ifindex=_unknown_index()) is False


def test_without_an_interface_any_entry_for_the_address_is_listed() -> None:
    entries = [
        Neighbour(ip="192.0.2.8", mac=_MAC, interface="lab0", family=AddressFamily.IPV4),
        Neighbour(ip="192.0.2.7", mac=_MAC, interface=None, family=AddressFamily.IPV4),
    ]

    assert lists_neighbour(entries, "192.0.2.7") is True
    assert lists_neighbour(entries, "192.0.2.9") is False
