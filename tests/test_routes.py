"""Route-lookup stories: the shared contract, and the wire formats per platform.

The macOS decoder gets adversarial coverage over synthetic buffers because it
cannot be exercised on the Linux development host at all, and a routing message
is exactly the kind of variable-length walk that goes wrong silently.
"""

# _next_hop and the routing-message constants are asked directly throughout:
# they decode a SOCKADDR_INET and build a synthetic RTM_GET, and the public
# lookup that wraps them cannot run on this platform, so every case below would
# otherwise be unreachable.
# pyright: reportPrivateUsage=false

from __future__ import annotations

import ctypes
import json
import socket
import struct

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

import ipscout
from ipscout import bsdroute, winapi
from ipscout import routes_macos as macos
from ipscout import routes_windows as windows
from ipscout.cli import EXIT_NOT_REACHED, EXIT_OK, cli, main
from ipscout.models import AddressFamily, RouteInfo

pytestmark = pytest.mark.os_agnostic


# --------------------------------------------------------------------------
# The contract every backend answers to
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_a_loopback_destination_is_reached_without_a_router() -> None:
    # The direct-versus-routed distinction is the whole reason this lookup
    # exists, and loopback is the one destination every host agrees is direct.
    route = ipscout.query_route("127.0.0.1")

    assert route is not None
    assert route.gateway is None


@pytest.mark.os_agnostic
def test_a_default_route_names_a_router_rather_than_pointing_at_loopback() -> None:
    # Asking for the route to 0.0.0.0 looks like it should yield the default
    # route and does not: on Linux the unspecified address matches the local
    # table first, so the answer came back as loopback with no gateway. This
    # pins the outcome on every platform, since the same mistake is available
    # to each backend and only CI can catch it on macOS and Windows.
    route = ipscout.default_gateway()

    if route is None:
        pytest.skip("this host has no IPv4 default route")
    assert route.gateway is not None, route
    assert route.interface != "lo", route


@pytest.mark.os_agnostic
def test_a_family_without_a_default_route_reports_absence_rather_than_raising() -> None:
    # A host with no IPv6 default route is an ordinary configuration.
    route = ipscout.default_gateway(AddressFamily.IPV6)

    assert route is None or route.gateway is not None


@pytest.mark.os_agnostic
def test_an_unparseable_destination_is_not_a_route() -> None:
    assert ipscout.query_route("not-an-address") is None


@pytest.mark.os_agnostic
def test_a_zone_does_not_turn_a_route_into_a_silent_absence() -> None:
    # The zone names an interface, which the routing table does not carry in
    # the destination it is asked about. Passing it through reached inet_pton,
    # which refuses it, and the refusal reads as "no route to that address" -
    # a real answer, and the wrong one.
    bare = ipscout.query_route("::1", AddressFamily.IPV6)
    scoped = ipscout.query_route("::1%1", AddressFamily.IPV6)

    assert scoped == bare


@pytest.mark.os_agnostic
def test_a_route_record_cannot_be_edited_after_the_fact() -> None:
    route = RouteInfo(gateway="192.0.2.1")

    with pytest.raises(ValidationError):
        route.gateway = "192.0.2.2"


# --------------------------------------------------------------------------
# macOS wire format, over synthetic buffers
# --------------------------------------------------------------------------


def _sockaddr_in(address: str) -> bytes:
    """Build a BSD sockaddr_in: len, family, port, address, padding."""

    return struct.pack("=BBH4s8s", 16, socket.AF_INET, 0, socket.inet_aton(address), b"\x00" * 8)


def _rt_message(*, flags: int, addrs: int, payload: bytes, pid: int = 4242, seq: int = 1, index: int = 0, errno: int = 0) -> bytes:
    """Build one routing message with the documented rt_msghdr layout."""

    header = bsdroute.RT_MSGHDR.pack(
        bsdroute.RT_MSGHDR.size + len(payload),
        macos._RTM_VERSION,
        macos._RTM_GET,
        index,
        flags,
        addrs,
        pid,
        seq,
        errno,
        0,
        0,
        b"\x00" * 56,
    )
    return header + payload


@pytest.mark.os_agnostic
def test_the_header_matches_the_documented_c_layout() -> None:
    # 92 bytes is what the C struct comes to; a mismatch means every sockaddr
    # after it is read from the wrong offset.
    assert bsdroute.RT_MSGHDR.size == 92


@pytest.mark.os_agnostic
def test_a_routed_reply_yields_the_next_hop() -> None:
    message = _rt_message(
        flags=bsdroute.RTF_UP | bsdroute.RTF_GATEWAY,
        addrs=bsdroute.RTA_DST | bsdroute.RTA_GATEWAY,
        payload=_sockaddr_in("8.8.8.8") + _sockaddr_in("192.168.1.1"),
    )

    route = macos.parse_route_reply(message, pid=4242, seq=1)

    assert route is not None
    assert route.gateway == "192.168.1.1"


@pytest.mark.os_agnostic
def test_an_on_link_reply_reports_no_gateway_even_though_one_is_present() -> None:
    # An on-link route still carries a gateway sockaddr, holding the link
    # address rather than a router. Reading it without checking RTF_GATEWAY
    # would invent a next hop for a directly-attached host.
    message = _rt_message(
        flags=bsdroute.RTF_UP,
        addrs=bsdroute.RTA_DST | bsdroute.RTA_GATEWAY,
        payload=_sockaddr_in("192.168.1.5") + _sockaddr_in("192.168.1.5"),
    )

    route = macos.parse_route_reply(message, pid=4242, seq=1)

    assert route is not None
    assert route.gateway is None


@pytest.mark.os_agnostic
def test_a_zero_length_sockaddr_still_consumes_its_slot() -> None:
    # The default route carries an unspecified destination as a zero-length
    # sockaddr. Treating that as zero bytes slides every later address out of
    # position, so the gateway would be read from the middle of nowhere.
    message = _rt_message(
        flags=bsdroute.RTF_UP | bsdroute.RTF_GATEWAY,
        addrs=bsdroute.RTA_DST | bsdroute.RTA_GATEWAY,
        payload=b"\x00\x00\x00\x00" + _sockaddr_in("192.168.1.1"),
    )

    route = macos.parse_route_reply(message, pid=4242, seq=1)

    assert route is not None
    assert route.gateway == "192.168.1.1"


@pytest.mark.os_agnostic
def test_another_process_reply_is_not_mistaken_for_ours() -> None:
    # A route socket is shared: every listener sees every message.
    message = _rt_message(
        flags=bsdroute.RTF_UP | bsdroute.RTF_GATEWAY,
        addrs=bsdroute.RTA_DST | bsdroute.RTA_GATEWAY,
        payload=_sockaddr_in("8.8.8.8") + _sockaddr_in("192.168.1.1"),
        pid=9999,
    )

    assert macos.parse_route_reply(message, pid=4242, seq=1) is None


@pytest.mark.os_agnostic
def test_a_reply_to_an_older_query_is_not_mistaken_for_this_one() -> None:
    message = _rt_message(
        flags=bsdroute.RTF_UP,
        addrs=bsdroute.RTA_DST,
        payload=_sockaddr_in("8.8.8.8"),
        seq=7,
    )

    assert macos.parse_route_reply(message, pid=4242, seq=1) is None


@pytest.mark.os_agnostic
def test_a_route_that_is_down_is_not_a_route() -> None:
    message = _rt_message(flags=0, addrs=bsdroute.RTA_DST, payload=_sockaddr_in("8.8.8.8"))

    assert macos.parse_route_reply(message, pid=4242, seq=1) is None


@pytest.mark.os_agnostic
def test_a_kernel_error_reply_is_not_a_route() -> None:
    message = _rt_message(flags=bsdroute.RTF_UP, addrs=bsdroute.RTA_DST, payload=_sockaddr_in("8.8.8.8"), errno=65)

    assert macos.parse_route_reply(message, pid=4242, seq=1) is None


@pytest.mark.os_agnostic
@pytest.mark.parametrize("size", [0, 1, 40, 91])
def test_a_truncated_message_is_refused_rather_than_misread(size: int) -> None:
    message = _rt_message(flags=bsdroute.RTF_UP, addrs=bsdroute.RTA_DST, payload=_sockaddr_in("8.8.8.8"))

    assert macos.parse_route_reply(message[:size]) is None


@pytest.mark.os_agnostic
def test_a_sockaddr_claiming_more_bytes_than_it_has_does_not_read_past_the_end() -> None:
    # A hostile or corrupt length must not walk off the buffer.
    truncated = _sockaddr_in("8.8.8.8")[:8]
    message = _rt_message(flags=bsdroute.RTF_UP | bsdroute.RTF_GATEWAY, addrs=bsdroute.RTA_DST | bsdroute.RTA_GATEWAY, payload=truncated)

    route = macos.parse_route_reply(message, pid=4242, seq=1)

    assert route is None or route.gateway is None


@pytest.mark.os_agnostic
def test_a_link_layer_sockaddr_carries_no_ip_address() -> None:
    # AF_LINK appears in real replies; the interface comes from rtm_index.
    link = struct.pack("=BB", 8, 18) + b"\x00" * 6

    assert bsdroute.address_of(link) is None


# --------------------------------------------------------------------------
# The CLI surface
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_the_gateway_command_emits_a_valid_envelope() -> None:
    result = CliRunner().invoke(cli, ["--json", "gateway"], standalone_mode=False)
    payload = json.loads(result.output)

    assert payload["ok"] is True
    assert payload["command"] == "gateway"
    assert set(payload["data"]) == {"gateway", "interface", "source"}


@pytest.mark.os_agnostic
def test_the_gateway_command_exits_one_when_there_is_no_route() -> None:
    # Through main(), not CliRunner(standalone_mode=False): that harness swallows
    # ctx.exit() and reports 0 for every not-reached path, so this assertion used
    # to pass only because the developer box happens to HAVE a default route, and
    # would have failed on the routeless host it is named for.
    expected = EXIT_OK if ipscout.default_gateway() is not None else EXIT_NOT_REACHED

    assert main(["gateway"]) == expected


@pytest.mark.os_agnostic
def test_the_gateway_command_can_report_the_next_hop_toward_one_address() -> None:
    result = CliRunner().invoke(cli, ["--json", "gateway", "--to", "127.0.0.1"], standalone_mode=False)
    payload = json.loads(result.output)

    assert payload["ok"] is True
    assert payload["data"]["gateway"] is None


# --------------------------------------------------------------------------
# Windows next-hop decoding, over structures built by hand
# --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_an_on_link_windows_route_reports_no_router() -> None:
    # GetBestRoute2 does not leave the next hop empty for an on-link
    # destination: it fills in the unspecified address of the right family,
    # which decodes as a perfectly valid "0.0.0.0". Reading that as a router
    # made every Windows job report the loopback route as routed via 0.0.0.0.
    sockaddr = winapi.SOCKADDR_INET()
    sockaddr.si_family = winapi.WIN_AF_INET

    assert windows._next_hop(sockaddr) is None


@pytest.mark.os_agnostic
def test_an_unspecified_ipv6_next_hop_reports_no_router() -> None:
    sockaddr = winapi.SOCKADDR_INET()
    sockaddr.si_family = winapi.WIN_AF_INET6

    assert windows._next_hop(sockaddr) is None


@pytest.mark.os_agnostic
def test_a_real_windows_next_hop_is_reported() -> None:
    sockaddr = winapi.SOCKADDR_INET()
    sockaddr.si_family = winapi.WIN_AF_INET
    sockaddr.Ipv4.sin_addr[:] = (192, 168, 1, 1)

    assert windows._next_hop(sockaddr) == "192.168.1.1"


@pytest.mark.os_agnostic
def test_a_next_hop_of_no_family_reports_no_router() -> None:
    assert windows._next_hop(winapi.SOCKADDR_INET()) is None


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("structure", "expected"),
    [("SOCKADDR_IN", 16), ("SOCKADDR_IN6", 28), ("SOCKADDR_INET", 28), ("IP_ADDRESS_PREFIX", 32), ("MIB_IPFORWARD_ROW2", 104)],
)
def test_the_windows_structures_match_their_c_layouts(structure: str, expected: int) -> None:
    # A short structure would have GetBestRoute2 write past the buffer it was
    # given, which corrupts memory rather than failing cleanly.
    assert ctypes.sizeof(getattr(winapi, structure)) == expected


@pytest.mark.os_agnostic
def test_the_forwarding_table_rows_start_at_the_aligned_offset() -> None:
    # NET_LUID is 64-bit, so the row array begins at 8, not at 4 where the
    # count ends. Reading from 4 would misparse every row.
    assert winapi.MIB_IPFORWARD_TABLE2.Table.offset == 8
