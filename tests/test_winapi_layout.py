"""Windows struct-layout stories, verifiable from any platform.

The Windows ICMP backend cannot be executed here, but its ctypes structures can
still be built and measured, because :mod:`ipscout.winapi` defers loading the
DLL until it is actually called. Every field is declared with an explicit width,
so the layout computed on Linux is the layout Windows will see - which is what
makes these assertions meaningful rather than decorative.

A wrong offset here would not raise on Windows. It would silently read the
wrong bytes and report a plausible, wrong address or status, so pinning the
layout is the only cheap defence available before CI runs.
"""

from __future__ import annotations

import ctypes
import sys

import pytest

from ipscout import winapi
from ipscout.errors import IPScoutUnsupportedError

pytestmark = pytest.mark.os_agnostic

#: Pointer width of this interpreter. Windows x64 and Linux x86-64 agree here,
#: which is why these sizes can be checked from either.
_PTR = ctypes.sizeof(ctypes.c_void_p)


def _offset(struct_type: type[ctypes.Structure], field: str) -> int:
    """Return the byte offset of a field within a ctypes structure."""

    return int(getattr(struct_type, field).offset)


def test_every_integer_field_has_the_width_the_c_header_declares() -> None:
    # The trap this guards: c_ulong is 4 bytes on Windows (LLP64) and 8 on
    # 64-bit Linux (LP64), so one c_ulong would make every later field land at
    # a different offset depending on where Python happens to run.
    #
    # This checks widths rather than type identity, because identity cannot be
    # checked portably: on Windows ctypes.c_uint32 *is* ctypes.c_ulong, so a
    # "no c_ulong anywhere" assertion passes on Linux and fails on Windows
    # while the layout is in fact correct on both.
    expected = {
        "Ttl": 1,
        "Tos": 1,
        "Flags": 1,
        "OptionsSize": 1,
        "Address": None,  # a struct in one type, a uint32 in the other
        "Status": 4,
        "RoundTripTime": 4,
        "DataSize": 2,
        "Reserved": 2,
        "sin6_port": 2,
        "sin6_family": 2,
        "sin6_flowinfo": 4,
        "sin6_scope_id": 4,
        "sin6_addr": 16,
    }
    structures = (
        winapi.IP_OPTION_INFORMATION,
        winapi.ICMP_ECHO_REPLY,
        winapi.IPV6_ADDRESS_EX,
        winapi.ICMPV6_ECHO_REPLY,
        winapi.SOCKADDR_IN6,
    )

    for structure in structures:
        for name, field_type, *_ in structure._fields_:
            width = expected.get(name)
            if width is None:
                continue
            actual = ctypes.sizeof(field_type)
            assert actual == width, f"{structure.__name__}.{name} is {actual} bytes, expected {width}"


def test_the_option_block_matches_the_c_layout() -> None:
    # Four bytes of flags, then a pointer on its natural boundary.
    assert _offset(winapi.IP_OPTION_INFORMATION, "Ttl") == 0
    assert _offset(winapi.IP_OPTION_INFORMATION, "Tos") == 1
    assert _offset(winapi.IP_OPTION_INFORMATION, "Flags") == 2
    assert _offset(winapi.IP_OPTION_INFORMATION, "OptionsSize") == 3
    assert _offset(winapi.IP_OPTION_INFORMATION, "OptionsData") == _PTR
    assert ctypes.sizeof(winapi.IP_OPTION_INFORMATION) == _PTR * 2


def test_the_ipv4_reply_matches_the_c_layout() -> None:
    reply = winapi.ICMP_ECHO_REPLY

    assert _offset(reply, "Address") == 0
    assert _offset(reply, "Status") == 4
    assert _offset(reply, "RoundTripTime") == 8
    assert _offset(reply, "DataSize") == 12
    assert _offset(reply, "Reserved") == 14
    assert _offset(reply, "Data") == 16
    assert _offset(reply, "Options") == 16 + _PTR
    # 40 bytes on a 64-bit build, 28 on 32-bit.
    assert ctypes.sizeof(reply) == 16 + _PTR + ctypes.sizeof(winapi.IP_OPTION_INFORMATION)


def test_the_ipv6_address_stays_byte_packed() -> None:
    # Declared between packon.h and packoff.h in the Windows headers. Without
    # _pack_ = 1 the compiler would insert two bytes of padding after
    # sin6_port and every field after it would be read from the wrong place.
    address = winapi.IPV6_ADDRESS_EX

    assert _offset(address, "sin6_port") == 0
    assert _offset(address, "sin6_flowinfo") == 2
    assert _offset(address, "sin6_addr") == 6
    assert _offset(address, "sin6_scope_id") == 22
    assert ctypes.sizeof(address) == 26


def test_the_ipv6_reply_is_not_itself_packed() -> None:
    # Only the address structure is packed; the reply around it is not, so
    # Status sits on its natural 4-byte boundary after the 26-byte address.
    reply = winapi.ICMPV6_ECHO_REPLY

    assert _offset(reply, "Address") == 0
    assert _offset(reply, "Status") == 28
    assert _offset(reply, "RoundTripTime") == 32
    assert ctypes.sizeof(reply) == 36


def test_the_sockaddr_matches_what_the_api_expects() -> None:
    sockaddr = winapi.SOCKADDR_IN6

    assert _offset(sockaddr, "sin6_family") == 0
    assert _offset(sockaddr, "sin6_port") == 2
    assert _offset(sockaddr, "sin6_flowinfo") == 4
    assert _offset(sockaddr, "sin6_addr") == 8
    assert _offset(sockaddr, "sin6_scope_id") == 24
    assert ctypes.sizeof(sockaddr) == 28


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "0.0.0.0", "192.168.1.1", "8.8.8.8", "255.255.255.255"],  # noqa: S104 - round-trip fixtures
)
def test_an_ipv4_address_survives_the_round_trip_through_the_api_encoding(address: str) -> None:
    assert winapi.ipv4_to_string(winapi.string_to_ipv4(address)) == address


def test_the_ipv4_encoding_matches_the_documented_byte_order() -> None:
    # IPAddr is network byte order packed into a little-endian ULONG, so
    # 127.0.0.1 is 0x0100007F, not 0x7F000001. Getting this backwards would
    # report every reply as coming from a mirrored address.
    assert winapi.string_to_ipv4("127.0.0.1") == 0x0100007F
    assert winapi.ipv4_to_string(0x0100007F) == "127.0.0.1"


@pytest.mark.parametrize("address", ["::1", "::", "fe80::1", "2001:db8::1"])
def test_an_ipv6_address_decodes_from_the_word_array(address: str) -> None:
    import socket

    packed = socket.inet_pton(socket.AF_INET6, address)
    words = (ctypes.c_uint16 * 8).from_buffer_copy(packed)

    assert winapi.ipv6_words_to_string(words) == address


def test_every_status_code_renders_as_text() -> None:
    assert winapi.status_message(winapi.IP_SUCCESS) == "success"
    assert winapi.status_message(winapi.IP_TTL_EXPIRED_TRANSIT) == "TTL expired in transit"
    assert winapi.status_message(winapi.IP_REQ_TIMED_OUT) == "request timed out"
    assert "12345" in winapi.status_message(12345)


@pytest.mark.skipif(sys.platform == "win32", reason="the DLL genuinely loads on Windows")
def test_loading_the_dll_off_windows_says_so_plainly() -> None:
    winapi.reset_library_cache()

    with pytest.raises(IPScoutUnsupportedError, match="Windows library"):
        winapi.iphlpapi()


@pytest.mark.skipif(sys.platform == "win32", reason="availability is real on Windows")
def test_availability_is_reported_as_false_rather_than_raising_off_windows() -> None:
    from ipscout.transport_windows import windows_icmp_available

    winapi.reset_library_cache()

    assert windows_icmp_available() is False
