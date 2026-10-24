"""Three platform backends' pure parts, asserted from any OS.

* The Windows adapter record: the name it is reported under, decoded from the
  ctypes structure the API fills, never ``"b'{GUID}'"`` and never empty.
* The macOS neighbour dump: header fields read by name through the one
  ``RT_MSGHDR`` struct, pinned byte for byte over a crafted dump.
* The macOS capture probe: it walks the BPF pool the way a capture claims a
  device, so a busy ``/dev/bpf0`` is not mistaken for a missing privilege.
  ``os.open`` is the operating-system edge the probe asks, so it is the one
  thing replaced; every other path is passed through to the real call.
"""

from __future__ import annotations

import ctypes
import errno
import os
import socket
import struct
import sys
from collections.abc import Callable, Iterator

import pytest

from ipscout import bsdroute, interfaces_windows
from ipscout import neighbours_macos as macos
from ipscout.bpf import open_bpf_device
from ipscout.dhcp_macos import capture_available
from ipscout.models import AddressFamily, Neighbour, NeighbourState

pytestmark = pytest.mark.os_agnostic

_Adapter = interfaces_windows._IpAdapterAddresses  # pyright: ignore[reportPrivateUsage] - the adapter record is the module's own ctypes struct
_Unicast = interfaces_windows._IpAdapterUnicastAddress  # pyright: ignore[reportPrivateUsage] - same, the unicast entry it points at

#: A GUID-shaped adapter name, as Windows writes it into AdapterName.
_GUID = b"{12345678-9ABC-DEF0-1234-56789ABCDEF0}"

#: AF_INET in Windows' numbering, which is how the sockaddr below is written.
_WIN_AF_INET = 2


# --------------------------------------------------------------------------
# Windows: the adapter name
# --------------------------------------------------------------------------


def _adapter(*, friendly: str | None, adapter_name: bytes | None, index: int) -> _Adapter:
    adapter = _Adapter()
    adapter.FriendlyName = friendly
    adapter.AdapterName = adapter_name
    adapter.IfIndex = index
    return adapter


def _build(adapter: _Adapter, *, position: int = 0) -> str:
    record = interfaces_windows._to_interface(adapter, position=position)  # pyright: ignore[reportPrivateUsage] - the adapter decode has no public entry off Windows
    return record.name


def test_the_friendly_name_is_what_a_person_recognises() -> None:
    assert _build(_adapter(friendly="Ethernet 2", adapter_name=_GUID, index=7)) == "Ethernet 2"


def test_the_adapter_name_is_decoded_text_not_the_repr_of_bytes() -> None:
    # c_char_p reads as bytes; str() of it was "b'{...}'".
    assert _build(_adapter(friendly=None, adapter_name=_GUID, index=7)) == _GUID.decode("ascii")


def test_an_empty_friendly_name_falls_through_to_the_adapter_name() -> None:
    assert _build(_adapter(friendly="", adapter_name=_GUID, index=7)) == _GUID.decode("ascii")


def test_an_adapter_with_no_name_is_named_by_its_index() -> None:
    assert _build(_adapter(friendly=None, adapter_name=None, index=7)) == "ifindex-7"


def test_an_adapter_with_no_name_and_no_index_is_named_by_its_position() -> None:
    names = {_build(_adapter(friendly=None, adapter_name=None, index=0), position=n) for n in range(3)}

    assert names == {"adapter-0", "adapter-1", "adapter-2"}


def test_a_stray_byte_in_the_adapter_name_does_not_fail_the_enumeration() -> None:
    assert _build(_adapter(friendly=None, adapter_name=b"{ab\xffcd}", index=7)) == "{ab�cd}"


def test_an_adapter_record_carries_its_unicast_address_and_prefix() -> None:
    raw = _WIN_AF_INET.to_bytes(2, "little") + bytes(2) + socket.inet_aton("192.0.2.10") + bytes(8)
    sockaddr = ctypes.create_string_buffer(raw, len(raw))
    unicast = _Unicast()
    unicast.Address.lpSockaddr = ctypes.addressof(sockaddr)
    unicast.Address.iSockaddrLength = len(raw)
    unicast.OnLinkPrefixLength = 24
    adapter = _adapter(friendly=None, adapter_name=_GUID, index=7)
    adapter.FirstUnicastAddress = ctypes.pointer(unicast)

    record = interfaces_windows._to_interface(adapter, position=0)  # pyright: ignore[reportPrivateUsage] - the adapter decode has no public entry off Windows

    assert record.name == _GUID.decode("ascii")
    assert record.index == 7
    assert [(a.address, a.prefix_len) for a in record.ipv4] == [("192.0.2.10", 24)]
    assert record.ipv6 == ()


# --------------------------------------------------------------------------
# macOS: the neighbour dump, read by field name
# --------------------------------------------------------------------------


def _sockaddr_dl(mac: bytes, name: bytes = b"en0") -> bytes:
    data = name + mac
    length = bsdroute.SOCKADDR_DL.size + len(data)
    return bsdroute.SOCKADDR_DL.pack(length, bsdroute.AF_LINK, 1, 6, len(name), len(mac), 0) + data


def _entry(ip: str, mac: bytes, *, index: int, pad: int = 0) -> bytes:
    """One NET_RT_FLAGS entry; ``pad`` leaves rtm_msglen off a 4-byte boundary."""

    dst = struct.pack("=BBH4s8s", 16, socket.AF_INET, 0, socket.inet_aton(ip), bytes(8))
    link = _sockaddr_dl(mac)
    payload = dst + link + bytes(-len(link) % 4) + bytes(pad)
    header = bsdroute.RT_MSGHDR.pack(
        bsdroute.RT_MSGHDR.size + len(payload),
        bsdroute.RTM_VERSION,
        0x04,
        index,
        bsdroute.RTF_UP | bsdroute.RTF_LLINFO,
        bsdroute.RTA_DST | bsdroute.RTA_GATEWAY,
        0,
        0,
        0,
        0,
        0,
        bsdroute.NO_METRICS,
    )
    return header + payload + bytes(-len(payload) % 4)


def _a_real_interface() -> tuple[int, str]:
    """The lowest index this host has, so the dump's index field is observable."""

    return min(socket.if_nameindex())


def test_a_crafted_dump_decodes_byte_for_byte_with_its_interface_index() -> None:
    index, name = _a_real_interface()
    dump = (
        _entry("192.0.2.5", bytes.fromhex("02005e100001"), index=index)
        + _entry("192.0.2.6", bytes.fromhex("02005e100002"), index=0, pad=1)
        # A header whose rtm_msglen is smaller than a header: the walk stops.
        + bytes(bsdroute.RT_MSGHDR.size)
        + _entry("192.0.2.7", bytes.fromhex("02005e100003"), index=0)
    )

    entries = macos.parse_neighbour_dump(dump, AddressFamily.IPV4)

    assert entries == [
        Neighbour(
            ip="192.0.2.5",
            mac="02:00:5e:10:00:01",
            interface=name,
            state=NeighbourState.OTHER,
            family=AddressFamily.IPV4,
        ),
        Neighbour(
            ip="192.0.2.6",
            mac="02:00:5e:10:00:02",
            interface=None,
            state=NeighbourState.OTHER,
            family=AddressFamily.IPV4,
        ),
    ]


def test_a_message_claiming_more_than_the_dump_holds_ends_the_walk() -> None:
    whole = _entry("192.0.2.5", bytes.fromhex("02005e100001"), index=0)
    second = _entry("192.0.2.6", bytes.fromhex("02005e100002"), index=0)

    entries = macos.parse_neighbour_dump(whole + second[:-4], AddressFamily.IPV4)

    assert [str(e.ip) for e in entries] == ["192.0.2.5"]


# --------------------------------------------------------------------------
# macOS: the capture probe walks the pool
# --------------------------------------------------------------------------

_RealOpen = Callable[..., int]


class _FakeBpfPool:
    """Answers ``os.open`` for ``/dev/bpf<n>`` from a script; passes the rest through."""

    def __init__(self, real_open: _RealOpen, answers: dict[int, int | None], default: int | None) -> None:
        self._real_open = real_open
        self._answers = answers
        self._default = default
        self.tried: list[int] = []
        self.opened: list[int] = []

    def __call__(self, path: str, flags: int, *args: int, **kwargs: int) -> int:
        if not str(path).startswith("/dev/bpf"):
            return self._real_open(path, flags, *args, **kwargs)
        number = int(str(path).removeprefix("/dev/bpf"))
        self.tried.append(number)
        code = self._answers.get(number, self._default)
        if code is not None:
            # OSError(errno, ...) picks the subclass itself: EACCES and EPERM
            # come back as PermissionError, exactly as the real call raises.
            raise OSError(code, os.strerror(code), path)
        descriptor = self._real_open(os.devnull, os.O_RDONLY)
        self.opened.append(descriptor)
        return descriptor


@pytest.fixture
def bpf_pool(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[dict[int, int | None], int | None], _FakeBpfPool]]:
    real_open: _RealOpen = os.open

    def install(answers: dict[int, int | None], default: int | None) -> _FakeBpfPool:
        pool = _FakeBpfPool(real_open, answers, default)
        monkeypatch.setattr(os, "open", pool)
        return pool

    yield install


def _closed(descriptor: int) -> bool:
    try:
        os.fstat(descriptor)
    except OSError as exc:
        return exc.errno == errno.EBADF
    return False


def test_a_busy_first_device_does_not_hide_a_free_second_one(
    bpf_pool: Callable[[dict[int, int | None], int | None], _FakeBpfPool],
) -> None:
    pool = bpf_pool({0: errno.EBUSY, 1: None}, errno.ENOENT)

    assert capture_available() is True
    assert pool.tried == [0, 1]
    assert len(pool.opened) == 1
    assert _closed(pool.opened[0])


@pytest.mark.parametrize("code", [errno.EACCES, errno.EPERM])
def test_a_refused_device_answers_no_privilege_at_once(
    bpf_pool: Callable[[dict[int, int | None], int | None], _FakeBpfPool],
    code: int,
) -> None:
    pool = bpf_pool({0: code}, None)

    assert capture_available() is False
    assert pool.tried == [0]


def test_a_refusal_after_a_busy_device_still_answers_no_privilege(
    bpf_pool: Callable[[dict[int, int | None], int | None], _FakeBpfPool],
) -> None:
    pool = bpf_pool({0: errno.EBUSY, 1: errno.EACCES}, None)

    assert capture_available() is False
    assert pool.tried == [0, 1]


@pytest.mark.skipif(sys.platform == "win32", reason="open_bpf_device needs fcntl, which Windows lacks")
def test_the_probe_tries_the_same_pool_a_capture_claims_from(
    bpf_pool: Callable[[dict[int, int | None], int | None], _FakeBpfPool],
) -> None:
    probe = bpf_pool({}, errno.EBUSY)
    assert capture_available() is False

    claim = bpf_pool({}, errno.EBUSY)
    with pytest.raises(OSError) as raised:
        open_bpf_device("en0")

    assert raised.value.errno == errno.EBUSY

    assert probe.tried == claim.tried
    assert len(probe.tried) > 1


def test_an_entry_of_the_other_family_is_skipped_rather_than_failing_the_dump() -> None:
    # A Neighbour refuses a family that disagrees with its address, so an IPv4
    # entry in a dump requested for IPv6 must be dropped, not raise.
    dump = _entry("192.0.2.5", bytes.fromhex("02005e100001"), index=0)

    assert macos.parse_neighbour_dump(dump, AddressFamily.IPV6) == []
    assert [entry.ip for entry in macos.parse_neighbour_dump(dump, AddressFamily.IPV4)] == ["192.0.2.5"]
