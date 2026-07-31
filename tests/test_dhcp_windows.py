"""The Windows capture backend, asserted from any platform where possible.

The constants and the address resolution are pure, so they are pinned here and
run everywhere - the same technique ``test_winapi_layout.py`` uses to check
Windows structure layouts from Linux. The socket path itself needs Windows and
an elevated process, which CI has: ``windows-latest`` runs as an administrator
account, so unlike the Linux backend this one is genuinely exercised there.
"""

# The backend's private dispatch and address resolution are the subject here.
# pyright: reportPrivateUsage=false

from __future__ import annotations

import socket
import sys

import pytest

from ipscout.dhcp import _open_capture, dhcp_capture_available
from ipscout.dhcp_windows import (
    RCVALL_OFF,
    RCVALL_ON,
    SIO_RCVALL,
    RawSocketCapture,
    capture_available,
    open_capture,
)
from ipscout.errors import IPScoutPermissionError, IPScoutUnsupportedError
from ipscout.ports import PacketCapture

pytestmark = pytest.mark.os_agnostic


# --------------------------------------------------------------------------
# Pinned from any platform
# --------------------------------------------------------------------------


def test_the_ioctl_number_is_the_one_mstcpip_defines() -> None:
    # _WSAIOW(IOC_VENDOR, 1) resolves to this. Spelled as a literal in the
    # source because the macro's inputs are not exposed by the socket module,
    # so a mistyped digit would otherwise only surface on a Windows host.
    ioc_in, ioc_vendor = 0x80000000, 0x18000000

    assert ioc_in | ioc_vendor | 1 == SIO_RCVALL


def test_the_ioctl_arguments_are_off_and_on() -> None:
    assert (RCVALL_OFF, RCVALL_ON) == (0, 1)


def test_the_module_imports_and_answers_on_every_platform() -> None:
    # It has to import cleanly off Windows, or the pure assertions above could
    # not run and the facade could not dispatch to it.
    assert isinstance(capture_available(), bool)


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has socket.ioctl, so the absence cannot be observed there")
def test_a_platform_without_the_ioctl_reports_no_capability() -> None:
    # capture_available() must not claim a capability that rests on an ioctl
    # this platform does not have, even if the raw socket itself opened.
    assert capture_available() is False


# --------------------------------------------------------------------------
# The address resolution, which is what makes one spelling work everywhere
# --------------------------------------------------------------------------


def test_an_address_is_taken_as_given_rather_than_looked_up() -> None:
    # SIO_RCVALL binds to an address, but the public argument is called
    # "interface" on every platform, so both spellings have to work.
    from ipscout.dhcp_windows import _address_for

    assert _address_for("192.0.2.10") == "192.0.2.10"


def test_an_ipv6_address_is_not_mistaken_for_something_to_bind() -> None:
    # DHCPv4 is IPv4 only. An IPv6 literal is not an adapter name either, so
    # it must fall through to the lookup rather than being bound.
    from ipscout.dhcp_windows import _address_for

    with pytest.raises((IPScoutUnsupportedError, ModuleNotFoundError, OSError)):
        _address_for("2001:db8::1")


# --------------------------------------------------------------------------
# The real socket, on Windows
# --------------------------------------------------------------------------


@pytest.mark.os_windows
@pytest.mark.skipif(sys.platform != "win32", reason="the raw socket path is Windows-only")
def test_a_real_capture_opens_and_satisfies_the_protocol() -> None:
    if not dhcp_capture_available():
        pytest.skip("this process is not elevated, so no raw socket may be opened")

    address = socket.gethostbyname(socket.gethostname())
    with open_capture(address) as capture:
        assert isinstance(capture, PacketCapture)
        assert isinstance(capture, RawSocketCapture)
        assert capture.address == address
        # Nothing is asserted about what arrives: a quiet moment on the wire is
        # the ordinary case, and requiring traffic would make this flaky.
        capture.receive(timeout=0.2)


@pytest.mark.os_windows
@pytest.mark.skipif(sys.platform != "win32", reason="the raw socket path is Windows-only")
def test_the_facade_reaches_the_windows_backend() -> None:
    if not dhcp_capture_available():
        pytest.skip("this process is not elevated, so no raw socket may be opened")

    with _open_capture(socket.gethostbyname(socket.gethostname())) as capture:
        assert isinstance(capture, RawSocketCapture)


@pytest.mark.os_windows
@pytest.mark.skipif(sys.platform != "win32", reason="the raw socket path is Windows-only")
def test_an_interface_that_holds_no_address_is_refused_by_name() -> None:
    with pytest.raises(IPScoutUnsupportedError, match="no interface named"):
        open_capture("no-such-adapter-here")


@pytest.mark.os_windows
@pytest.mark.skipif(sys.platform != "win32", reason="the raw socket path is Windows-only")
def test_an_unelevated_process_is_refused_with_the_remedy_named() -> None:
    if dhcp_capture_available():
        pytest.skip("this process is elevated, so there is no refusal to observe")

    with pytest.raises(IPScoutPermissionError, match="Administrator"):
        open_capture(socket.gethostbyname(socket.gethostname()))
