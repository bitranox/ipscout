"""How a refused connection is recognised, in each spelling a platform uses for it."""

from __future__ import annotations

import errno

import pytest

from ipscout.sockerr import is_refusal

pytestmark = pytest.mark.os_agnostic


def test_the_dedicated_exception_class_is_a_refusal() -> None:
    assert is_refusal(ConnectionRefusedError(errno.ECONNREFUSED, "refused"))


def test_a_bare_oserror_carrying_the_posix_errno_is_a_refusal() -> None:
    # The condition can arrive without the subclass, so the errno alone must decide.
    assert is_refusal(OSError(errno.ECONNREFUSED, "refused"))


@pytest.mark.parametrize("code", [10061, 1225], ids=["WSAECONNREFUSED", "ERROR_CONNECTION_REFUSED"])
def test_the_windows_numbering_is_a_refusal_in_errno(code: int) -> None:
    assert is_refusal(OSError(code, "refused"))


class _WinerrorOnlyError(OSError):
    """An OSError whose errno says nothing and whose ``winerror`` says refused.

    OSError carries ``winerror`` only on Windows, so this stands in for that
    shape on every platform without patching the builtin.
    """

    def __init__(self, winerror: int) -> None:
        super().__init__(errno.EIO, "refused")
        self.winerror = winerror


@pytest.mark.parametrize("code", [10061, 1225], ids=["WSAECONNREFUSED", "ERROR_CONNECTION_REFUSED"])
def test_the_windows_numbering_is_a_refusal_in_winerror(code: int) -> None:
    assert is_refusal(_WinerrorOnlyError(code))


@pytest.mark.parametrize(
    "exc",
    [TimeoutError("timed out"), OSError(errno.EHOSTUNREACH, "no route"), OSError(errno.ENETUNREACH, "no network"), OSError("no errno")],
    ids=["timeout", "host-unreachable", "net-unreachable", "no-errno"],
)
def test_silence_and_unreachability_are_not_refusals(exc: OSError) -> None:
    # A refusal proves something is there; these prove nothing, so they must not pass for one.
    assert not is_refusal(exc)
