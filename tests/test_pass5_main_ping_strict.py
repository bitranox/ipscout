"""A ping's numeric arguments are taken as given, never coerced from another type.

``True`` is an ``int`` subclass and ``"1"`` parses as a float, so a lax model
sent one echo for ``times=True`` and waited a second for ``timeout="1"``: a
caller's mistake read as a successful probe.
"""

from __future__ import annotations

import pytest

import ipscout


@pytest.mark.parametrize(
    ("argument", "value"),
    [
        ("times", True),
        ("times", 2.0),
        ("timeout", "1"),
        ("interval", "0"),
        ("payload_size", True),
        ("tcp_port", "443"),
    ],
)
def test_a_ping_argument_of_the_wrong_type_is_refused_before_any_probe(argument: str, value: object) -> None:
    with pytest.raises(ValueError, match=rf"^ping refused its arguments: {argument}: "):
        ipscout.ping("127.0.0.1", **{argument: value})  # pyright: ignore[reportArgumentType] - the wrong type is the input under test


def test_reachability_answers_false_for_a_timeout_given_as_text() -> None:
    # is_reachable never raises: a refused argument reads as "not reached",
    # the same as a refused tcp_port, even for a host that does answer.
    assert ipscout.is_reachable("127.0.0.1") is True
    assert ipscout.is_reachable("127.0.0.1", timeout="1") is False  # pyright: ignore[reportArgumentType] - the wrong type is the input under test
