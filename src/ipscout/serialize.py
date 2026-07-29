"""Renders a result into JSON text at the output boundary.

One adapter, not a converter per type. Every record is a Pydantic model, so its
own ``model_dump(mode="json")`` already produces JSON-ready data with the
computed statistics included and the enums flattened to their values. All that
remains is walking the containers a command hands back - a list of hops, a
mapping of target to result - down to the models inside.

Contents:
    to_jsonable: Convert a command result to JSON-ready data.
    dumps: Serialise it to text.

Note:
    This replaced a set of hand-written per-type converters. Those had to
    re-list every field, which meant a field added to a model was silently
    absent from its JSON until someone noticed. ``model_dump`` cannot drift
    from the model because it *is* the model.

"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

from pydantic import BaseModel

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = ["dumps", "to_jsonable"]


def to_jsonable(value: Any) -> Any:
    """Return ``value`` as data ``json.dumps`` accepts.

    Args:
        value: A model, or any list/tuple/dict containing them.

    Returns:
        Dictionaries, lists and scalars.

    Examples:
        >>> from ipscout.models import ResponseObject
        >>> payload = to_jsonable(ResponseObject(target="t", ip="10.0.0.1",
        ...                                      number_of_pings=1, rtts_ms=(2.0,),
        ...                                      packets_sent=1, packets_received=1,
        ...                                      reached=True))
        >>> payload["family"], payload["method"]
        ('ipv4', 'icmp')

        The computed statistics come along, because they are model fields:

        >>> payload["time_avg_ms"], payload["packets_lost_percentage"]
        (2.0, 0)

        Containers are walked through:

        >>> to_jsonable({"a": [1, 2]})
        {'a': [1, 2]}

    """

    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in cast("dict[Any, Any]", value).items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in cast("Iterable[Any]", value)]
    return value


def dumps(payload: Any, *, indent: int | None = 2) -> str:
    """Return ``payload`` as JSON text.

    Args:
        payload: Anything :func:`to_jsonable` can convert.
        indent: Pretty-printing indent, or ``None`` for one compact line.

    Returns:
        JSON text.

    Examples:
        >>> dumps({"ok": True}, indent=None)
        '{"ok": true}'

    """

    return json.dumps(to_jsonable(payload), indent=indent)
