"""Exception hierarchy for every failure this library reports.

The central rule is that *setup* problems raise while *network conditions* do
not. A host that is down, a packet that times out, a link with 100% loss - all
of those are answers, not errors, and come back as a ``ResponseObject`` with
``reached=False``. An exception here always means the caller asked for something
this process cannot do, and no amount of retrying will change it.

Keeping the two apart is the point of this module: a missing ICMP permission
and an unreachable host need different responses from the caller, so they are
reported through different channels rather than collapsed into one flag.

Contents:
    IPScoutError: Base class, so callers can catch the whole family.
    IPScoutPermissionError: The process lacks a required privilege.
    IPScoutResolutionError: A target name or family could not be resolved.
    IPScoutUnsupportedError: No backend exists for this platform or feature.
    IPScoutSweepError: A sweep cannot be run as asked, in two flavours -
        IPScoutSweepTooWideError and IPScoutSweepIncompleteError.
    ARP_SCAN_ALTERNATIVE: The unprivileged way out every refused active
        resolution offers.
    PERMISSION_ERRNOS: The errnos a kernel answers with for want of a privilege.
    kernel_refused_neighbour_change: The error for a neighbour-table change the
        kernel refused for a reason other than privilege.

Note:
    Names carry the ``IPScout`` prefix rather than reading ``PermissionError``
    or ``ResolutionError`` because ``PermissionError`` is a Python builtin and
    shadowing it is both confusing and flagged by ruff's ``A`` ruleset.

"""

from __future__ import annotations

import errno
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydantic import ValidationError

__all__ = [
    "ARP_SCAN_ALTERNATIVE",
    "PERMISSION_ERRNOS",
    "IPScoutError",
    "IPScoutPermissionError",
    "IPScoutResolutionError",
    "IPScoutSweepError",
    "IPScoutSweepIncompleteError",
    "IPScoutSweepTooWideError",
    "IPScoutUnsupportedError",
    "could_not_ask",
    "kernel_refused_neighbour_change",
    "refused_arguments",
    "validation_problems",
]

#: The way out offered whenever active MAC resolution is refused for want of a
#: privilege. Every backend ends its refusal with these words, so a caller meets
#: the same remedy whichever platform refused, and it is written once here.
ARP_SCAN_ALTERNATIVE = "use arp_scan(), which resolves the same addresses unprivileged"

#: The errnos a kernel answers with when the process lacks a privilege. Which
#: of the two a refusal carries depends on the path it took through the kernel,
#: so testing for one alone would report the other as an unexplained failure
#: instead of naming the privilege to grant.
PERMISSION_ERRNOS = frozenset({errno.EPERM, errno.EACCES})


class IPScoutError(Exception):
    """Base class for every error this library raises deliberately.

    Catch this to handle any ipscout-specific failure without also catching
    unrelated ``OSError`` noise from the standard library.

    Examples:
        >>> issubclass(IPScoutPermissionError, IPScoutError)
        True

    """


class IPScoutPermissionError(IPScoutError):
    """The process lacks a privilege the requested operation needs.

    Raised when unprivileged ICMP is unavailable and no raw socket can be
    opened either, or when ``active=True`` MAC resolution is requested without
    the rights it needs on this platform.

    The message is expected to name the concrete remediation rather than just
    reporting refusal, because the fix differs per platform and per operation.

    Examples:
        >>> raise IPScoutPermissionError("unprivileged ICMP unavailable")
        Traceback (most recent call last):
        ...
        ipscout.errors.IPScoutPermissionError: unprivileged ICMP unavailable

    """


class IPScoutResolutionError(IPScoutError):
    """A target could not be turned into a usable address.

    Covers both an unknown host and a host that resolves fine but has no
    address in the address family the caller demanded, which are different
    problems with the same practical consequence: there is nothing to probe.

    Examples:
        >>> issubclass(IPScoutResolutionError, IPScoutError)
        True

    """


class IPScoutSweepError(IPScoutError, ValueError):
    """A sweep cannot be run as the caller asked for it.

    Also a ``ValueError`` deliberately: the sweeping callables have documented
    ``Raises: ValueError`` since their first release, so a caller written
    against that contract keeps working while a caller who prefers the library
    hierarchy can catch :class:`IPScoutError` instead.

    Examples:
        >>> issubclass(IPScoutSweepError, (IPScoutError, ValueError))
        True

    """


class IPScoutSweepTooWideError(IPScoutSweepError):
    """Nothing was left to sweep once the address bound was applied.

    Either the network the caller named is wider than the bound, or every
    network this host is attached to is. The message names each one and its
    address count, because the remedy is to pass a narrower network and the
    caller cannot choose one without knowing which was refused.

    Examples:
        >>> issubclass(IPScoutSweepTooWideError, IPScoutSweepError)
        True

    """


class IPScoutSweepIncompleteError(IPScoutSweepError):
    """The sweep covered part of the ground and found nothing there.

    Raised instead of reporting "not found": with a network left unswept, an
    empty answer says only that nothing was found where the sweep reached,
    which is not the same statement and would read as the stronger one. A
    sweep that *did* find something reports the gap as data rather than
    raising, since the answer stands on its own.

    Examples:
        >>> issubclass(IPScoutSweepIncompleteError, IPScoutSweepError)
        True

    """


class IPScoutUnsupportedError(IPScoutError):
    """No backend implements this operation on this platform.

    Used where a capability genuinely does not exist rather than merely being
    forbidden - for instance traceroute on a platform whose kernel never
    surfaces ICMP Time Exceeded to an unprivileged socket. Distinguishing this
    from :class:`IPScoutPermissionError` matters: running as root would fix a
    permission problem, and would not fix this one.

    Examples:
        >>> issubclass(IPScoutUnsupportedError, IPScoutError)
        True

    """


def validation_problems(error: ValidationError) -> list[str]:
    """Return one ``<field>: <reason>`` line per problem a model refused.

    ``str(ValidationError)`` is written for the model's author: it names
    pydantic's error types, links a docs URL carrying the pinned pydantic
    version and echoes the caller's input back. Every refusal this library
    shows a caller is built from these lines instead, so the field and the
    reason are what reaches them. A validator's own ``ValueError`` keeps its
    exact words, without pydantic's ``Value error,`` prefix, and a refusal of
    the whole model (no field) is the reason alone.

    Args:
        error: The refusal to describe.

    Returns:
        The lines, in pydantic's order, without duplicates.

    Examples:
        >>> from pydantic import BaseModel, Field, ValidationError
        >>> class Probe(BaseModel):
        ...     times: int = Field(ge=1)
        >>> try:
        ...     Probe(times=0)
        ... except ValidationError as refused:
        ...     validation_problems(refused)
        ['times: Input should be greater than or equal to 1']

    """

    lines: list[str] = []
    for item in error.errors():
        context = item.get("ctx") or {}
        reason = str(context["error"]) if item["type"] == "value_error" and "error" in context else item["msg"]
        where = ".".join(str(part) for part in item["loc"])
        line = f"{where}: {reason}" if where else reason
        if line not in lines:
            lines.append(line)
    return lines


def refused_arguments(operation: str, error: ValidationError, *, field: str | None = None) -> ValueError:
    """Return the ``ValueError`` an entry point raises when its arguments model refused them.

    Every public function that checks its arguments through a model reports a
    refusal the same way, ``<operation> refused its arguments: <field>: <reason>``
    with one ``; ``-separated part per problem, so a caller meets one shape
    whichever function they called. Raise it ``from error`` so a traceback
    still reaches pydantic's full report.

    Args:
        operation: What refused, as the caller knows it (``"ping"``, ``"port scan"``).
        error: The model's refusal.
        field: The argument's name, when the refusal came from checking one bare
            value (a ``TypeAdapter``), which carries no field of its own.

    Examples:
        >>> from pydantic import TypeAdapter, ValidationError
        >>> from typing import Annotated
        >>> from annotated_types import Ge
        >>> try:
        ...     TypeAdapter(Annotated[int, Ge(1)]).validate_python(0)
        ... except ValidationError as refused:
        ...     str(refused_arguments("sweep", refused, field="limit"))
        'sweep refused its arguments: limit: Input should be greater than or equal to 1'

    """

    problems = validation_problems(error)
    if field is not None:
        problems = [f"{field}: {problem}" for problem in problems]
    return ValueError(f"{operation} refused its arguments: " + "; ".join(problems))


def could_not_ask(target_ip: str, interface: str, error: OSError) -> IPScoutUnsupportedError:
    """Return the error for a resolution request that could not be sent or heard.

    An interface that went down, a send the stack refused, a read that failed:
    none of these is "nobody answered", and reporting one as a ``None`` answer
    would tell a caller an address is free when it was never asked about. This
    is the same class as having no path at all, so a caller who allowed a
    fallback to the cache gets one.

    Args:
        target_ip: The address the request asked about.
        interface: The interface it was to go out on.
        error: What the operating system reported.

    Examples:
        >>> str(could_not_ask("192.0.2.7", "eth0", OSError(19, "No such device")))
        'could not ask for 192.0.2.7 on eth0: [Errno 19] No such device'

    """

    return IPScoutUnsupportedError(f"could not ask for {target_ip} on {interface}: {error}")


def kernel_refused_neighbour_change(verb: str, error: int) -> IPScoutError:
    """Return the error for a neighbour-table change the kernel refused.

    For a refusal that is not about privilege - those are
    :data:`PERMISSION_ERRNOS` and get their own remedy - so the kernel's own
    reason is all there is to report, with its errno for a caller to match on.

    Args:
        verb: What the change was to do (``"add"``, ``"delete"``).
        error: The errno the kernel answered with.

    Examples:
        >>> str(kernel_refused_neighbour_change("add", errno.EEXIST))
        'the kernel refused to add the neighbour entry: File exists (errno 17)'

    """

    return IPScoutError(f"the kernel refused to {verb} the neighbour entry: {os.strerror(error)} (errno {error})")
