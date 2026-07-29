"""Exception hierarchy for every failure this library reports.

The central rule is that *setup* problems raise while *network conditions* do
not. A host that is down, a packet that times out, a link with 100% loss - all
of those are answers, not errors, and come back as a ``ResponseObject`` with
``reached=False``. An exception here always means the caller asked for something
this process cannot do, and no amount of retrying will change it.

The old library swallowed everything through ``except: ... finally: return
response``, which made a missing ICMP permission look exactly like an
unreachable host. Splitting the two apart is the point of this module.

Contents:
    IPScoutError: Base class, so callers can catch the whole family.
    IPScoutPermissionError: The process lacks a required privilege.
    IPScoutResolutionError: A target name or family could not be resolved.
    IPScoutUnsupportedError: No backend exists for this platform or feature.

Note:
    Names carry the ``IPScout`` prefix rather than reading ``PermissionError``
    or ``ResolutionError`` because ``PermissionError`` is a Python builtin and
    shadowing it is both confusing and flagged by ruff's ``A`` ruleset.

"""

from __future__ import annotations

__all__ = [
    "IPScoutError",
    "IPScoutPermissionError",
    "IPScoutResolutionError",
    "IPScoutUnsupportedError",
]


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
