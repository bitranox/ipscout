"""Reading what the OS's own DHCP client already stored, on Linux.

Contents:
    lease_for: The lease for one interface, from whichever store holds it.
    parse_networkd_lease: systemd-networkd's key/value format.
    parse_dhclient_lease: the ISC dhclient lease-block format.

Note:
    **No DHCP traffic is sent.** The client that already holds the lease wrote
    it down, so this reads a file rather than asking the network again. An
    active DHCPINFORM would need UDP port 68, which is privileged and normally
    already held by that same client, and RFC 2131 has servers reply to port
    68 rather than to the request's source port - so it works only against
    some servers even when it can bind at all.

    The parsers are pure functions over text so they can be tested without a
    DHCP lease on the machine running the tests, which a statically addressed
    host does not have.

"""

from __future__ import annotations

import contextlib
import re
import socket
from pathlib import Path

from .models import LeaseInfo

__all__ = ["lease_for", "parse_dhclient_lease", "parse_networkd_lease"]

#: systemd-networkd writes one file per interface index, world-readable.
_NETWORKD_LEASES = Path("/run/systemd/netif/leases")

#: Where the ISC client and NetworkManager keep theirs.
_DHCLIENT_PATHS = (
    Path("/var/lib/dhcp"),
    Path("/var/lib/dhclient"),
    Path("/var/lib/NetworkManager"),
)

#: A lease block, and the options inside one.
_LEASE_BLOCK = re.compile(r"lease\s*\{(.*?)\}", re.DOTALL)
_OPTION = re.compile(r"option\s+([a-z0-9-]+)\s+([^;]+);")
_INTERFACE = re.compile(r'interface\s+"([^"]+)"')
_RENEW = re.compile(r"renew\s+\d+\s+([0-9/]+\s+[0-9:]+);")
_EXPIRE = re.compile(r"expire\s+\d+\s+([0-9/]+\s+[0-9:]+);")


def _addresses(value: str) -> tuple[str, ...]:
    """Return the addresses in a space- or comma-separated list."""

    found: list[str] = []
    for piece in value.replace(",", " ").split():
        text = piece.strip()
        with contextlib.suppress(OSError, ValueError):
            socket.inet_pton(socket.AF_INET6 if ":" in text else socket.AF_INET, text)
            found.append(text)
    return tuple(found)


def parse_networkd_lease(text: str) -> LeaseInfo:
    """Decode a systemd-networkd lease file.

    Args:
        text: The file's contents, a flat ``KEY=value`` list.

    Returns:
        What the file recorded. Fields it does not mention stay unset, which
        is different from a value of zero.

    Examples:
        >>> lease = parse_networkd_lease(
        ...     "ADDRESS=192.168.1.50\\nSERVER_ADDRESS=192.168.1.1\\n"
        ...     "ROUTER=192.168.1.1\\nDNS=192.168.1.1 9.9.9.9\\nDOMAINNAME=lan\\n")
        >>> lease.dhcp_server, lease.domain
        ('192.168.1.1', 'lan')
        >>> lease.dns_servers
        ('192.168.1.1', '9.9.9.9')

    """

    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip().upper()] = value.strip()

    return LeaseInfo(
        dhcp_server=values.get("SERVER_ADDRESS") or None,
        router=values.get("ROUTER") or None,
        dns_servers=_addresses(values.get("DNS", "")),
        domain=values.get("DOMAINNAME") or None,
        obtained=values.get("T1") or None,
        expires=values.get("LIFETIME") or None,
    )


def parse_dhclient_lease(text: str, interface: str | None = None) -> LeaseInfo:
    """Decode an ISC dhclient lease file.

    Args:
        text: The file's contents, one or more ``lease { ... }`` blocks.
        interface: Only consider blocks for this interface, when given.

    Returns:
        The most recent matching lease. The file is append-only, so the last
        block is the current one and the earlier ones are history.

    Examples:
        >>> lease = parse_dhclient_lease('''
        ...   lease {
        ...     interface "eth0";
        ...     option dhcp-server-identifier 192.168.1.1;
        ...     option domain-name-servers 192.168.1.1,9.9.9.9;
        ...     option domain-name "lan";
        ...     expire 2 2026/07/29 10:00:00;
        ...   }
        ... ''')
        >>> lease.dhcp_server, lease.domain, lease.expires
        ('192.168.1.1', 'lan', '2026/07/29 10:00:00')

    """

    latest = LeaseInfo()
    for block in _LEASE_BLOCK.findall(text):
        name = _INTERFACE.search(block)
        if interface is not None and name is not None and name.group(1) != interface:
            continue

        options = {key: value.strip() for key, value in _OPTION.findall(block)}
        renew = _RENEW.search(block)
        expire = _EXPIRE.search(block)
        latest = LeaseInfo(
            dhcp_server=options.get("dhcp-server-identifier"),
            router=options.get("routers", "").split(",")[0].strip() or None,
            dns_servers=_addresses(options.get("domain-name-servers", "")),
            domain=options.get("domain-name", "").strip('"') or None,
            obtained=renew.group(1) if renew else None,
            expires=expire.group(1) if expire else None,
        )
    return latest


def _read(path: Path) -> str | None:
    """Return a file's text, or None when it cannot be read."""

    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        # Not present, or not readable by this user: both mean no lease data
        # from this store, which is not an error.
        return None


def lease_for(interface: str) -> LeaseInfo:
    """Return what this host's DHCP client recorded for one interface.

    Args:
        interface: The interface name.

    Returns:
        The lease, or an empty record when nothing is stored - which is the
        normal case for a statically addressed interface.

    Note:
        Tries systemd-networkd first, since its files are world-readable and
        indexed by interface, then the dhclient and NetworkManager stores.

    Examples:
        >>> isinstance(lease_for("lo").dns_servers, tuple)
        True

    """

    with contextlib.suppress(OSError, ValueError):
        index = socket.if_nametoindex(interface)
        text = _read(_NETWORKD_LEASES / str(index))
        if text:
            return parse_networkd_lease(text)

    for directory in _DHCLIENT_PATHS:
        with contextlib.suppress(OSError):
            if not directory.is_dir():
                continue
            for path in sorted(directory.glob("*lease*")):
                text = _read(path)
                if text and "lease" in text:
                    lease = parse_dhclient_lease(text, interface)
                    if lease.dhcp_server or lease.dns_servers:
                        return lease
    return LeaseInfo()
