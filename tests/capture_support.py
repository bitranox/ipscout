"""Pick an interface the running platform can actually open a capture on.

The two backends name their target differently and there is no spelling that
works on both: ``lo`` is a POSIX device name, while ``SIO_RCVALL`` binds to an
address and Windows adapters are called things like ``Ethernet 4``. A test that
hardcodes either one passes on its own platform and fails on the other, which
is exactly what happened the first time the Windows backend reached CI.
"""

from __future__ import annotations

import sys

from ipscout import local_interfaces


def capture_interface() -> str | None:
    """Return something ``observe_dhcp`` can watch here, or None if nothing is.

    Returns:
        On POSIX the loopback device, which exists everywhere and carries no
        DHCP, so a test naming it never sniffs the developer's real network.
        On Windows the address of the first non-loopback adapter, because
        ``SIO_RCVALL`` binds to an address and is refused on the loopback
        pseudo-interface. ``None`` when this host offers neither, which a
        caller should treat as "skip" rather than as a failure.

    Note:
        Deliberately not ``socket.gethostbyname(socket.gethostname())``: on a
        host running a VPN that resolves to the tunnel's address rather than to
        the adapter a caller means, measured as 100.94.168.106 on a box whose
        LAN address was 192.168.168.139.

    """

    if sys.platform != "win32":
        return "lo"
    for interface in local_interfaces():
        if interface.ipv4 and not interface.is_loopback:
            return interface.ipv4[0].address
    return None
