"""A scripted SNMP agent on a loopback UDP port, for tests that need a real socket.

The script decides what to send back for each request, so a test can produce
exactly the reply it is about: a normal answer, an error status, a reply to
another request, garbage, or silence.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

from ipscout.snmpber import (
    GET_RESPONSE,
    NO_SUCH_OBJECT,
    OBJECT_IDENTIFIER,
    OCTET_STRING,
    TIMETICKS,
    SnmpMessage,
    VarBind,
    encode_message,
    encode_oid,
    parse_message,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

DESCRIPTION, OBJECT_ID, UPTIME, NAME = "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"

SYSTEM: dict[str, tuple[int, bytes]] = {
    DESCRIPTION: (OCTET_STRING, b"A print server"),
    OBJECT_ID: (OBJECT_IDENTIFIER, encode_oid("1.3.6.1.4.1.11.2.3.9.1")),
    UPTIME: (TIMETICKS, (12345).to_bytes(2, "big")),
    NAME: (OCTET_STRING, b"PRINTER"),
}

#: SNMPv1 error status for an OID the agent does not know (RFC 1157).
NO_SUCH_NAME = 2

#: Given a request, the datagrams to send back; an empty list stays silent.
Script = Callable[[SnmpMessage], list[bytes]]


def answer(
    request: SnmpMessage,
    values: Mapping[str, tuple[int, bytes]] = SYSTEM,
    *,
    error_status: int = 0,
    error_index: int = 0,
    version: int | None = None,
    request_id: int | None = None,
    pdu_tag: int = GET_RESPONSE,
    oids: list[str] | None = None,
) -> bytes:
    """Return a reply to ``request`` binding each OID it asked for (or ``oids``) to ``values``."""

    names = oids if oids is not None else [binding.oid for binding in request.bindings]
    bindings = tuple(VarBind(oid=oid, tag=values[oid][0], value=values[oid][1]) for oid in names)
    return encode_message(
        SnmpMessage(
            version=request.version if version is None else version,
            community=request.community,
            pdu_tag=pdu_tag,
            request_id=request.request_id if request_id is None else request_id,
            error_status=error_status,
            error_index=error_index,
            bindings=bindings,
        )
    )


def honest(values: Mapping[str, tuple[int, bytes]] = SYSTEM) -> Script:
    """Return a script that behaves like a real agent holding ``values``."""

    def script(request: SnmpMessage) -> list[bytes]:
        names = [binding.oid for binding in request.bindings]
        missing = [index for index, oid in enumerate(names, start=1) if oid not in values]
        if request.version == 0 and missing:
            return [answer(request, dict.fromkeys(names, (OCTET_STRING, b"")), error_status=NO_SUCH_NAME, error_index=missing[0])]
        known = {oid: values.get(oid, (NO_SUCH_OBJECT, b"")) for oid in names}
        return [answer(request, known)]

    return script


class FakeAgent:
    """Answer SNMP requests on a loopback UDP port from a script, in a thread."""

    def __init__(self, script: Script, *, host: str = "127.0.0.1") -> None:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._socket = socket.socket(family, socket.SOCK_DGRAM)
        self._socket.bind((host, 0))
        self._socket.settimeout(0.05)
        self.port: int = self._socket.getsockname()[1]
        self.requests: list[SnmpMessage] = []
        self._script = script
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> FakeAgent:
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stop.set()
        self._thread.join(timeout=5.0)
        self._socket.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, sender = self._socket.recvfrom(65535)
            except TimeoutError:
                continue
            request = parse_message(data)
            self.requests.append(request)
            for reply in self._script(request):
                self._socket.sendto(reply, sender)
