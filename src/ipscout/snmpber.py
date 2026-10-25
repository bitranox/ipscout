"""SNMP messages in BER (ITU-T X.690): what a GET of a few scalar values needs, no more.

Contents:
    encode_get_request / encode_message: The bytes of one message.
    parse_message: A message taken apart by structure.
    encode_oid / decode_oid: Object identifiers between dotted text and BER.
    SnmpMessage, VarBind: What a message says.
    BerError: Bytes that are not a well-formed SNMP message.

Note:
    A reply is walked element by element and never searched for a tag byte,
    so a community string or request id that happens to contain a value's tag
    cannot be mistaken for the value. Every element must end inside its parent,
    and indefinite lengths are refused: SNMP never sends them.

"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "END_OF_MIB_VIEW",
    "EXCEPTION_TAGS",
    "GET_REQUEST",
    "GET_RESPONSE",
    "INTEGER",
    "NO_SUCH_INSTANCE",
    "NO_SUCH_OBJECT",
    "NULL",
    "OBJECT_IDENTIFIER",
    "OCTET_STRING",
    "SEQUENCE",
    "TIMETICKS",
    "BerError",
    "SnmpMessage",
    "VarBind",
    "decode_oid",
    "encode_get_request",
    "encode_message",
    "encode_oid",
    "parse_message",
]

SEQUENCE: Final = 0x30
INTEGER: Final = 0x02
OCTET_STRING: Final = 0x04
NULL: Final = 0x05
OBJECT_IDENTIFIER: Final = 0x06
#: Application tag 3: an unsigned 32-bit count of hundredths of a second (RFC 2578).
TIMETICKS: Final = 0x43
GET_REQUEST: Final = 0xA0
GET_RESPONSE: Final = 0xA2
#: SNMPv2c sends one of these in place of a value the agent does not have (RFC 3416).
NO_SUCH_OBJECT: Final = 0x80
NO_SUCH_INSTANCE: Final = 0x81
END_OF_MIB_VIEW: Final = 0x82
EXCEPTION_TAGS: Final = frozenset({NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW})

#: A length octet at or above this is the long form: its low bits count the length octets.
_LONG_FORM: Final = 0x80
#: Four length octets already describe more than any UDP datagram can carry.
_MAX_LENGTH_OCTETS: Final = 4
#: A request id, version or error field fits a signed 32-bit INTEGER, so 5 octets at most.
_MAX_INTEGER_OCTETS: Final = 5
#: X.660: the first two arcs share one sub-identifier, 40 * first + second, because the roots
#: 0 and 1 hold at most 40 children each; root 2 is the last and has no such limit.
_ARCS_PER_ROOT: Final = 40
_LAST_ROOT_ARC: Final = 2
#: SMI (RFC 2578, 3.5): an identifier has at most 128 arcs, each at most 2**32-1. Enforced on
#: the way in so a hostile agent cannot make the reader build an unbounded integer, which is
#: quadratic to accumulate and whose str() raises a plain ValueError past 4300 digits.
_MAX_ARCS: Final = 128
_MAX_ARC: Final = 2**32 - 1
#: The first encoded sub-identifier carries two arcs, so under root 2 it may exceed _MAX_ARC.
_MAX_FIRST_SUB_IDENTIFIER: Final = _ARCS_PER_ROOT * _LAST_ROOT_ARC + _MAX_ARC
#: Dotted text: at least two arcs, each a run of ASCII digits.
_DOTTED: Final = re.compile(r"[0-9]{1,10}(?:\.[0-9]{1,10})+")


class BerError(ValueError):
    """Bytes that are not well-formed BER, or not the SNMP message they claim to be."""


class VarBind(BaseModel):
    """One variable binding: an object identifier and the value element that follows it.

    ``tag`` and ``value`` are the raw element: interpreting them is the
    caller's job, since only the caller knows which type each OID must have.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    oid: str
    tag: int
    value: bytes


class SnmpMessage(BaseModel):
    """An SNMPv1 or v2c message with one PDU, as sent or as received."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    #: 0 for SNMPv1, 1 for SNMPv2c.
    version: int
    community: bytes
    pdu_tag: int
    request_id: int
    error_status: int
    error_index: int
    bindings: tuple[VarBind, ...]


def _length(size: int) -> bytes:
    if size < _LONG_FORM:
        return bytes([size])
    octets = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([_LONG_FORM | len(octets)]) + octets


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _length(len(body)) + body


def _integer(value: int) -> bytes:
    # One sign bit more than the magnitude needs: the minimal two's complement form. A negative
    # value's magnitude is that of its complement (-128 needs the 7 bits of 127), else -128
    # would take a needless 0xff octet.
    magnitude = ~value if value < 0 else value
    return _tlv(INTEGER, value.to_bytes(magnitude.bit_length() // 8 + 1, "big", signed=True))


def _base128(number: int) -> bytes:
    octets = [number & 0x7F]
    number >>= 7
    while number:
        octets.append(_LONG_FORM | (number & 0x7F))
        number >>= 7
    return bytes(reversed(octets))


def encode_oid(dotted: str) -> bytes:
    """Return the BER body of an object identifier written as dotted text.

    Args:
        dotted: Such as ``"1.3.6.1.2.1.1.3.0"``.

    Returns:
        The identifier's content octets, without tag or length.

    Raises:
        ValueError: The text is not an object identifier: fewer than two or
            more than 128 arcs, a non-digit, an arc above 2**32-1, a first arc
            above 2, or a second arc above 39 under a first arc of 0 or 1.

    Examples:
        >>> encode_oid("1.3.6.1.2.1.1.3.0").hex()
        '2b06010201010300'

    """

    if not _DOTTED.fullmatch(dotted):
        msg = f"not an object identifier: {dotted!r}"
        raise ValueError(msg)
    arcs = [int(arc) for arc in dotted.split(".")]
    first, second, *rest = arcs
    beyond_smi = len(arcs) > _MAX_ARCS or max(arcs) > _MAX_ARC
    if beyond_smi or first > _LAST_ROOT_ARC or (first < _LAST_ROOT_ARC and second >= _ARCS_PER_ROOT):
        msg = f"not an object identifier: {dotted!r}"
        raise ValueError(msg)
    return _base128(_ARCS_PER_ROOT * first + second) + b"".join(_base128(arc) for arc in rest)


def decode_oid(body: bytes) -> str:
    """Return an object identifier's BER body as dotted text.

    Args:
        body: The content octets of an OBJECT IDENTIFIER element.

    Returns:
        Dotted text, such as ``"1.3.6.1.4.1.11.2.3.9.1"``.

    Raises:
        BerError: The body is empty, ends inside a sub-identifier, starts one
            with the padding octet 0x80, which BER forbids, or goes past what
            SMI allows: more than 128 arcs, or an arc above 2**32-1.

    Examples:
        >>> decode_oid(bytes.fromhex("2b06010201010300"))
        '1.3.6.1.2.1.1.3.0'

    """

    if not body:
        msg = "empty object identifier"
        raise BerError(msg)
    if body[-1] & _LONG_FORM:
        msg = "object identifier ends inside a sub-identifier"
        raise BerError(msg)
    numbers = _sub_identifiers(body)
    head = min(numbers[0] // _ARCS_PER_ROOT, _LAST_ROOT_ARC)
    return ".".join(str(arc) for arc in [head, numbers[0] - _ARCS_PER_ROOT * head, *numbers[1:]])


def _sub_identifiers(body: bytes) -> list[int]:
    """Return the encoded sub-identifiers of an identifier body, refusing any SMI does not allow."""

    numbers: list[int] = []
    current, starting = 0, True
    for octet in body:
        if starting and octet == _LONG_FORM:
            msg = "object identifier sub-identifier has a leading 0x80"
            raise BerError(msg)
        current = (current << 7) | (octet & 0x7F)
        # Checked per octet, so a hostile run of continuation octets stops at the bound.
        if current > (_MAX_ARC if numbers else _MAX_FIRST_SUB_IDENTIFIER):
            msg = "object identifier arc exceeds 2**32-1"
            raise BerError(msg)
        starting = not octet & _LONG_FORM
        if starting:
            numbers.append(current)
            current = 0
    # The first encoded sub-identifier holds two arcs.
    if len(numbers) + 1 > _MAX_ARCS:
        msg = f"object identifier of {len(numbers) + 1} arcs, more than {_MAX_ARCS}"
        raise BerError(msg)
    return numbers


def encode_message(message: SnmpMessage) -> bytes:
    """Return the bytes of one message.

    Args:
        message: What to send. Its integers must be non-negative.

    Returns:
        The complete BER message.

    """

    bindings = b"".join(_tlv(SEQUENCE, _tlv(OBJECT_IDENTIFIER, encode_oid(bind.oid)) + _tlv(bind.tag, bind.value)) for bind in message.bindings)
    pdu = _tlv(message.pdu_tag, _integer(message.request_id) + _integer(message.error_status) + _integer(message.error_index) + _tlv(SEQUENCE, bindings))
    return _tlv(SEQUENCE, _integer(message.version) + _tlv(OCTET_STRING, message.community) + pdu)


def encode_get_request(*, version: int, community: bytes, request_id: int, oids: Sequence[str]) -> bytes:
    """Return a GetRequest asking for ``oids``, each bound to NULL as the protocol requires.

    Args:
        version: 0 for SNMPv1, 1 for SNMPv2c.
        community: The read community, as bytes.
        request_id: A positive id the reply must echo.
        oids: The object identifiers to read, in dotted text.

    Returns:
        The complete BER message.

    Examples:
        >>> encode_get_request(version=0, community=b"public", request_id=1, oids=["1.3.6.1.2.1.1.3.0"]).hex()[:8]
        '30260201'

    """

    bindings = tuple(VarBind(oid=oid, tag=NULL, value=b"") for oid in oids)
    return encode_message(
        SnmpMessage(version=version, community=community, pdu_tag=GET_REQUEST, request_id=request_id, error_status=0, error_index=0, bindings=bindings)
    )


class _Reader:
    """Walks the BER elements of one byte string in order, refusing anything malformed."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._position = 0

    def at_end(self) -> bool:
        return self._position == len(self._data)

    def next(self) -> tuple[int, bytes]:
        """Return the next element's tag and content octets."""

        data, start = self._data, self._position + 2
        if start > len(data):
            msg = "element header runs past the end"
            raise BerError(msg)
        tag, size = data[self._position], data[self._position + 1]
        if size & _LONG_FORM:
            size, start = self._long_length(size & 0x7F, start)
        end = start + size
        if end > len(data):
            msg = "element runs past the end of its parent"
            raise BerError(msg)
        self._position = end
        return tag, data[start:end]

    def _long_length(self, octets: int, start: int) -> tuple[int, int]:
        if octets == 0:
            msg = "indefinite length, which SNMP never sends"
            raise BerError(msg)
        if octets > _MAX_LENGTH_OCTETS:
            msg = f"length field of {octets} octets"
            raise BerError(msg)
        if start + octets > len(self._data):
            msg = "length field runs past the end"
            raise BerError(msg)
        return int.from_bytes(self._data[start : start + octets], "big"), start + octets

    def expect(self, tag: int, what: str) -> bytes:
        """Return the next element's content, which must carry ``tag``."""

        if self.at_end():
            msg = f"{what}: missing"
            raise BerError(msg)
        found, body = self.next()
        if found != tag:
            msg = f"{what}: expected tag 0x{tag:02x}, found 0x{found:02x}"
            raise BerError(msg)
        return body

    def integer(self, what: str) -> int:
        body = self.expect(INTEGER, what)
        if not 1 <= len(body) <= _MAX_INTEGER_OCTETS:
            msg = f"{what}: an INTEGER of {len(body)} octets"
            raise BerError(msg)
        return int.from_bytes(body, "big", signed=True)

    def finish(self, what: str) -> None:
        if not self.at_end():
            msg = f"bytes after the {what}"
            raise BerError(msg)


def _bindings(body: bytes) -> tuple[VarBind, ...]:
    reader = _Reader(body)
    found: list[VarBind] = []
    while not reader.at_end():
        binding = _Reader(reader.expect(SEQUENCE, "variable binding"))
        oid = decode_oid(binding.expect(OBJECT_IDENTIFIER, "variable binding name"))
        tag, value = binding.next()
        if not binding.at_end():
            msg = "a variable binding holds more than a name and a value"
            raise BerError(msg)
        found.append(VarBind(oid=oid, tag=tag, value=value))
    return tuple(found)


def parse_message(data: bytes) -> SnmpMessage:
    """Return an SNMP message taken apart element by element.

    Args:
        data: One datagram's payload.

    Returns:
        The message. Its PDU type, version and request id are reported, not
        checked: whether they are the ones expected is the caller's question.

    Raises:
        BerError: The bytes are not one well-formed SNMP message.

    """

    outer = _Reader(data)
    message = _Reader(outer.expect(SEQUENCE, "message"))
    outer.finish("message")
    version = message.integer("version")
    community = message.expect(OCTET_STRING, "community")
    if message.at_end():
        msg = "pdu: missing"
        raise BerError(msg)
    pdu_tag, pdu_body = message.next()
    message.finish("pdu")
    pdu = _Reader(pdu_body)
    request_id, error_status, error_index = pdu.integer("request id"), pdu.integer("error status"), pdu.integer("error index")
    bindings = _bindings(pdu.expect(SEQUENCE, "variable bindings"))
    pdu.finish("variable bindings")
    return SnmpMessage(
        version=version, community=community, pdu_tag=pdu_tag, request_id=request_id, error_status=error_status, error_index=error_index, bindings=bindings
    )
