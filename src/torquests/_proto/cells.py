"""Cell framing and the cell types used by the link handshake and circuits.

A cell is the unit a channel exchanges. Fixed-length cells carry a 509-byte body;
variable-length cells (VERSIONS and the ``>= 128`` commands) carry a 2-byte length
followed by that many bytes. The CircID is 4 bytes for link protocol 4+, except
the VERSIONS cell, which is always framed with a 2-byte CircID because it is
exchanged before a version is negotiated.

RELAY and RELAY_EARLY cells are carried as :class:`RawCell`; their 509-byte body
is (en/de)crypted and parsed one layer up, in :mod:`torquests._proto.relay`.
"""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Callable
from dataclasses import dataclass

from ..exceptions import ChannelError
from .constants import (
    CELL_PAYLOAD_LEN,
    Cell,
    is_variable_cell,
)


def circid_len(link_version: int) -> int:
    """CircID width in bytes for a negotiated link protocol version."""
    return 4 if link_version >= 4 else 2


@dataclass(frozen=True)
class RawCell:
    """A framed cell: circuit id, command, and the raw (unpadded) body bytes."""

    circ_id: int
    command: int
    payload: bytes

    def pack(self, link_version: int) -> bytes:
        """Serialize the cell for a given negotiated link version."""
        width = 2 if self.command == Cell.VERSIONS else circid_len(link_version)
        header = self.circ_id.to_bytes(width, "big") + bytes([self.command])
        if is_variable_cell(self.command):
            return header + struct.pack(">H", len(self.payload)) + self.payload
        if len(self.payload) > CELL_PAYLOAD_LEN:
            raise ValueError("fixed-cell payload exceeds 509 bytes")
        return header + self.payload.ljust(CELL_PAYLOAD_LEN, b"\x00")


def read_cell(recv_exact: Callable[[int], bytes], link_version: int) -> RawCell:
    """Read exactly one cell using ``recv_exact(n)`` to pull ``n`` bytes.

    ``link_version`` selects the CircID width; pass ``2`` (or ``0``) before a
    version has been negotiated, when only VERSIONS cells are exchanged.
    """
    width = circid_len(link_version)
    header = recv_exact(width + 1)
    circ_id = int.from_bytes(header[:width], "big")
    command = header[width]
    if is_variable_cell(command):
        (length,) = struct.unpack(">H", recv_exact(2))
        payload = recv_exact(length) if length else b""
    else:
        payload = recv_exact(CELL_PAYLOAD_LEN)
    return RawCell(circ_id, command, payload)


# --------------------------------------------------------------------------- #
# Address encoding for NETINFO
# --------------------------------------------------------------------------- #

_ATYPE_IPV4 = 0x04
_ATYPE_IPV6 = 0x06


def _encode_address(ip: str) -> bytes:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return bytes([_ATYPE_IPV4, 4]) + addr.packed
    return bytes([_ATYPE_IPV6, 16]) + addr.packed


def _decode_address(data: bytes, offset: int) -> tuple[str | None, int]:
    if offset + 2 > len(data):
        raise ChannelError("truncated NETINFO cell: address header past end of payload")
    atype = data[offset]
    alen = data[offset + 1]
    if offset + 2 + alen > len(data):
        raise ChannelError("truncated NETINFO cell: address value past end of payload")
    value = data[offset + 2 : offset + 2 + alen]
    offset += 2 + alen
    if atype == _ATYPE_IPV4 and alen == 4:
        return str(ipaddress.IPv4Address(value)), offset
    if atype == _ATYPE_IPV6 and alen == 16:
        return str(ipaddress.IPv6Address(value)), offset
    return None, offset  # unknown address type; skip it


# --------------------------------------------------------------------------- #
# Typed cells
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class VersionsCell:
    versions: tuple[int, ...]

    def to_raw(self) -> RawCell:
        payload = b"".join(struct.pack(">H", v) for v in self.versions)
        return RawCell(0, Cell.VERSIONS, payload)

    @classmethod
    def from_raw(cls, raw: RawCell) -> VersionsCell:
        count = len(raw.payload) // 2
        return cls(tuple(struct.unpack(f">{count}H", raw.payload[: count * 2])))


@dataclass(frozen=True)
class CertsCell:
    #: list of ``(cert_type, cert_bytes)``
    certs: tuple[tuple[int, bytes], ...]

    def to_raw(self, circ_id: int = 0) -> RawCell:
        body = bytes([len(self.certs)])
        for cert_type, cert in self.certs:
            body += bytes([cert_type]) + struct.pack(">H", len(cert)) + cert
        return RawCell(circ_id, Cell.CERTS, body)

    @classmethod
    def from_raw(cls, raw: RawCell) -> CertsCell:
        data = raw.payload
        if not data:
            raise ChannelError("truncated CERTS cell: empty payload")
        count = data[0]
        offset = 1
        certs: list[tuple[int, bytes]] = []
        for _ in range(count):
            if offset + 3 > len(data):
                raise ChannelError("truncated CERTS cell: certificate header past end of payload")
            cert_type = data[offset]
            (clen,) = struct.unpack(">H", data[offset + 1 : offset + 3])
            offset += 3
            if offset + clen > len(data):
                raise ChannelError("truncated CERTS cell: certificate body past end of payload")
            certs.append((cert_type, data[offset : offset + clen]))
            offset += clen
        return cls(tuple(certs))

    def by_type(self, cert_type: int) -> bytes | None:
        for t, cert in self.certs:
            if t == cert_type:
                return cert
        return None


@dataclass(frozen=True)
class NetInfoCell:
    timestamp: int
    other_address: str | None
    my_addresses: tuple[str, ...]

    def to_raw(self, circ_id: int = 0) -> RawCell:
        body = struct.pack(">I", self.timestamp)
        body += _encode_address(self.other_address) if self.other_address else bytes([0, 0])
        body += bytes([len(self.my_addresses)])
        for addr in self.my_addresses:
            body += _encode_address(addr)
        return RawCell(circ_id, Cell.NETINFO, body)

    @classmethod
    def from_raw(cls, raw: RawCell) -> NetInfoCell:
        data = raw.payload
        if len(data) < 4:
            raise ChannelError("truncated NETINFO cell: missing timestamp")
        (timestamp,) = struct.unpack(">I", data[:4])
        other, offset = _decode_address(data, 4)
        if offset >= len(data):
            raise ChannelError("truncated NETINFO cell: missing address count")
        n = data[offset]
        offset += 1
        mine: list[str] = []
        for _ in range(n):
            addr, offset = _decode_address(data, offset)
            if addr is not None:
                mine.append(addr)
        return cls(timestamp, other, tuple(mine))


@dataclass(frozen=True)
class Create2Cell:
    handshake_type: int
    handshake_data: bytes

    def to_raw(self, circ_id: int) -> RawCell:
        header = struct.pack(">HH", self.handshake_type, len(self.handshake_data))
        return RawCell(circ_id, Cell.CREATE2, header + self.handshake_data)

    @classmethod
    def from_raw(cls, raw: RawCell) -> Create2Cell:
        htype, hlen = struct.unpack(">HH", raw.payload[:4])
        return cls(htype, raw.payload[4 : 4 + hlen])


@dataclass(frozen=True)
class Created2Cell:
    handshake_data: bytes

    def to_raw(self, circ_id: int) -> RawCell:
        body = struct.pack(">H", len(self.handshake_data)) + self.handshake_data
        return RawCell(circ_id, Cell.CREATED2, body)

    @classmethod
    def from_raw(cls, raw: RawCell) -> Created2Cell:
        (hlen,) = struct.unpack(">H", raw.payload[:2])
        return cls(raw.payload[2 : 2 + hlen])


@dataclass(frozen=True)
class DestroyCell:
    reason: int = 0

    def to_raw(self, circ_id: int) -> RawCell:
        return RawCell(circ_id, Cell.DESTROY, bytes([self.reason]))

    @classmethod
    def from_raw(cls, raw: RawCell) -> DestroyCell:
        return cls(raw.payload[0] if raw.payload else 0)
