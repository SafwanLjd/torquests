"""The inner RELAY cell and its command bodies.

A decrypted relay cell is::

    RELAY_CMD(1) | Recognized(2) | StreamID(2) | Digest(4) | Length(2) | Data | Padding

The running digest is computed over this body with the digest field zeroed and
the cell padded to its full length, so :class:`RelayCell` exposes both the
digest-input form and the finished packed form. The relay command bodies
(BEGIN, DATA, EXTEND2, and so on) are separate small codecs.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field, replace
from enum import IntEnum

from ..exceptions import CircuitError
from .constants import CELL_PAYLOAD_LEN, RELAY_PAYLOAD_LEN
from .linkspec import LinkSpecifier, pack_block

_ZERO_DIGEST = b"\x00\x00\x00\x00"

#: RELAY_CMD(1) | Recognized(2) | StreamID(2) | Digest(4) | Length(2).
_RELAY_HEADER_LEN = 11


@dataclass(frozen=True)
class RelayCell:
    """A decrypted relay cell."""

    command: int
    stream_id: int
    data: bytes
    recognized: int = 0
    digest: bytes = _ZERO_DIGEST
    #: The trailing padding after the data. Excluded from equality (a cell's
    #: identity is its fields, not its random tail) and generated once in
    #: ``__post_init__`` so the digest input and the wire bytes share one tail.
    padding: bytes = field(default=b"", compare=False, repr=False)

    def __post_init__(self) -> None:
        # tor-spec (relay-cells): padding SHOULD be four zero bytes followed by
        # random bytes, so a relay cell's contents are unpredictable to the
        # terminating hop. Generate it once, here, rather than at pack() time, so a
        # cell derived via dataclasses.replace (digest_input, with_digest) copies
        # this exact tail and the running digest matches the serialized bytes.
        if self.padding:
            return
        pad_len = CELL_PAYLOAD_LEN - _RELAY_HEADER_LEN - len(self.data)
        if pad_len > 4:
            padding = _ZERO_DIGEST + os.urandom(pad_len - 4)
        else:
            padding = b"\x00" * max(pad_len, 0)
        object.__setattr__(self, "padding", padding)

    def pack(self) -> bytes:
        """Serialize to a full 509-byte body (digest field as currently set)."""
        if len(self.data) > RELAY_PAYLOAD_LEN:
            raise ValueError("relay data exceeds 498 bytes")
        header = (
            bytes([self.command])
            + struct.pack(">H", self.recognized)
            + struct.pack(">H", self.stream_id)
            + self.digest
            + struct.pack(">H", len(self.data))
        )
        # header + data + padding is already CELL_PAYLOAD_LEN; ljust is defensive.
        return (header + self.data + self.padding).ljust(CELL_PAYLOAD_LEN, b"\x00")

    def digest_input(self) -> bytes:
        """The body with the digest field zeroed, the input to the running digest."""
        return replace(self, digest=_ZERO_DIGEST).pack()

    def with_digest(self, digest4: bytes) -> RelayCell:
        return replace(self, digest=digest4)

    @classmethod
    def parse(cls, body: bytes) -> RelayCell:
        command = body[0]
        (recognized,) = struct.unpack(">H", body[1:3])
        (stream_id,) = struct.unpack(">H", body[3:5])
        digest = body[5:9]
        (length,) = struct.unpack(">H", body[9:11])
        if length > RELAY_PAYLOAD_LEN:
            # A declared length past the payload bound is a corrupt or hostile
            # relay cell. Fail with the typed circuit error the receiver path
            # already handles, not a bare ValueError that would escape untyped
            # (unwrapped by ``except TorError``) as the circuit tears down.
            raise CircuitError(f"relay cell length {length} exceeds {RELAY_PAYLOAD_LEN}")
        data = body[_RELAY_HEADER_LEN : _RELAY_HEADER_LEN + length]
        # Keep the real trailing bytes as padding rather than regenerating them; a
        # parsed cell is never re-serialized for the wire, and this avoids spending
        # entropy on the receive path.
        return cls(
            command,
            stream_id,
            data,
            recognized,
            digest,
            padding=body[_RELAY_HEADER_LEN + length :],
        )


# --------------------------------------------------------------------------- #
# Relay command bodies
# --------------------------------------------------------------------------- #


def begin_body(host: str, port: int) -> bytes:
    """RELAY_BEGIN body: ``ADDRPORT\\0`` then a 4-byte (zero) flags field.

    For an onion service the address is empty, giving ``:port``.
    """
    return f"{host}:{port}".encode() + b"\x00" + struct.pack(">I", 0)


class EndReason(IntEnum):
    """RELAY_END reason codes (tor-spec, closing-streams)."""

    MISC = 1
    RESOLVEFAILED = 2
    CONNECTREFUSED = 3
    EXITPOLICY = 4
    DESTROY = 5
    DONE = 6
    TIMEOUT = 7
    NOROUTE = 8
    HIBERNATING = 9
    INTERNAL = 10
    RESOURCELIMIT = 11
    CONNRESET = 12
    TORPROTOCOL = 13
    NOTDIRECTORY = 14


def end_body(reason: int = EndReason.DONE) -> bytes:
    return bytes([reason])


def parse_end_reason(data: bytes) -> int:
    return data[0] if data else EndReason.MISC


def extend2_body(
    link_specifiers: list[LinkSpecifier], handshake_type: int, handshake_data: bytes
) -> bytes:
    """RELAY_EXTEND2 body: link specifiers, handshake type, and handshake data."""
    return (
        pack_block(link_specifiers)
        + struct.pack(">HH", handshake_type, len(handshake_data))
        + handshake_data
    )


@dataclass(frozen=True)
class Extended2:
    """Parsed RELAY_EXTENDED2 body (identical layout to CREATED2)."""

    handshake_data: bytes

    @classmethod
    def parse(cls, data: bytes) -> Extended2:
        if len(data) < 2:
            raise CircuitError("EXTENDED2 body is too short for its length field")
        (hlen,) = struct.unpack(">H", data[:2])
        if len(data) < 2 + hlen:
            # A declared handshake longer than the body is a corrupt or hostile
            # reply on the circuit-extend path. Fail with the typed CircuitError
            # the build-retry catches, not a bare struct.error/IndexError that
            # would escape untyped as the circuit tears down.
            raise CircuitError(
                f"EXTENDED2 declares {hlen} handshake bytes but only {len(data) - 2} are present"
            )
        return cls(data[2 : 2 + hlen])


# --------------------------------------------------------------------------- #
# SENDME (authenticated v1)
# --------------------------------------------------------------------------- #


_SENDME_V1_VERSION = 1
_SENDME_DIGEST_LEN = 20


def sendme_v1_body(digest: bytes) -> bytes:
    """Authenticated SENDME v1: version(1)=1 | DATA_LEN(2)=20 | DATA(20-byte digest)."""
    if len(digest) != _SENDME_DIGEST_LEN:
        raise ValueError("authenticated SENDME digest must be 20 bytes")
    return bytes([_SENDME_V1_VERSION]) + struct.pack(">H", len(digest)) + digest


def parse_sendme_v1(body: bytes) -> bytes:
    """Return the 20-byte authenticating digest from a v1 SENDME body.

    Inverse of :func:`sendme_v1_body`. A SENDME body is VERSION(1) | DATA_LEN(2) |
    DATA(DATA_LEN); for version 1 the DATA section carries the first 20 bytes of
    the running relay digest of the DATA cell that triggered the acknowledgement
    (tor-spec, flow control / proposal 289). A version below 1 is the old
    unauthenticated format, and any truncated body is rejected, because
    authentication is mandatory (consensus ``sendme_accept_min_version=1``).
    """
    if len(body) < 3:
        raise ValueError("SENDME body too short to be authenticated")
    version = body[0]
    if version != _SENDME_V1_VERSION:
        raise ValueError(f"unauthenticated or unsupported SENDME version {version}")
    (data_len,) = struct.unpack(">H", body[1:3])
    if data_len < _SENDME_DIGEST_LEN or len(body) < 3 + data_len:
        raise ValueError("malformed authenticated SENDME body")
    return body[3 : 3 + _SENDME_DIGEST_LEN]
