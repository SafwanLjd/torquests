"""Protocol constants: command numbers, sizes, and identifier strings.

Values are from the Tor protocol specification (``tor-spec``) and the v3 onion
rendezvous specification (``rend-spec``).
"""

from __future__ import annotations

from enum import IntEnum

# --- Cell geometry --------------------------------------------------------- #

#: Fixed-cell payload size, in bytes.
CELL_PAYLOAD_LEN = 509

#: Link protocol versions this client advertises. v3 (2-byte CircID) is dropped;
#: every live relay offers 4 or 5.
SUPPORTED_LINK_VERSIONS = (4, 5)

#: Client-set MSB on locally-originated circuit ids (per tor-spec).
CIRCID_MSB = 0x8000_0000


class Cell(IntEnum):
    """Cell command numbers."""

    PADDING = 0
    CREATE = 1
    CREATED = 2
    RELAY = 3
    DESTROY = 4
    CREATE_FAST = 5
    CREATED_FAST = 6
    VERSIONS = 7  # variable-length despite being < 128
    NETINFO = 8
    RELAY_EARLY = 9
    CREATE2 = 10
    CREATED2 = 11
    PADDING_NEGOTIATE = 12
    VPADDING = 128
    CERTS = 129
    AUTH_CHALLENGE = 130
    AUTHENTICATE = 131
    AUTHORIZE = 132


def is_variable_cell(command: int) -> bool:
    """Return whether a cell command carries a variable-length body."""
    return command >= 128 or command == Cell.VERSIONS


class Relay(IntEnum):
    """Relay command numbers (the command inside a RELAY cell)."""

    BEGIN = 1
    DATA = 2
    END = 3
    CONNECTED = 4
    SENDME = 5
    EXTEND = 6
    EXTENDED = 7
    TRUNCATE = 8
    TRUNCATED = 9
    DROP = 10
    RESOLVE = 11
    RESOLVED = 12
    BEGIN_DIR = 13
    EXTEND2 = 14
    EXTENDED2 = 15
    # v3 onion-service relay commands
    ESTABLISH_INTRO = 32
    ESTABLISH_RENDEZVOUS = 33
    INTRODUCE1 = 34
    INTRODUCE2 = 35
    RENDEZVOUS1 = 36
    RENDEZVOUS2 = 37
    INTRO_ESTABLISHED = 38
    RENDEZVOUS_ESTABLISHED = 39
    INTRODUCE_ACK = 40


class LinkSpecType(IntEnum):
    """Link specifier types used in EXTEND2 and introduction points."""

    IPV4 = 0x00
    IPV6 = 0x01
    LEGACY_ID = 0x02  # 20-byte RSA identity digest
    ED25519_ID = 0x03  # 32-byte ed25519 identity


class HandshakeType(IntEnum):
    """CREATE2/EXTEND2 handshake types."""

    TAP = 0x0000
    NTOR = 0x0002
    NTOR_V3 = 0x0003


# --- Relay-cell geometry --------------------------------------------------- #

#: RELAY cell fixed header: command(1) + recognized(2) + stream_id(2) + digest(4) + length(2).
RELAY_HEADER_LEN = 11

#: Maximum application payload in a single RELAY cell.
RELAY_PAYLOAD_LEN = CELL_PAYLOAD_LEN - RELAY_HEADER_LEN  # 498


# --- Flow control ---------------------------------------------------------- #

CIRCUIT_WINDOW_INITIAL = 1000
CIRCUIT_WINDOW_INCREMENT = 100
STREAM_WINDOW_INITIAL = 500
STREAM_WINDOW_INCREMENT = 50


# --- Handshake identifier strings ------------------------------------------ #

NTOR_PROTOID = b"ntor-curve25519-sha256-1"
HS_NTOR_PROTOID = b"tor-hs-ntor-curve25519-sha3-256-1"


# --- Certificate types (cert-spec) ----------------------------------------- #


class CertType(IntEnum):
    """Tor ed25519 certificate types."""

    SIGNING_V_TLS = 0x05  # signing key -> TLS cert digest (link handshake)
    IDENTITY_V_SIGNING = 0x04  # ed25519 identity -> signing key (link handshake)
    HS_DESC_SIGNING = 0x08  # blinded key -> descriptor signing key
    HS_IP_AUTH = 0x09  # descriptor signing -> intro-point auth key
    HS_IP_ENC = 0x0B  # descriptor signing -> intro-point encryption key
