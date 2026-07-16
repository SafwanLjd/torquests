"""Decoding a fetched v3 onion-service descriptor.

A v3 descriptor is a signed, doubly-encrypted document. Decoding it means, in
order:

1. Parse the plaintext *outer* wrapper and authenticate it: the
   ``descriptor-signing-key-cert`` (a type-08 ed25519 certificate) must be
   signed by the blinded public key the client used to fetch, and carry that
   same key in its signing-key extension; the trailing ``signature`` line must
   verify under the descriptor signing key the cert certifies.
2. Decrypt the *superencrypted* (first) layer.
3. From that plaintext, take the *encrypted* (second) layer and decrypt it,
   optionally with a client-authorization descriptor cookie.
4. Parse the innermost plaintext into introduction points.

Both encrypted layers use the same scheme: a SHAKE256 KDF keyed by a secret
input, an AES-256-CTR body, and a SHA3-256 MAC that is checked before
decryption. The two layers differ only in a per-layer secret-data value and
string constant.

Reference: Tor rendezvous specification v3, "Onion service descriptors" and the
descriptor encryption/encoding sections.
"""

from __future__ import annotations

import base64
import binascii
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone

from .._crypto.primitives import aes_ctr, const_time_eq, ed25519_verify, sha3_256, shake256, x25519
from .._proto.certs import Ed25519Certificate
from .._proto.constants import CertType
from .._proto.linkspec import LinkSpecifier, parse_block
from ..exceptions import DescriptorError, OnionClientAuthRequired

#: Prepended (unhashed) to the message before verifying the outer signature.
_SIG_PREFIX = b"Tor onion service descriptor sig v3"

#: Per-layer KDF string constants.
_SUPERENCRYPTED_CONSTANT = b"hsdir-superencrypted-data"
_ENCRYPTED_CONSTANT = b"hsdir-encrypted-data"

#: Encrypted-layer field sizes, in bytes.
_SALT_LEN = 16
_MAC_LEN = 32
_S_KEY_LEN = 32
_S_IV_LEN = 16
_MAC_KEY_LEN = 32
_KDF_OUTPUT_LEN = _S_KEY_LEN + _S_IV_LEN + _MAC_KEY_LEN

#: Length of the client-authorization descriptor cookie.
_DESCRIPTOR_COOKIE_LEN = 16

_OUTER_FIELDS = frozenset(
    {
        "hs-descriptor",
        "descriptor-lifetime",
        "descriptor-signing-key-cert",
        "revision-counter",
        "superencrypted",
        "signature",
    }
)


@dataclass(frozen=True)
class IntroPoint:
    """One introduction point from a decrypted descriptor."""

    link_specifiers: list[LinkSpecifier]  #: how to reach the intro-point relay
    onion_key: bytes  #: the relay's ntor onion key (curve25519) for EXTEND2
    auth_key: bytes  #: KP_hs_ipt_sid, the intro-point auth key (ed25519)
    enc_key: bytes  #: KP_hss_ntor, the service's ntor key (curve25519)


@dataclass(frozen=True)
class HsDescriptor:
    """A decoded and authenticated v3 onion-service descriptor."""

    lifetime: int  #: descriptor lifetime, in minutes
    revision_counter: int  #: monotonic revision counter
    intro_points: list[IntroPoint]


@dataclass(frozen=True)
class _AuthClient:
    """One ``auth-client`` entry from the first-layer plaintext."""

    client_id: bytes
    iv: bytes
    encrypted_cookie: bytes


@dataclass(frozen=True)
class _OuterDescriptor:
    """The authenticated fields of the outer wrapper."""

    lifetime: int
    revision_counter: int
    desc_signing_key: bytes
    superencrypted_blob: bytes


# --------------------------------------------------------------------------- #
# Low-level parsing helpers
# --------------------------------------------------------------------------- #


def _b64decode(data: str) -> bytes:
    """Decode base64 that may be multi-line and may lack ``=`` padding."""
    compact = "".join(data.split())
    padded = compact + "=" * (-len(compact) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DescriptorError(f"invalid base64 in descriptor: {exc}") from exc


def _iter_items(text: str) -> Iterator[tuple[str, list[str], bytes | None]]:
    """Yield ``(keyword, args, object_bytes)`` for each meta-format entry.

    A keyword line is optionally followed by a ``-----BEGIN X-----`` /
    ``-----END X-----`` base64 object, which is decoded and attached to that
    keyword. Blank lines are ignored; a missing final newline is tolerated.
    """
    lines = text.split("\n")
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        i += 1
        if not line:
            continue
        parts = line.split(" ")
        keyword, args = parts[0], parts[1:]
        obj: bytes | None = None
        if i < n and lines[i].startswith("-----BEGIN "):
            i += 1
            body: list[str] = []
            while i < n and not lines[i].startswith("-----END "):
                body.append(lines[i])
                i += 1
            if i >= n:
                raise DescriptorError("unterminated object in descriptor")
            i += 1  # consume the END line
            obj = _b64decode("".join(body))
        yield keyword, args, obj


def _decode_plaintext(data: bytes) -> str:
    """Decode a decrypted layer to text, failing loudly on non-text bytes."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DescriptorError("decrypted descriptor layer is not valid text") from exc


def _parse_cert(blob: bytes | None, field: str) -> Ed25519Certificate:
    """Parse an ed25519 certificate object, converting errors to descriptor errors."""
    if blob is None:
        raise DescriptorError(f"{field} is missing its certificate object")
    try:
        return Ed25519Certificate.parse(blob)
    except ValueError as exc:
        raise DescriptorError(f"malformed {field} certificate: {exc}") from exc


# --------------------------------------------------------------------------- #
# Two-layer decryption
# --------------------------------------------------------------------------- #


def _decrypt_layer(
    blob: bytes,
    *,
    secret_data: bytes,
    string_constant: bytes,
    subcredential: bytes,
    revision_counter: int,
) -> bytes | None:
    """Verify a layer's MAC and decrypt it, or return ``None`` on MAC failure.

    The blob is ``SALT(16) | ENCRYPTED | MAC(32)``. Keys come from
    ``SHAKE256(SECRET_DATA | subcredential | INT_8(revision) | SALT |
    STRING_CONSTANT)``; the MAC is ``SHA3-256(INT_8(32) | MAC_KEY | INT_8(16) |
    SALT | ENCRYPTED)``. The plaintext is truncated at the first NUL.
    """
    if len(blob) < _SALT_LEN + 1 + _MAC_LEN:
        return None
    salt = blob[:_SALT_LEN]
    mac = blob[-_MAC_LEN:]
    encrypted = blob[_SALT_LEN:-_MAC_LEN]

    secret_input = secret_data + subcredential + struct.pack(">Q", revision_counter)
    keys = shake256(secret_input + salt + string_constant, _KDF_OUTPUT_LEN)
    s_key = keys[:_S_KEY_LEN]
    s_iv = keys[_S_KEY_LEN : _S_KEY_LEN + _S_IV_LEN]
    mac_key = keys[_S_KEY_LEN + _S_IV_LEN :]

    expected_mac = sha3_256(
        struct.pack(">Q", len(mac_key)) + mac_key + struct.pack(">Q", len(salt)) + salt + encrypted
    )
    if not const_time_eq(expected_mac, mac):
        return None

    plaintext = aes_ctr(s_key, s_iv, encrypted)
    nul = plaintext.find(b"\x00")
    return plaintext if nul == -1 else plaintext[:nul]


# --------------------------------------------------------------------------- #
# Outer wrapper
# --------------------------------------------------------------------------- #


def _resolve_now(now: datetime | None) -> datetime:
    """Resolve an optional ``now`` to a timezone-aware moment, as elsewhere."""
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be a timezone-aware datetime")
    return now


def _parse_and_verify_outer(text: str, blinded_pubkey: bytes, now: datetime) -> _OuterDescriptor:
    """Parse the outer wrapper and verify its certificate and signature."""
    fields: dict[str, tuple[list[str], bytes | None]] = {}
    for keyword, args, obj in _iter_items(text):
        if keyword in _OUTER_FIELDS and keyword not in fields:
            fields[keyword] = (args, obj)

    missing = _OUTER_FIELDS - fields.keys()
    if missing:
        raise DescriptorError(f"descriptor is missing fields: {', '.join(sorted(missing))}")

    version_args = fields["hs-descriptor"][0]
    if version_args[:1] != ["3"]:
        raise DescriptorError("not a version 3 hs-descriptor")

    try:
        lifetime = int(fields["descriptor-lifetime"][0][0])
        revision_counter = int(fields["revision-counter"][0][0])
    except (IndexError, ValueError) as exc:
        raise DescriptorError(f"malformed integer field: {exc}") from exc

    cert = _parse_cert(fields["descriptor-signing-key-cert"][1], "descriptor-signing-key-cert")
    if cert.cert_type != CertType.HS_DESC_SIGNING:
        raise DescriptorError(
            f"descriptor-signing-key-cert has type {cert.cert_type:#x}, expected 0x08"
        )
    # Reject an expired signing-key cert: a valid signature on a stale descriptor
    # would otherwise let a malicious HSDir replay an old (validly-signed) document.
    if cert.is_expired(now.timestamp()):
        raise DescriptorError("descriptor-signing-key-cert has expired")
    if cert.signing_key != blinded_pubkey:
        raise DescriptorError("descriptor-signing-key-cert not signed by the expected blinded key")
    if not cert.verify(blinded_pubkey):
        raise DescriptorError("descriptor-signing-key-cert signature is invalid")
    desc_signing_key = cert.certified_key

    superencrypted_blob = fields["superencrypted"][1]
    if superencrypted_blob is None:
        raise DescriptorError("superencrypted field is missing its message object")

    signature_args = fields["signature"][0]
    if not signature_args:
        raise DescriptorError("signature field is empty")
    signature = _b64decode(signature_args[0])

    raw = text.encode("utf-8")
    marker = raw.find(b"\nsignature ")
    if marker == -1:
        raise DescriptorError("could not locate the signature line")
    signed_region = raw[: marker + 1]
    if not ed25519_verify(desc_signing_key, signature, _SIG_PREFIX + signed_region):
        raise DescriptorError("outer descriptor signature is invalid")

    return _OuterDescriptor(lifetime, revision_counter, desc_signing_key, superencrypted_blob)


def _parse_first_layer(text: str) -> tuple[bytes | None, list[_AuthClient], bytes]:
    """Parse the first-layer plaintext into (ephemeral key, auth clients, blob)."""
    ephemeral_key: bytes | None = None
    auth_clients: list[_AuthClient] = []
    encrypted_blob: bytes | None = None
    for keyword, args, obj in _iter_items(text):
        if keyword == "desc-auth-ephemeral-key" and args:
            ephemeral_key = _b64decode(args[0])
        elif keyword == "auth-client" and len(args) >= 3:
            auth_clients.append(
                _AuthClient(_b64decode(args[0]), _b64decode(args[1]), _b64decode(args[2]))
            )
        elif keyword == "encrypted" and obj is not None:
            encrypted_blob = obj
    if encrypted_blob is None:
        raise DescriptorError("first descriptor layer has no encrypted section")
    return ephemeral_key, auth_clients, encrypted_blob


# --------------------------------------------------------------------------- #
# Inner (intro-point) plaintext
# --------------------------------------------------------------------------- #


def _finalize_intro_point(fields: dict[str, object], desc_signing_key: bytes) -> IntroPoint:
    """Validate one intro point's collected fields and build an IntroPoint."""
    link_spec_b64 = fields.get("link_specifiers")
    onion_key = fields.get("onion_key")
    enc_key = fields.get("enc_key")
    auth_cert_blob = fields.get("auth_cert")
    enc_cert_blob = fields.get("enc_cert")
    if not isinstance(link_spec_b64, str):
        raise DescriptorError("introduction point is missing its link specifiers")
    if not isinstance(onion_key, bytes):
        raise DescriptorError("introduction point is missing its onion-key")
    if not isinstance(enc_key, bytes):
        raise DescriptorError("introduction point is missing its enc-key")

    try:
        link_specifiers = parse_block(_b64decode(link_spec_b64))
    except ValueError as exc:
        raise DescriptorError(f"malformed introduction-point link specifiers: {exc}") from exc

    auth_cert = _parse_cert(
        auth_cert_blob if isinstance(auth_cert_blob, bytes) else None, "auth-key"
    )
    if auth_cert.cert_type != CertType.HS_IP_AUTH:
        raise DescriptorError(f"auth-key cert has type {auth_cert.cert_type:#x}, expected 0x09")
    if not auth_cert.verify(desc_signing_key):
        raise DescriptorError("auth-key certificate signature is invalid")

    enc_cert = _parse_cert(
        enc_cert_blob if isinstance(enc_cert_blob, bytes) else None, "enc-key-cert"
    )
    if enc_cert.cert_type != CertType.HS_IP_ENC:
        raise DescriptorError(f"enc-key-cert has type {enc_cert.cert_type:#x}, expected 0x0b")
    if not enc_cert.verify(desc_signing_key):
        raise DescriptorError("enc-key-cert signature is invalid")

    return IntroPoint(
        link_specifiers=link_specifiers,
        onion_key=onion_key,
        auth_key=auth_cert.certified_key,
        enc_key=enc_key,
    )


def _parse_intro_points(text: str, desc_signing_key: bytes) -> list[IntroPoint]:
    """Parse the second-layer plaintext into a list of introduction points."""
    create2_seen = False
    intro_points: list[IntroPoint] = []
    current: dict[str, object] | None = None

    for keyword, args, obj in _iter_items(text):
        if keyword == "create2-formats":
            create2_seen = True
            if "2" not in args:
                raise DescriptorError("create2-formats does not offer ntor (2)")
        elif keyword == "introduction-point":
            if current is not None:
                intro_points.append(_finalize_intro_point(current, desc_signing_key))
            if not args:
                raise DescriptorError("introduction-point line has no link specifiers")
            current = {"link_specifiers": args[0]}
        elif current is not None:
            if keyword == "onion-key" and args[:1] == ["ntor"] and "onion_key" not in current:
                if len(args) < 2:
                    raise DescriptorError("onion-key ntor line is missing its key value")
                current["onion_key"] = _b64decode(args[1])
            elif keyword == "auth-key":
                current["auth_cert"] = obj
            elif keyword == "enc-key" and args[:1] == ["ntor"] and "enc_key" not in current:
                if len(args) < 2:
                    raise DescriptorError("enc-key ntor line is missing its key value")
                current["enc_key"] = _b64decode(args[1])
            elif keyword == "enc-key-cert":
                current["enc_cert"] = obj

    if current is not None:
        intro_points.append(_finalize_intro_point(current, desc_signing_key))

    if not create2_seen:
        raise DescriptorError("inner descriptor layer is missing create2-formats")
    return intro_points


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #


def decrypt_first_layer(
    text: str, blinded_pubkey: bytes, subcredential: bytes, *, now: datetime | None = None
) -> str:
    """Verify the outer wrapper and decrypt the superencrypted (first) layer.

    Returns the first-layer plaintext, from which a client that holds an
    authorization key can derive its descriptor cookie via
    :func:`derive_descriptor_cookie` before calling :func:`parse_descriptor`.
    ``now`` (default: the current UTC time) bounds the signing-key cert's validity.
    """
    outer = _parse_and_verify_outer(text, blinded_pubkey, _resolve_now(now))
    first_layer = _decrypt_layer(
        outer.superencrypted_blob,
        secret_data=blinded_pubkey,
        string_constant=_SUPERENCRYPTED_CONSTANT,
        subcredential=subcredential,
        revision_counter=outer.revision_counter,
    )
    if first_layer is None:
        raise DescriptorError(
            "could not decrypt the superencrypted layer (wrong subcredential or corrupt descriptor)"
        )
    return _decode_plaintext(first_layer)


def derive_descriptor_cookie(
    first_layer_plaintext: str,
    subcredential: bytes,
    client_auth_privkey: bytes,
) -> bytes | None:
    """Derive the 16-byte descriptor cookie for a client-authorized descriptor.

    Uses the client's x25519 private key and the ephemeral key plus
    ``auth-client`` lines carried in the first-layer plaintext. Returns ``None``
    if this client is not in the authorized set (no matching ``auth-client``).
    """
    ephemeral_key, auth_clients, _ = _parse_first_layer(first_layer_plaintext)
    if ephemeral_key is None:
        return None
    try:
        secret_seed = x25519(client_auth_privkey, ephemeral_key)
    except ValueError:
        return None
    keys = shake256(subcredential + secret_seed, 40)
    client_id, cookie_key = keys[:8], keys[8:40]
    for client in auth_clients:
        if const_time_eq(client.client_id, client_id):
            return aes_ctr(cookie_key, client.iv, client.encrypted_cookie)
    return None


def parse_descriptor(
    text: str,
    blinded_pubkey: bytes,
    subcredential: bytes,
    *,
    descriptor_cookie: bytes | None = None,
    now: datetime | None = None,
) -> HsDescriptor:
    """Decode, authenticate, and decrypt a fetched v3 descriptor.

    ``blinded_pubkey`` and ``subcredential`` are the per-time-period values the
    client derived for the address. ``descriptor_cookie`` is the 16-byte
    client-authorization cookie (see :func:`derive_descriptor_cookie`); leave it
    ``None`` for the common no-authorization case. ``now`` (default: the current
    UTC time) is the moment the signing-key certificate's expiry is checked at.

    Raises :class:`DescriptorError` on any parse, signature, or MAC failure, and
    :class:`OnionClientAuthRequired` if the inner layer needs a cookie that was
    not supplied.
    """
    if descriptor_cookie is not None and len(descriptor_cookie) != _DESCRIPTOR_COOKIE_LEN:
        raise DescriptorError(
            f"descriptor cookie must be {_DESCRIPTOR_COOKIE_LEN} bytes, "
            f"got {len(descriptor_cookie)}"
        )

    outer = _parse_and_verify_outer(text, blinded_pubkey, _resolve_now(now))

    first_layer = _decrypt_layer(
        outer.superencrypted_blob,
        secret_data=blinded_pubkey,
        string_constant=_SUPERENCRYPTED_CONSTANT,
        subcredential=subcredential,
        revision_counter=outer.revision_counter,
    )
    if first_layer is None:
        raise DescriptorError(
            "could not decrypt the superencrypted layer (wrong subcredential or corrupt descriptor)"
        )

    _, _, encrypted_blob = _parse_first_layer(_decode_plaintext(first_layer))

    second_layer = _decrypt_layer(
        encrypted_blob,
        secret_data=blinded_pubkey + (descriptor_cookie or b""),
        string_constant=_ENCRYPTED_CONSTANT,
        subcredential=subcredential,
        revision_counter=outer.revision_counter,
    )
    if second_layer is None:
        if descriptor_cookie is None:
            raise OnionClientAuthRequired(
                "descriptor requires client authorization but no cookie was supplied"
            )
        raise DescriptorError("could not decrypt the inner layer (invalid client authorization)")

    intro_points = _parse_intro_points(_decode_plaintext(second_layer), outer.desc_signing_key)
    return HsDescriptor(
        lifetime=outer.lifetime,
        revision_counter=outer.revision_counter,
        intro_points=intro_points,
    )


def parse_descriptor_with_auth(
    text: str,
    blinded_pubkey: bytes,
    subcredential: bytes,
    *,
    client_auth_privkey: bytes | None = None,
    now: datetime | None = None,
) -> HsDescriptor:
    """Decode a descriptor, deriving the client-auth cookie from a client key.

    A client-side convenience over :func:`parse_descriptor`. Given
    ``client_auth_privkey`` (a 32-byte x25519 private key), this decrypts the
    first layer to read the service's ephemeral key, derives the descriptor
    cookie via :func:`derive_descriptor_cookie`, and unlocks the inner layer with
    it. With no key, or a key outside the descriptor's authorized set, no cookie
    is derived, so an authorized-only service raises
    :class:`OnionClientAuthRequired` while an open service decodes as usual.
    ``now`` (default: current UTC) bounds the signing-key cert's expiry.
    """
    # Resolve the clock once so the first-layer verify and the full parse below
    # bound the signing cert against the same instant.
    resolved_now = _resolve_now(now)
    cookie: bytes | None = None
    if client_auth_privkey is not None:
        first_layer = decrypt_first_layer(text, blinded_pubkey, subcredential, now=resolved_now)
        cookie = derive_descriptor_cookie(first_layer, subcredential, client_auth_privkey)
    return parse_descriptor(
        text, blinded_pubkey, subcredential, descriptor_cookie=cookie, now=resolved_now
    )
