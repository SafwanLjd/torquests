"""Service-side v3 descriptor builder, for offline round-trip testing.

This is the encrypting/signing inverse of ``torquests._onion.descriptor``:
given a service identity seed, a time period, and a set of introduction points,
it produces the exact wire text a real onion service would publish, plus the
blinded public key and subcredential a client derives independently. Nothing in
the production library depends on this module; it exists only so the decoder
can be exercised without a live HSDir.

The one non-trivial piece is signing with the *blinded* private key (the
``descriptor-signing-key-cert`` is signed by ``KS_hs_blind_id``). No seed exists
for the blinded key, so we sign with expanded-key ed25519: derive the blinded
scalar ``a' = (h * a) mod L`` and PRF secret ``RH'``, then compute a standard
ed25519 signature by hand. libsodium (via PyNaCl) provides the scalar and point
arithmetic; the result verifies under a stock ed25519 verifier keyed with ``A'``.
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from nacl import bindings as nacl

from torquests._crypto import ed25519_blind as kb
from torquests._crypto.primitives import (
    aes_ctr,
    sha3_256,
    shake256,
    x25519,
    x25519_keypair,
)
from torquests._proto.constants import CertType
from torquests._proto.linkspec import LinkSpecifier, pack_block

from .crypto_helpers import ed25519_public_from_seed, ed25519_sign

_SIG_PREFIX = b"Tor onion service descriptor sig v3"
_RH_BLIND_STRING = b"Derive temporary signing key hash input"
_SUPERENCRYPTED_CONSTANT = b"hsdir-superencrypted-data"
_ENCRYPTED_CONSTANT = b"hsdir-encrypted-data"

_SUPERENC_PAD_MULTIPLE = 10000
_AUTH_CLIENT_MULTIPLE = 16
_DESCRIPTOR_COOKIE_LEN = 16
# Far enough in the future that a descriptor built with the default expiry is not
# expired at any real wall-clock ``now`` for centuries; the expiry path is
# exercised by passing an explicit short expiration and a ``now`` past it.
_CERT_EXPIRATION_HOURS = 4_000_000

#: The spec's worked-example time period (period 16903, 1440-minute length).
DEFAULT_PERIOD_NUM = 16903
DEFAULT_PERIOD_LENGTH = 1440


@dataclass
class IntroPointSpec:
    """The intended contents of one introduction point."""

    link_specifiers: list[LinkSpecifier]
    onion_key: bytes  #: curve25519 ntor onion key of the intro-point relay
    auth_key_pubkey: bytes  #: ed25519 KP_hs_ipt_sid
    enc_key: bytes  #: curve25519 KP_hss_ntor


@dataclass
class BuiltDescriptor:
    """A fully encoded descriptor plus the values a client derives for it."""

    text: str
    identity_pubkey: bytes
    blinded_pubkey: bytes
    subcredential: bytes
    desc_signing_pubkey: bytes
    desc_signing_seed: bytes
    revision_counter: int
    lifetime: int
    prefix_lines: list[str]
    superencrypted_blob: bytes
    descriptor_cookie: bytes | None = None
    intro_points: list[IntroPointSpec] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Blinded-key expanded signing
# --------------------------------------------------------------------------- #


def _blinded_signing_material(
    identity_seed: bytes, period_num: int, period_length: int
) -> tuple[bytes, bytes, bytes]:
    """Return ``(blinded_pubkey, blinded_scalar, blinded_prf_secret)``."""
    identity_pub = ed25519_public_from_seed(identity_seed)
    h = kb.blinding_factor(identity_pub, period_num, period_length)
    digest = hashlib.sha512(identity_seed).digest()
    a_scalar = bytearray(digest[:32])
    a_scalar[0] &= 248
    a_scalar[31] &= 63
    a_scalar[31] |= 64
    rh = digest[32:64]
    h_int = int.from_bytes(h, "little")
    a_int = int.from_bytes(a_scalar, "little")
    blinded_scalar = ((h_int * a_int) % kb.ED25519_L).to_bytes(32, "little")
    blinded_prf = hashlib.sha512(_RH_BLIND_STRING + rh).digest()[:32]
    blinded_pub = kb.blind_public_key(identity_pub, period_num, period_length)
    return blinded_pub, blinded_scalar, blinded_prf


def _blinded_signer(
    blinded_scalar: bytes, blinded_prf: bytes, blinded_pub: bytes
) -> Callable[[bytes], bytes]:
    """Return an expanded-key ed25519 signer for the blinded key."""

    def sign(message: bytes) -> bytes:
        r = nacl.crypto_core_ed25519_scalar_reduce(hashlib.sha512(blinded_prf + message).digest())
        big_r = nacl.crypto_scalarmult_ed25519_base_noclamp(r)
        k = nacl.crypto_core_ed25519_scalar_reduce(
            hashlib.sha512(big_r + blinded_pub + message).digest()
        )
        s = nacl.crypto_core_ed25519_scalar_add(
            r, nacl.crypto_core_ed25519_scalar_mul(k, blinded_scalar)
        )
        return big_r + s

    return sign


# --------------------------------------------------------------------------- #
# Encoding helpers
# --------------------------------------------------------------------------- #


def _b64(data: bytes) -> str:
    """Single-line padded standard base64."""
    return base64.b64encode(data).decode("ascii")


def _b64_nopad(data: bytes) -> str:
    """Single-line unpadded standard base64 (as used for the signature line)."""
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _b64_lines(data: bytes) -> list[str]:
    """Multi-line (64-char) padded base64 body, as used inside PEM objects."""
    encoded = base64.b64encode(data).decode("ascii")
    return [encoded[i : i + 64] for i in range(0, len(encoded), 64)]


def _build_cert(
    cert_type: int,
    certified_key: bytes,
    signing_pubkey: bytes,
    sign: Callable[[bytes], bytes],
    *,
    expiration_hours: int = _CERT_EXPIRATION_HOURS,
) -> bytes:
    """Build and sign a Tor ed25519 certificate (with a signing-key extension)."""
    body = bytes([1, cert_type])
    body += struct.pack(">I", expiration_hours)
    body += bytes([1])  # CERT_KEY_TYPE
    body += certified_key
    body += bytes([1])  # N_EXTENSIONS
    body += struct.pack(">H", len(signing_pubkey)) + bytes([0x04, 0x00]) + signing_pubkey
    return body + sign(body)


def _pem(label: str, blob: bytes) -> list[str]:
    """Lines for a ``-----BEGIN <label>-----`` base64 object."""
    return [f"-----BEGIN {label}-----", *_b64_lines(blob), f"-----END {label}-----"]


def _encrypt_layer(
    plaintext: bytes,
    *,
    secret_data: bytes,
    string_constant: bytes,
    subcredential: bytes,
    revision_counter: int,
    salt: bytes,
    pad_multiple: int | None = None,
) -> bytes:
    """Produce ``SALT | ENCRYPTED | MAC`` for one descriptor layer."""
    if pad_multiple is not None:
        padded_len = -(-len(plaintext) // pad_multiple) * pad_multiple
        plaintext = plaintext + b"\x00" * (padded_len - len(plaintext))
    secret_input = secret_data + subcredential + struct.pack(">Q", revision_counter)
    keys = shake256(secret_input + salt + string_constant, 80)
    s_key, s_iv, mac_key = keys[:32], keys[32:48], keys[48:80]
    encrypted = aes_ctr(s_key, s_iv, plaintext)
    mac = sha3_256(
        struct.pack(">Q", len(mac_key)) + mac_key + struct.pack(">Q", len(salt)) + salt + encrypted
    )
    return salt + encrypted + mac


# --------------------------------------------------------------------------- #
# Inner and first-layer plaintext
# --------------------------------------------------------------------------- #


def _encode_intro_point(ip: IntroPointSpec, desc_signing_seed: bytes) -> list[str]:
    desc_signing_pub = ed25519_public_from_seed(desc_signing_seed)

    def sign(message: bytes) -> bytes:
        return ed25519_sign(desc_signing_seed, message)

    auth_cert = _build_cert(CertType.HS_IP_AUTH, ip.auth_key_pubkey, desc_signing_pub, sign)
    # The enc-key cert subject is a "moot" ed25519 point; a random key is fine.
    enc_cert_subject = ed25519_public_from_seed(os.urandom(32))
    enc_cert = _build_cert(CertType.HS_IP_ENC, enc_cert_subject, desc_signing_pub, sign)

    lines = [f"introduction-point {_b64(pack_block(ip.link_specifiers))}"]
    lines.append(f"onion-key ntor {_b64(ip.onion_key)}")
    lines.append("auth-key")
    lines.extend(_pem("ED25519 CERT", auth_cert))
    lines.append(f"enc-key ntor {_b64(ip.enc_key)}")
    lines.append("enc-key-cert")
    lines.extend(_pem("ED25519 CERT", enc_cert))
    return lines


def _inner_plaintext(intro_points: Sequence[IntroPointSpec], desc_signing_seed: bytes) -> bytes:
    lines = ["create2-formats 2"]
    for ip in intro_points:
        lines.extend(_encode_intro_point(ip, desc_signing_seed))
    return ("\n".join(lines) + "\n").encode("ascii")


def _auth_client_line(client_id: bytes, iv: bytes, cookie: bytes) -> str:
    return f"auth-client {_b64_nopad(client_id)} {_b64_nopad(iv)} {_b64_nopad(cookie)}"


def _first_layer_plaintext(
    layer2_blob: bytes,
    subcredential: bytes,
    authorized_client_pubkey: bytes | None,
    descriptor_cookie: bytes | None,
) -> bytes:
    if authorized_client_pubkey is not None and descriptor_cookie is not None:
        ephemeral_priv, ephemeral_pub = x25519_keypair()
        secret_seed = x25519(ephemeral_priv, authorized_client_pubkey)
        keys = shake256(subcredential + secret_seed, 40)
        client_id, cookie_key = keys[:8], keys[8:40]
        iv = os.urandom(16)
        encrypted_cookie = aes_ctr(cookie_key, iv, descriptor_cookie)
        auth_lines = [_auth_client_line(client_id, iv, encrypted_cookie)]
    else:
        _, ephemeral_pub = x25519_keypair()
        auth_lines = []

    # Pad the client list with fake entries up to the required multiple.
    while len(auth_lines) % _AUTH_CLIENT_MULTIPLE != 0 or not auth_lines:
        auth_lines.append(_auth_client_line(os.urandom(8), os.urandom(16), os.urandom(16)))

    lines = ["desc-auth-type x25519", f"desc-auth-ephemeral-key {_b64(ephemeral_pub)}"]
    lines.extend(auth_lines)
    lines.append("encrypted")
    lines.extend(_pem("MESSAGE", layer2_blob))
    return ("\n".join(lines) + "\n").encode("ascii")


# --------------------------------------------------------------------------- #
# Outer wrapper
# --------------------------------------------------------------------------- #


def assemble_descriptor(
    prefix_lines: Sequence[str], superencrypted_blob: bytes, desc_signing_seed: bytes
) -> str:
    """Assemble and sign the outer descriptor from its parts.

    Exposed so tests can re-sign a deliberately corrupted superencrypted blob
    (to exercise the MAC path while keeping the outer signature valid).
    """
    lines = list(prefix_lines)
    lines.append("superencrypted")
    lines.extend(_pem("MESSAGE", superencrypted_blob))
    signed_region = "\n".join(lines) + "\n"
    signature = ed25519_sign(desc_signing_seed, _SIG_PREFIX + signed_region.encode("ascii"))
    return signed_region + f"signature {_b64_nopad(signature)}\n"


def build_descriptor(
    identity_seed: bytes,
    intro_points: Sequence[IntroPointSpec],
    *,
    period_num: int = DEFAULT_PERIOD_NUM,
    period_length: int = DEFAULT_PERIOD_LENGTH,
    revision_counter: int = 1,
    lifetime_minutes: int = 180,
    authorized_client_pubkey: bytes | None = None,
    signing_cert_type: int = CertType.HS_DESC_SIGNING,
    signing_cert_expiration_hours: int = _CERT_EXPIRATION_HOURS,
) -> BuiltDescriptor:
    """Encode a complete v3 descriptor for a service identity and intro points.

    Pass ``authorized_client_pubkey`` (a client's x25519 public key) to produce a
    client-authorized descriptor; the returned ``descriptor_cookie`` is then the
    cookie that client will recover. ``signing_cert_type`` and
    ``signing_cert_expiration_hours`` override the descriptor-signing-key cert's
    type and expiry, to drive the decoder's wrong-type and expiry rejections.
    """
    identity_pub = ed25519_public_from_seed(identity_seed)
    blinded_pub, blinded_scalar, blinded_prf = _blinded_signing_material(
        identity_seed, period_num, period_length
    )
    subcredential = kb.subcredential(identity_pub, blinded_pub)
    blinded_sign = _blinded_signer(blinded_scalar, blinded_prf, blinded_pub)

    desc_signing_seed = os.urandom(32)
    desc_signing_pub = ed25519_public_from_seed(desc_signing_seed)

    descriptor_cookie: bytes | None = None
    if authorized_client_pubkey is not None:
        descriptor_cookie = os.urandom(_DESCRIPTOR_COOKIE_LEN)

    # Layer 2 (inner): the intro points.
    inner = _inner_plaintext(intro_points, desc_signing_seed)
    layer2_blob = _encrypt_layer(
        inner,
        secret_data=blinded_pub + (descriptor_cookie or b""),
        string_constant=_ENCRYPTED_CONSTANT,
        subcredential=subcredential,
        revision_counter=revision_counter,
        salt=os.urandom(16),
    )

    # Layer 1 (superencrypted): the client-auth wrapper around layer 2.
    first_layer = _first_layer_plaintext(
        layer2_blob, subcredential, authorized_client_pubkey, descriptor_cookie
    )
    superencrypted_blob = _encrypt_layer(
        first_layer,
        secret_data=blinded_pub,
        string_constant=_SUPERENCRYPTED_CONSTANT,
        subcredential=subcredential,
        revision_counter=revision_counter,
        salt=os.urandom(16),
        pad_multiple=_SUPERENC_PAD_MULTIPLE,
    )

    # Outer wrapper: version, lifetime, signing-key cert, revision counter.
    signing_cert = _build_cert(
        signing_cert_type,
        desc_signing_pub,
        blinded_pub,
        blinded_sign,
        expiration_hours=signing_cert_expiration_hours,
    )
    prefix_lines = [
        "hs-descriptor 3",
        f"descriptor-lifetime {lifetime_minutes}",
        "descriptor-signing-key-cert",
        *_pem("ED25519 CERT", signing_cert),
        f"revision-counter {revision_counter}",
    ]
    text = assemble_descriptor(prefix_lines, superencrypted_blob, desc_signing_seed)

    return BuiltDescriptor(
        text=text,
        identity_pubkey=identity_pub,
        blinded_pubkey=blinded_pub,
        subcredential=subcredential,
        desc_signing_pubkey=desc_signing_pub,
        desc_signing_seed=desc_signing_seed,
        revision_counter=revision_counter,
        lifetime=lifetime_minutes,
        prefix_lines=prefix_lines,
        superencrypted_blob=superencrypted_blob,
        descriptor_cookie=descriptor_cookie,
        intro_points=list(intro_points),
    )


def random_intro_point() -> IntroPointSpec:
    """Generate an introduction point with fresh keys and link specifiers."""
    _, onion_key = x25519_keypair()
    _, enc_key = x25519_keypair()
    auth_key = ed25519_public_from_seed(os.urandom(32))
    link_specifiers = [
        LinkSpecifier.ipv4("10.0.0.1", 9001),
        LinkSpecifier.legacy_id(os.urandom(20)),
        LinkSpecifier.ed25519_id(os.urandom(32)),
    ]
    return IntroPointSpec(link_specifiers, onion_key, auth_key, enc_key)
