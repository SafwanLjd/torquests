"""Tor ed25519 certificates (cert-spec).

A certificate binds one key to another with a signature::

    VERSION(1) | CERT_TYPE(1) | EXPIRATION(4, hours since epoch) |
    CERT_KEY_TYPE(1) | CERTIFIED_KEY(32) | N_EXTENSIONS(1) |
    extensions | SIGNATURE(64)

The signature covers every byte before it. A self-signed certificate carries the
signing key in a "signed-with-ed25519-key" extension (type ``0x04``); otherwise
the signer is an external key the caller supplies.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .._crypto.primitives import ed25519_verify

#: Extension type carrying the ed25519 key that signed the certificate.
EXT_SIGNED_WITH_ED25519_KEY = 0x04


@dataclass(frozen=True)
class CertExtension:
    ext_type: int
    flags: int
    data: bytes


@dataclass(frozen=True)
class Ed25519Certificate:
    version: int
    cert_type: int
    expiration_hours: int
    cert_key_type: int
    certified_key: bytes
    extensions: tuple[CertExtension, ...]
    signature: bytes
    signed_body: bytes

    @classmethod
    def parse(cls, data: bytes) -> Ed25519Certificate:
        if len(data) < 40:
            raise ValueError("certificate too short")
        version = data[0]
        cert_type = data[1]
        (expiration,) = struct.unpack(">I", data[2:6])
        cert_key_type = data[6]
        certified_key = data[7:39]
        n_ext = data[39]
        offset = 40
        extensions: list[CertExtension] = []
        for _ in range(n_ext):
            # Bounds-check before unpacking: a truncated buffer must fail as the
            # ValueError this parser already uses for malformed certs, not as the
            # struct.error / IndexError that would slip through the ``except
            # ValueError`` guards in the descriptor and link layers.
            if offset + 4 > len(data):
                raise ValueError("certificate extension header is truncated")
            (ext_len,) = struct.unpack(">H", data[offset : offset + 2])
            ext_type = data[offset + 2]
            flags = data[offset + 3]
            ext_data = data[offset + 4 : offset + 4 + ext_len]
            if len(ext_data) != ext_len:
                raise ValueError("certificate extension body is truncated")
            extensions.append(CertExtension(ext_type, flags, ext_data))
            offset += 4 + ext_len
        signed_body = data[:offset]
        signature = data[offset : offset + 64]
        if len(signature) != 64:
            raise ValueError("certificate is missing its 64-byte signature")
        return cls(
            version,
            cert_type,
            expiration,
            cert_key_type,
            certified_key,
            tuple(extensions),
            signature,
            signed_body,
        )

    @property
    def signing_key(self) -> bytes | None:
        """The ed25519 key from the signed-with-ed25519-key extension, if present."""
        for ext in self.extensions:
            if ext.ext_type == EXT_SIGNED_WITH_ED25519_KEY and len(ext.data) == 32:
                return ext.data
        return None

    def verify(self, signer_public_key: bytes) -> bool:
        """Verify the signature under an explicitly supplied signer key."""
        return ed25519_verify(signer_public_key, self.signature, self.signed_body)

    def verify_self_signed(self) -> bool:
        """Verify a certificate signed by the key carried in its own extension."""
        key = self.signing_key
        if key is None:
            return False
        return self.verify(key)

    def is_expired(self, now_unix: float) -> bool:
        """Whether the certificate has expired at ``now_unix`` seconds."""
        return self.expiration_hours * 3600 <= now_unix
