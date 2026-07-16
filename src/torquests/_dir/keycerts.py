"""Directory-authority key certificates (dir-spec, key certificates).

An authority's long-term identity key certifies a medium-term *signing* key,
which is what actually signs a consensus. The certificate is fetched from a
directory over plain HTTP, so it must be verified: the identity key's SHA-1
fingerprint must match the trusted v3 identity, and the certificate's
self-signature (``dir-key-certification``) must check out under that identity
key. Only then is the signing key trusted to have signed the consensus.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .consensus import signing_key_digest, verify_document_signature

_CERT_MARKER = "dir-key-certificate-version 3"
_CERTIFICATION_TOKEN = "dir-key-certification\n"


@dataclass(frozen=True)
class KeyCertificate:
    """A verified authority key certificate."""

    v3ident: bytes  # 20-byte SHA-1 of the identity key
    signing_key_pem: bytes  # the medium-term signing key, PEM "RSA PUBLIC KEY"


def _pem(label: str, text: str) -> str | None:
    match = re.search(rf"-----BEGIN {label}-----\n(.*?)-----END {label}-----", text, re.S)
    if match is None:
        return None
    return f"-----BEGIN {label}-----\n{match.group(1)}-----END {label}-----\n"


def _load_rsa(pem: str) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("expected an RSA public key")
    return key


def _parse_one(cert_text: str) -> KeyCertificate | None:
    fingerprint_match = re.search(r"fingerprint ([0-9A-Fa-f]{40})", cert_text)
    identity_pem = _pem("RSA PUBLIC KEY", cert_text)
    signing_match = re.search(
        r"dir-signing-key\n(-----BEGIN.*?-----END RSA PUBLIC KEY-----\n)", cert_text, re.S
    )
    signature_pem = _pem("SIGNATURE", cert_text)
    if not (fingerprint_match and identity_pem and signing_match and signature_pem):
        return None

    identity_key = _load_rsa(identity_pem)
    v3ident = signing_key_digest(identity_key)
    if v3ident.hex() != fingerprint_match.group(1).lower():
        return None  # the fingerprint field does not match the identity key

    token = cert_text.find(_CERTIFICATION_TOKEN)
    if token == -1:
        return None
    signed_region = cert_text[: token + len(_CERTIFICATION_TOKEN)].encode()

    signature = base64.b64decode(re.sub(r"\s+", "", _pem_body(signature_pem)))
    if not verify_document_signature(identity_key, signature, hashlib.sha1(signed_region).digest()):
        return None  # the identity did not certify this signing key

    signing_pem = signing_match.group(1)
    _load_rsa(signing_pem)  # ensure it parses
    return KeyCertificate(v3ident, signing_pem.encode())


def _pem_body(pem: str) -> str:
    return re.sub(r"-----(BEGIN|END)[^-]*-----", "", pem)


def parse_key_certificates(text: str) -> list[KeyCertificate]:
    """Parse and verify every key certificate in a document, skipping bad ones.

    A certificate that fails a verification check is dropped (``_parse_one`` returns
    ``None``); one whose key or signature material is malformed raises ``ValueError``
    from the crypto layer, which is caught here so a single corrupt entry cannot
    abort parsing of the whole document. Callers that require a usable certificate
    enforce that separately: ``bootstrap`` fails loud with a typed
    :class:`~torquests.exceptions.TorBootstrapError` when too few authority signing
    keys verify.
    """
    chunks = text.split(_CERT_MARKER)
    certs: list[KeyCertificate] = []
    for chunk in chunks[1:]:
        try:
            cert = _parse_one(_CERT_MARKER + chunk)
        except ValueError:
            continue  # malformed key or signature material: skip this certificate
        if cert is not None:
            certs.append(cert)
    return certs
