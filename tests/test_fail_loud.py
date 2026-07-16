"""Fail-loud hardening for eight leaf modules.

Each test drives one parsing/handshake/transport edge that previously escaped as
an untyped exception (``ValueError``, ``struct.error``, ``IndexError``) or leaked
a resource, and asserts the fixed code surfaces the matching typed error instead.
Inputs are built inline so the module is self-contained and needs no fixtures.
"""

from __future__ import annotations

import base64
import hashlib
import random
import ssl
import struct

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from torquests._client import bootstrap
from torquests._dir.consensus import signing_key_digest, verify_document_signature
from torquests._dir.keycerts import parse_key_certificates
from torquests._net import transport as transport_mod
from torquests._net.link import _validate_certs
from torquests._onion.descriptor import _parse_cert, _parse_intro_points
from torquests._proto.cells import CertsCell, NetInfoCell, RawCell
from torquests._proto.certs import Ed25519Certificate
from torquests._proto.constants import Cell, CertType
from torquests._proto.handshake.hs_ntor import HsNtorHandshake
from torquests.exceptions import (
    ChannelError,
    DescriptorError,
    LinkAuthError,
    RendezvousError,
    TorBootstrapError,
)

from .dir_fixtures import sign_document_digest

# --------------------------------------------------------------------------- #
# Inline builders (no shared test fixtures)
# --------------------------------------------------------------------------- #


def _ed25519_public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def _ed25519_sign(seed: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def _build_cert(
    cert_type: int,
    certified_key: bytes,
    signer_seed: bytes,
    *,
    ext_identity: bytes | None = None,
    expiration_hours: int = 10_000_000,
) -> bytes:
    """Build a signed Tor ed25519 certificate (cert-spec wire layout)."""
    body = bytes([1, cert_type]) + struct.pack(">I", expiration_hours) + bytes([1]) + certified_key
    if ext_identity is not None:
        ext = struct.pack(">H", 32) + bytes([0x04, 0x00]) + ext_identity
        body += bytes([1]) + ext
    else:
        body += bytes([0])
    return body + _ed25519_sign(signer_seed, body)


def _truncated_cert_bytes() -> bytes:
    """A 40-byte cert header that declares one extension but is cut off before it.

    ``VERSION | CERT_TYPE | EXPIRATION(4) | CERT_KEY_TYPE | CERTIFIED_KEY(32) |
    N_EXTENSIONS=1`` with no extension body, so the extension-length unpack runs
    off the end of the buffer.
    """
    header = bytes([1, CertType.IDENTITY_V_SIGNING])
    header += struct.pack(">I", 1000)  # expiration hours
    header += bytes([1])  # cert_key_type
    header += b"\x00" * 32  # certified_key
    header += bytes([1])  # n_extensions = 1, with nothing following
    return header


# --------------------------------------------------------------------------- #
# 1. hs_ntor.complete_rendezvous: low-order key -> RendezvousError
# --------------------------------------------------------------------------- #


def test_complete_rendezvous_low_order_key_raises_rendezvous_error() -> None:
    """A degenerate (all-zero) rendezvous key is a RendezvousError, not ValueError."""
    handshake = HsNtorHandshake(
        b"\x11" * 32, b"\x22" * 32, b"\x33" * 32, ephemeral_private=bytes(range(32))
    )
    with pytest.raises(RendezvousError):
        handshake.complete_rendezvous(b"\x00" * 32, b"\x00" * 32)


# --------------------------------------------------------------------------- #
# 2. consensus.verify_document_signature: recovery ValueError -> failure
# --------------------------------------------------------------------------- #


def test_verify_document_signature_treats_recover_value_error_as_failure() -> None:
    """A ValueError from RSA recovery is a failed signature, not a crash.

    This matches the sibling ``ed25519_verify`` primitive, which treats both
    ``InvalidSignature`` and ``ValueError`` as verification failure.
    """

    class _RaisingKey:
        def recover_data_from_signature(
            self, signature: bytes, pad: object, algorithm: object
        ) -> bytes:
            raise ValueError("invalid signature size")

    assert verify_document_signature(_RaisingKey(), b"\x00" * 16, b"\x11" * 32) is False  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# 3. certs.Ed25519Certificate.parse: truncation -> ValueError, wrapped upstream
# --------------------------------------------------------------------------- #


def test_truncated_certificate_raises_value_error_not_struct_error() -> None:
    """A truncated cert raises ValueError, the malformed-cert error certs.py uses.

    ``struct.error`` is not a ``ValueError`` subclass, so it would slip through
    the ``except ValueError`` guards in the descriptor and link layers.
    """
    with pytest.raises(ValueError) as excinfo:
        Ed25519Certificate.parse(_truncated_cert_bytes())
    assert not isinstance(excinfo.value, struct.error)


def test_descriptor_parse_cert_wraps_truncated_cert() -> None:
    """The descriptor layer turns a truncated cert into a DescriptorError."""
    with pytest.raises(DescriptorError):
        _parse_cert(_truncated_cert_bytes(), "descriptor-signing-key-cert")


def test_validate_certs_wraps_truncated_cert_as_link_error() -> None:
    """The link layer turns a truncated CERTS entry into a LinkAuthError."""
    tls_cert = _build_cert(CertType.SIGNING_V_TLS, b"\x07" * 32, b"\x02" * 32)
    certs = CertsCell(
        (
            (CertType.IDENTITY_V_SIGNING, _truncated_cert_bytes()),
            (CertType.SIGNING_V_TLS, tls_cert),
        )
    )
    with pytest.raises(LinkAuthError):
        _validate_certs(certs, b"\x07" * 32)


# --------------------------------------------------------------------------- #
# 4. descriptor._parse_intro_points: bare "ntor" line -> DescriptorError
# --------------------------------------------------------------------------- #


def test_intro_point_bare_onion_key_ntor_raises_descriptor_error() -> None:
    """`onion-key ntor` with no key value is a DescriptorError, not IndexError."""
    text = "create2-formats 2\nintroduction-point AQAG\nonion-key ntor\n"
    with pytest.raises(DescriptorError):
        _parse_intro_points(text, b"\x00" * 32)


def test_intro_point_bare_enc_key_ntor_raises_descriptor_error() -> None:
    """`enc-key ntor` with no key value is a DescriptorError, not IndexError."""
    text = "create2-formats 2\nintroduction-point AQAG\nonion-key ntor AAAA\nenc-key ntor\n"
    with pytest.raises(DescriptorError):
        _parse_intro_points(text, b"\x00" * 32)


# --------------------------------------------------------------------------- #
# 5. link._validate_certs: inner CERT_TYPE must match the CERTS slot
# --------------------------------------------------------------------------- #


def test_validate_certs_rejects_wrong_inner_cert_type() -> None:
    """An identity cert whose inner CERT_TYPE is not 0x04 is rejected."""
    identity_seed = b"\x01" * 32
    signing_seed = b"\x02" * 32
    ed_identity = _ed25519_public(identity_seed)
    signing_pub = _ed25519_public(signing_seed)
    tls_digest = b"\x07" * 32

    # Correctly self-signed and TLS-bound, but the inner CERT_TYPE is 0x08 rather
    # than the IDENTITY_V_SIGNING (0x04) the CERTS slot promises.
    forged = _build_cert(
        CertType.HS_DESC_SIGNING, signing_pub, identity_seed, ext_identity=ed_identity
    )
    tls_cert = _build_cert(CertType.SIGNING_V_TLS, tls_digest, signing_seed)
    certs = CertsCell(((CertType.IDENTITY_V_SIGNING, forged), (CertType.SIGNING_V_TLS, tls_cert)))
    with pytest.raises(LinkAuthError):
        _validate_certs(certs, tls_digest)


def test_validate_certs_accepts_correct_inner_cert_types() -> None:
    """The cert-type check does not reject a well-formed chain (guards the fix)."""
    identity_seed = b"\x01" * 32
    signing_seed = b"\x02" * 32
    ed_identity = _ed25519_public(identity_seed)
    signing_pub = _ed25519_public(signing_seed)
    tls_digest = b"\x07" * 32

    identity_cert = _build_cert(
        CertType.IDENTITY_V_SIGNING, signing_pub, identity_seed, ext_identity=ed_identity
    )
    tls_cert = _build_cert(CertType.SIGNING_V_TLS, tls_digest, signing_seed)
    certs = CertsCell(
        ((CertType.IDENTITY_V_SIGNING, identity_cert), (CertType.SIGNING_V_TLS, tls_cert))
    )
    assert _validate_certs(certs, tls_digest) == ed_identity


# --------------------------------------------------------------------------- #
# 6. transport.TlsTransport.connect: handshake failure must not leak the socket
# --------------------------------------------------------------------------- #


def test_tls_transport_closes_socket_on_handshake_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed TLS handshake closes the underlying TCP socket (no fd leak)."""
    closed = {"count": 0}

    class _FakeSocket:
        def settimeout(self, _timeout: float | None) -> None:
            pass

        def close(self) -> None:
            closed["count"] += 1

    fake = _FakeSocket()
    monkeypatch.setattr(transport_mod.socket, "create_connection", lambda *a, **k: fake)

    def _boom(self: object, sock: object, **kwargs: object) -> None:
        raise ssl.SSLError("handshake failed")

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", _boom)

    transport = transport_mod.TlsTransport("relay.example", 443)
    with pytest.raises(ChannelError):
        transport.connect()
    assert closed["count"] == 1


# --------------------------------------------------------------------------- #
# 7. keycerts.parse_key_certificates: a corrupt certificate must not leak
# --------------------------------------------------------------------------- #


def _pkcs1_public_pem(key: rsa.RSAPrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
        .decode("ascii")
    )


def _valid_key_certificate(identity: rsa.RSAPrivateKey, signing: rsa.RSAPrivateKey) -> str:
    """A well-formed ``dir-key-certificate-version 3`` document (dir-spec).

    The identity key certifies the signing key and self-signs the certification
    region, so :func:`parse_key_certificates` accepts it. The Tor-style signature
    is produced by the suite's shared ``sign_document_digest`` primitive.
    """
    fingerprint = signing_key_digest(identity.public_key()).hex().upper()
    prefix = (
        "dir-key-certificate-version 3\n"
        f"fingerprint {fingerprint}\n"
        "dir-identity-key\n"
        f"{_pkcs1_public_pem(identity)}"
        "dir-key-published 2026-01-01 00:00:00\n"
        "dir-key-expires 2027-01-01 00:00:00\n"
        "dir-signing-key\n"
        f"{_pkcs1_public_pem(signing)}"
        "dir-key-certification\n"
    )
    digest = hashlib.sha1(prefix.encode("ascii")).digest()
    encoded = base64.b64encode(sign_document_digest(identity, digest)).decode("ascii")
    wrapped = "\n".join(encoded[i : i + 64] for i in range(0, len(encoded), 64))
    return prefix + f"-----BEGIN SIGNATURE-----\n{wrapped}\n-----END SIGNATURE-----\n"


def _corrupt_key_certificate() -> str:
    """A certificate whose key PEM is syntactically framed but is not valid DER.

    All four required fields are present, so parsing reaches ``load_pem_public_key``
    on the identity key, where the garbage body raises ``ValueError`` -- the raw
    leak this fix contains.
    """
    garbage_pem = (
        "-----BEGIN RSA PUBLIC KEY-----\nbm90LXZhbGlkLURFUg==\n-----END RSA PUBLIC KEY-----\n"
    )
    return (
        "dir-key-certificate-version 3\n"
        f"fingerprint {'A' * 40}\n"
        "dir-identity-key\n"
        f"{garbage_pem}"
        "dir-signing-key\n"
        f"{garbage_pem}"
        "dir-key-certification\n"
        "-----BEGIN SIGNATURE-----\nAAAA\n-----END SIGNATURE-----\n"
    )


def test_key_certificates_skip_corrupt_and_keep_valid() -> None:
    """A corrupt certificate among valid ones is skipped; the valid one survives."""
    identity = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    signing = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    document = _corrupt_key_certificate() + _valid_key_certificate(identity, signing)
    (cert,) = parse_key_certificates(document)
    assert cert.v3ident == signing_key_digest(identity.public_key())


def test_bootstrap_wholly_corrupt_key_certs_is_typed_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wholly corrupt ``/tor/keys/all`` document is a typed TorBootstrapError.

    Without the fix the malformed identity key raises a bare ``ValueError`` out of
    ``bootstrap``; with it, the certificate is skipped and the authority-quorum
    check surfaces the typed :class:`TorBootstrapError` the hierarchy promises.
    """
    monkeypatch.setattr(bootstrap, "_fetch", lambda *args, **kwargs: _corrupt_key_certificate())
    with pytest.raises(TorBootstrapError):
        bootstrap.bootstrap(rng=random.Random(0))


# --------------------------------------------------------------------------- #
# 8. cells: a truncated CERTS or NETINFO cell must not index past the buffer
# --------------------------------------------------------------------------- #


def test_truncated_certs_cell_raises_channel_error() -> None:
    """A CERTS cell that declares a certificate it does not carry is a ChannelError."""
    # count=1 and a cert type, but the 2-byte length runs off the end of the body.
    truncated = RawCell(0, Cell.CERTS, bytes([1, CertType.IDENTITY_V_SIGNING]))
    with pytest.raises(ChannelError) as excinfo:
        CertsCell.from_raw(truncated)
    assert not isinstance(excinfo.value, (IndexError, struct.error))


def test_truncated_netinfo_cell_raises_channel_error() -> None:
    """A NETINFO cell cut off right after its timestamp is a ChannelError."""
    truncated = RawCell(0, Cell.NETINFO, struct.pack(">I", 1_700_000_000))
    with pytest.raises(ChannelError) as excinfo:
        NetInfoCell.from_raw(truncated)
    assert not isinstance(excinfo.value, (IndexError, struct.error))


def test_wellformed_certs_cell_round_trips() -> None:
    """The bounds checks do not reject a well-formed CERTS cell (no over-tightening)."""
    cell = CertsCell(
        ((CertType.IDENTITY_V_SIGNING, b"\x01\x02\x03"), (CertType.SIGNING_V_TLS, b"\x04\x05"))
    )
    assert CertsCell.from_raw(cell.to_raw()) == cell


def test_wellformed_netinfo_cell_round_trips() -> None:
    """The bounds checks do not reject a well-formed NETINFO cell (no over-tightening)."""
    cell = NetInfoCell(timestamp=1_700_000_000, other_address="1.2.3.4", my_addresses=("5.6.7.8",))
    assert NetInfoCell.from_raw(cell.to_raw()) == cell
