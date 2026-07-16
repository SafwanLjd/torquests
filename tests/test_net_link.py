"""Tests for CERTS validation and link-version negotiation."""

from __future__ import annotations

import pytest

from torquests._net.link import _negotiate_version, _validate_certs
from torquests._proto.cells import CertsCell
from torquests._proto.constants import CertType
from torquests.exceptions import ChannelError, LinkAuthError

from .crypto_helpers import ed25519_public_from_seed
from .fakes import FakeRelay, build_cert


def _valid_certs(relay: FakeRelay) -> CertsCell:
    return CertsCell.from_raw(relay.certs_cell())


def test_valid_chain_returns_identity() -> None:
    relay = FakeRelay()
    identity = _validate_certs(_valid_certs(relay), relay.tls_digest)
    assert identity == relay.guard.ed_identity


def test_missing_certificate_is_rejected() -> None:
    relay = FakeRelay()
    only_identity = CertsCell(
        ((CertType.IDENTITY_V_SIGNING, _valid_certs(relay).by_type(CertType.IDENTITY_V_SIGNING)),)
    )
    with pytest.raises(LinkAuthError, match="missing"):
        _validate_certs(only_identity, relay.tls_digest)


def test_tls_digest_mismatch_is_rejected() -> None:
    relay = FakeRelay()
    with pytest.raises(LinkAuthError, match="does not match"):
        _validate_certs(_valid_certs(relay), b"\x00" * 32)


def test_forged_identity_cert_is_rejected() -> None:
    # An identity cert whose self-signature is made with the wrong key.
    relay = FakeRelay()
    wrong_seed = ed25519_public_from_seed(bytes([9]) * 32)  # unrelated key as the ext identity
    forged_identity = build_cert(
        CertType.IDENTITY_V_SIGNING,
        relay.guard.signing_pub,
        relay.guard.identity_seed,  # signed by the real identity...
        ext_identity=wrong_seed,  # ...but the extension claims a different identity
    )
    tls_cert = _valid_certs(relay).by_type(CertType.SIGNING_V_TLS)
    certs = CertsCell(
        ((CertType.IDENTITY_V_SIGNING, forged_identity), (CertType.SIGNING_V_TLS, tls_cert))
    )
    with pytest.raises(LinkAuthError):
        _validate_certs(certs, relay.tls_digest)


def test_expired_certificate_is_rejected() -> None:
    relay = FakeRelay()
    guard = relay.guard
    expired = build_cert(
        CertType.IDENTITY_V_SIGNING,
        guard.signing_pub,
        guard.identity_seed,
        ext_identity=guard.ed_identity,
        expiration_hours=1,  # one hour after the epoch: long expired
    )
    tls_cert = _valid_certs(relay).by_type(CertType.SIGNING_V_TLS)
    certs = CertsCell(((CertType.IDENTITY_V_SIGNING, expired), (CertType.SIGNING_V_TLS, tls_cert)))
    with pytest.raises(LinkAuthError, match="expired"):
        _validate_certs(certs, relay.tls_digest)


def test_version_negotiation() -> None:
    assert _negotiate_version((3, 4, 5)) == 5
    assert _negotiate_version((3, 4)) == 4
    with pytest.raises(ChannelError):
        _negotiate_version((1, 2, 3))
