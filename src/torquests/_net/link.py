"""The OR link handshake.

After TLS, the client and relay exchange VERSIONS to pick a link protocol, the
relay sends its CERTS / AUTH_CHALLENGE / NETINFO, and the client replies with its
own NETINFO. The client authenticates the relay by validating the CERTS chain and
binding it to the TLS certificate it is talking over; it never authenticates
itself. Validating CERTS is what makes the guard's identity trustworthy; torpy
skipped it entirely.

Reference: tor-spec, "Negotiating and initializing channels".
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .._proto.cells import (
    CertsCell,
    NetInfoCell,
    RawCell,
    VersionsCell,
    read_cell,
)
from .._proto.certs import Ed25519Certificate
from .._proto.constants import SUPPORTED_LINK_VERSIONS, Cell, CertType
from ..exceptions import ChannelError, LinkAuthError
from .transport import Transport


@dataclass(frozen=True)
class LinkInfo:
    """The result of a successful link handshake."""

    link_version: int
    relay_ed_identity: bytes  # KP_relayid_ed, validated against the TLS certificate


def _negotiate_version(peer_versions: tuple[int, ...]) -> int:
    common = set(peer_versions) & set(SUPPORTED_LINK_VERSIONS)
    if not common:
        raise ChannelError(f"no common link version with peer {peer_versions}")
    return max(common)


def _parse_link_cert(cert_bytes: bytes, expected_type: CertType, label: str) -> Ed25519Certificate:
    """Parse one CERTS-cell certificate, failing loud as a :class:`LinkAuthError`.

    A malformed certificate surfaces as :class:`LinkAuthError` rather than a bare
    ``ValueError``, and the parsed certificate's inner ``CERT_TYPE`` must match the
    type its CERTS slot promised, so a relay cannot present a certificate of one
    role in another role's slot.
    """
    try:
        cert = Ed25519Certificate.parse(cert_bytes)
    except ValueError as exc:
        raise LinkAuthError(f"malformed {label} certificate: {exc}") from exc
    if cert.cert_type != expected_type:
        raise LinkAuthError(
            f"{label} certificate has type {cert.cert_type:#x}, expected {int(expected_type):#x}"
        )
    return cert


def _validate_certs(
    certs: CertsCell, tls_certificate_digest: bytes, *, now: float | None = None
) -> bytes:
    """Validate the CERTS chain and return the relay's ed25519 identity key."""
    identity_cert_bytes = certs.by_type(CertType.IDENTITY_V_SIGNING)
    tls_cert_bytes = certs.by_type(CertType.SIGNING_V_TLS)
    if identity_cert_bytes is None or tls_cert_bytes is None:
        raise LinkAuthError("CERTS cell is missing the identity or TLS-link certificate")

    identity_cert = _parse_link_cert(identity_cert_bytes, CertType.IDENTITY_V_SIGNING, "identity")
    tls_cert = _parse_link_cert(tls_cert_bytes, CertType.SIGNING_V_TLS, "TLS-link")

    when = time.time() if now is None else now
    if identity_cert.is_expired(when) or tls_cert.is_expired(when):
        raise LinkAuthError("relay certificate has expired")

    # The identity certificate is self-signed by the ed25519 identity key it
    # carries in its extension; it certifies the signing key.
    if not identity_cert.verify_self_signed():
        raise LinkAuthError("identity certificate signature is invalid")
    relay_identity = identity_cert.signing_key
    if relay_identity is None:
        raise LinkAuthError("identity certificate has no signing-key extension")
    signing_key = identity_cert.certified_key

    # The link certificate is signed by the signing key and binds to the TLS cert.
    if not tls_cert.verify(signing_key):
        raise LinkAuthError("TLS-link certificate signature is invalid")
    if tls_cert.certified_key != tls_certificate_digest:
        raise LinkAuthError("TLS-link certificate does not match the presented TLS certificate")

    return relay_identity


def do_link_handshake(
    transport: Transport,
    peer_address: str,
    *,
    expected_identity: bytes | None = None,
) -> LinkInfo:
    """Run the client side of the link handshake over ``transport``."""
    transport.send(VersionsCell(SUPPORTED_LINK_VERSIONS).to_raw().pack(link_version=2))

    versions_raw = read_cell(transport.recv_exact, link_version=2)
    if versions_raw.command != Cell.VERSIONS:
        raise ChannelError(f"expected VERSIONS, got command {versions_raw.command}")
    link_version = _negotiate_version(VersionsCell.from_raw(versions_raw).versions)

    certs: CertsCell | None = None
    netinfo: NetInfoCell | None = None
    while netinfo is None:
        cell: RawCell = read_cell(transport.recv_exact, link_version)
        if cell.command == Cell.CERTS:
            certs = CertsCell.from_raw(cell)
        elif cell.command == Cell.NETINFO:
            netinfo = NetInfoCell.from_raw(cell)
        # AUTH_CHALLENGE, VPADDING, and anything else are ignored: a client does
        # not authenticate itself.

    if certs is None:
        raise LinkAuthError("relay sent no CERTS cell")
    relay_identity = _validate_certs(certs, transport.certificate_digest)
    if expected_identity is not None and relay_identity != expected_identity:
        raise LinkAuthError("relay identity does not match the expected fingerprint")

    reply = NetInfoCell(timestamp=0, other_address=peer_address, my_addresses=())
    transport.send(reply.to_raw().pack(link_version))

    return LinkInfo(link_version, relay_identity)
