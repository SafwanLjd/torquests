"""Consensus verification: liveness and authority-signature checking.

The signed region of a status document runs from the start of the
``network-status-version`` item through the *space* after the first
``directory-signature`` keyword. That excludes the rest of that line and the
newline, so every authority signs identical bytes
(dir-spec/consensus-formats.md, "directory-signature").

Each SIGNATURE object is an RSA PKCS#1 v1.5 signature over the *bare* document
digest: the padding is standard, but the DigestInfo ``algorithmIdentifier``
that PKCS#1 signatures normally embed is omitted (dir-spec/netdoc.md,
"Signing documents"). That is why verification here recovers the padded
payload and compares digests instead of calling a hash-and-verify API. A
microdescriptor consensus SHOULD use sha256-algorithm signatures
(dir-spec/computing-consensus.md, "Signatures"); sha1 is the documented
default and is accepted too, while unrecognized algorithms are ignored as the
spec requires.

A consensus counts as verified when *more than half* of the trusted
authorities have a valid signature on it, and it is live when ``now`` falls
within [valid-after, valid-until] (dir-spec/client-operation.md).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .._crypto.primitives import const_time_eq
from ..exceptions import ConsensusError
from .authorities import DirectoryAuthority
from .models import Consensus
from .parsers import parse_consensus

_SIGNED_REGION_MARKER = "\ndirectory-signature "
_DIGESTS: dict[str, Callable[[bytes], bytes]] = {
    "sha1": lambda data: hashlib.sha1(data).digest(),
    "sha256": lambda data: hashlib.sha256(data).digest(),
}


def signing_key_digest(public_key: rsa.RSAPublicKey) -> bytes:
    """The SHA-1 digest of a signing key's DER-encoded PKCS#1 form.

    This is the value carried as the second fingerprint on a
    ``directory-signature`` line.
    """
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    return hashlib.sha1(der).digest()


def verify_document_signature(
    public_key: rsa.RSAPublicKey, signature: bytes, digest: bytes
) -> bool:
    """Whether ``signature`` is a Tor-style PKCS#1 v1.5 signature over ``digest``.

    Tor pads the raw digest with PKCS#1 v1.5 but omits the DigestInfo
    ``algorithmIdentifier`` (dir-spec/netdoc.md), so this recovers the signed
    payload and compares it to the expected digest.
    """
    try:
        recovered = public_key.recover_data_from_signature(signature, padding.PKCS1v15(), None)
    except (InvalidSignature, ValueError):
        # A malformed or wrong-size signature can surface as ValueError rather than
        # InvalidSignature depending on the cryptography backend/version. Treat it as
        # a failed signature (exactly as the sibling ed25519_verify primitive does)
        # so a hostile mirror cannot abort parsing of a cleartext-fetched consensus
        # or key certificate with an uncaught exception.
        return False
    return const_time_eq(recovered, digest)


def _load_signing_key(authority: DirectoryAuthority) -> rsa.RSAPublicKey | None:
    if authority.signing_key_pem is None:
        return None
    try:
        key = serialization.load_pem_public_key(authority.signing_key_pem)
    except ValueError as exc:
        raise ConsensusError(
            f"authority {authority.nickname} has an unparseable signing key"
        ) from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise ConsensusError(f"authority {authority.nickname} signing key is not RSA")
    return key


def _signed_region(consensus_text: str) -> bytes:
    """The exact byte range every authority signature covers."""
    index = consensus_text.find(_SIGNED_REGION_MARKER)
    if index == -1:
        raise ConsensusError("consensus has no directory-signature item")
    return consensus_text[: index + len(_SIGNED_REGION_MARKER)].encode("utf-8")


def verify_consensus(
    consensus_text: str,
    authorities: Sequence[DirectoryAuthority],
    *,
    now: datetime | None = None,
) -> Consensus:
    """Parse, liveness-check, and signature-check a microdesc consensus.

    ``now`` must be timezone-aware; it defaults to ``datetime.now(timezone.utc)``.
    Raises :class:`ConsensusError` if the consensus is malformed, not live at
    ``now``, or carries valid signatures from at most half of ``authorities``.
    """
    if not authorities:
        raise ConsensusError("no directory authorities to verify the consensus against")
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be a timezone-aware datetime")

    consensus = parse_consensus(consensus_text)
    if now < consensus.valid_after:
        raise ConsensusError(
            f"consensus not yet valid: valid-after {consensus.valid_after.isoformat()}"
            f" is after now {now.isoformat()}"
        )
    if now > consensus.valid_until:
        raise ConsensusError(
            f"consensus expired: valid-until {consensus.valid_until.isoformat()}"
            f" is before now {now.isoformat()}"
        )

    region = _signed_region(consensus_text)
    digests = {algorithm: fn(region) for algorithm, fn in _DIGESTS.items()}
    by_identity = {authority.v3ident: authority for authority in authorities}
    verified: set[bytes] = set()
    for signature in consensus.signatures:
        digest = digests.get(signature.algorithm)
        if digest is None:
            continue  # MUST ignore signatures with an unrecognized algorithm
        authority = by_identity.get(signature.identity)
        if authority is None:
            continue
        key = _load_signing_key(authority)
        if key is None:
            continue
        if not const_time_eq(signing_key_digest(key), signature.signing_key_digest):
            continue  # signed with a key we do not have; cannot be counted
        if verify_document_signature(key, signature.signature, digest):
            verified.add(signature.identity)

    if 2 * len(verified) <= len(authorities):
        raise ConsensusError(
            f"consensus signed by {len(verified)} of {len(authorities)} authorities;"
            " a majority is required"
        )
    return consensus
