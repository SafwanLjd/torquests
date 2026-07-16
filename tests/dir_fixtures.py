"""Synthetic directory documents for the ``_dir`` tests.

Builds a small, internally consistent network: eight routers with varied flags
and bandwidths, microdescriptors whose SHA-256 digests really are the
consensus ``m`` values, and three self-generated RSA-2048 authorities that
sign the consensus over the exact signed region the spec defines, from
``network-status-version`` through the *space* after the first
``directory-signature`` keyword (dir-spec/consensus-formats.md), with the
PKCS#1 v1.5 padding applied to the bare SHA-256 digest, DigestInfo omitted
(dir-spec/netdoc.md, "Signing documents").
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from torquests._crypto.primitives import x25519_public_from_private
from torquests._dir.authorities import DirectoryAuthority
from torquests._dir.consensus import signing_key_digest

from .crypto_helpers import ed25519_public_from_seed

VALID_AFTER = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
FRESH_UNTIL = datetime(2026, 1, 1, 13, 0, 0, tzinfo=timezone.utc)
VALID_UNTIL = datetime(2026, 1, 1, 15, 0, 0, tzinfo=timezone.utc)
NOW_LIVE = datetime(2026, 1, 1, 12, 30, 0, tzinfo=timezone.utc)

SRV_CURRENT = hashlib.sha256(b"synthetic srv current").digest()
SRV_PREVIOUS = hashlib.sha256(b"synthetic srv previous").digest()

_TOR_VERSION = "Tor 0.4.8.14"
_PR_LINE = (
    "pr Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2"
    " Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4 SendMe=1 Tunnel=1-2"
)


def b64_unpadded(raw: bytes) -> str:
    """Base64 with trailing ``=`` stripped, as consensus digests are encoded."""
    return base64.b64encode(raw).decode("ascii").rstrip("=")


def _wrap64(text: str) -> str:
    return "\n".join(text[i : i + 64] for i in range(0, len(text), 64))


def _timestamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def sign_document_digest(key: rsa.RSAPrivateKey, digest: bytes) -> bytes:
    """Tor-style signature: PKCS#1 v1.5 padding over the bare digest.

    Standard signing APIs insert the DigestInfo algorithmIdentifier, which Tor
    omits, so the fixture pads and exponentiates by hand.
    """
    size = key.key_size // 8
    padded = b"\x00\x01" + b"\xff" * (size - 3 - len(digest)) + b"\x00" + digest
    numbers = key.private_numbers()
    value = pow(int.from_bytes(padded, "big"), numbers.d, numbers.public_numbers.n)
    return value.to_bytes(size, "big")


@dataclass(frozen=True)
class RouterExpectation:
    """What the tests expect the parsers to recover for one router."""

    nickname: str
    fingerprint: bytes
    address: str
    or_port: int
    dir_port: int
    flags: frozenset[str]
    bandwidth: int
    ntor_onion_key: bytes
    ed25519_id: bytes
    md_digest: bytes


@dataclass(frozen=True)
class SyntheticDirectory:
    """A signed synthetic consensus plus everything needed to re-sign variants."""

    authorities: tuple[DirectoryAuthority, ...]
    signers: tuple[tuple[DirectoryAuthority, rsa.RSAPrivateKey], ...]
    consensus_text: str
    unsigned_body: str
    microdescriptors_text: str
    authority_section: str
    router_section: str
    expected: dict[str, RouterExpectation]


@dataclass(frozen=True)
class _RouterSpec:
    nickname: str
    address: str
    or_port: int
    dir_port: int
    flags: str  # space-separated, alphabetical
    bandwidth: int
    policy: str | None = None  # a 'p' line body, e.g. "accept 80,443"
    family_with: tuple[str, ...] = ()
    pem_onion_key: bool = False
    ipv6: str | None = None


_ROUTERS = (
    _RouterSpec(
        "guardian1",
        "10.1.0.1",
        9001,
        9030,
        "Fast Guard HSDir Running Stable V2Dir Valid",
        30000,
    ),
    _RouterSpec(
        "guardian2",
        "10.2.0.1",
        443,
        0,
        "Fast Guard Running Stable V2Dir Valid",
        20000,
        ipv6="[2001:db8::5]:9001",
    ),
    _RouterSpec("middleman", "10.3.0.1", 9001, 0, "Fast Running Valid", 15000, pem_onion_key=True),
    _RouterSpec(
        "exitpoint",
        "10.4.0.1",
        9001,
        0,
        "Exit Fast Running Stable Valid",
        25000,
        policy="accept 80,443,8000-8999",
        family_with=("kinsman",),
    ),
    _RouterSpec(
        "portlyexit",
        "10.5.0.1",
        9001,
        0,
        "Exit Fast HSDir Running Valid",
        10000,
        policy="accept 22,25",
    ),
    _RouterSpec(
        "rottenexit",
        "10.6.0.1",
        9001,
        0,
        "BadExit Exit Fast Running Valid",
        50000,
        policy="accept 1-65535",
    ),
    _RouterSpec(
        "nearguard",
        "10.1.5.5",
        9001,
        0,
        "Fast Guard NoEdConsensus Running Stable V2Dir Valid",
        30000,
    ),
    _RouterSpec(
        "kinsman", "10.7.0.1", 9001, 0, "Fast Running Valid", 15000, family_with=("exitpoint",)
    ),
)


def _fingerprint(nickname: str) -> bytes:
    return hashlib.sha1(b"synthetic rsa identity: " + nickname.encode()).digest()


def _ntor_key(nickname: str) -> bytes:
    private = hashlib.sha256(b"synthetic ntor key: " + nickname.encode()).digest()
    return x25519_public_from_private(private)


def _ed_identity(nickname: str) -> bytes:
    seed = hashlib.sha256(b"synthetic ed identity: " + nickname.encode()).digest()
    return ed25519_public_from_seed(seed)


def _microdescriptor(spec: _RouterSpec) -> str:
    lines = ["onion-key"]
    if spec.pem_onion_key:
        lines.append("-----BEGIN RSA PUBLIC KEY-----")
        lines.append(_wrap64(base64.b64encode(b"\x42" * 96).decode("ascii")))
        lines.append("-----END RSA PUBLIC KEY-----")
    lines.append(f"ntor-onion-key {b64_unpadded(_ntor_key(spec.nickname))}")
    if spec.family_with:
        members = sorted(
            "$" + _fingerprint(nick).hex().upper() for nick in (spec.nickname, *spec.family_with)
        )
        lines.append("family " + " ".join(members))
    if spec.policy is not None:
        lines.append(f"p {spec.policy}")
    lines.append(f"id ed25519 {b64_unpadded(_ed_identity(spec.nickname))}")
    return "\n".join(lines) + "\n"


def _router_entry(spec: _RouterSpec, md_digest: bytes) -> str:
    lines = [
        f"r {spec.nickname} {b64_unpadded(_fingerprint(spec.nickname))}"
        f" 2038-01-01 00:00:00 {spec.address} {spec.or_port} {spec.dir_port}"
    ]
    if spec.ipv6 is not None:
        lines.append(f"a {spec.ipv6}")
    lines.append(f"m {b64_unpadded(md_digest)}")
    lines.append(f"s {spec.flags}")
    lines.append(f"v {_TOR_VERSION}")
    lines.append(_PR_LINE)
    lines.append(f"w Bandwidth={spec.bandwidth}")
    return "\n".join(lines) + "\n"


def _authority_section(
    signers: tuple[tuple[DirectoryAuthority, rsa.RSAPrivateKey], ...],
) -> str:
    blocks = []
    for index, (authority, _) in enumerate(signers):
        blocks.append(
            f"dir-source {authority.nickname} {authority.v3ident.hex().upper()}"
            f" {authority.nickname}.example.org 192.0.2.{index + 1} 80 443\n"
            f"contact synthetic authority {authority.nickname}\n"
            f"vote-digest {hashlib.sha1(authority.nickname.encode()).digest().hex().upper()}\n"
        )
    return "".join(blocks)


def consensus_body(
    *,
    authority_section: str,
    router_section: str,
    valid_after: datetime = VALID_AFTER,
    fresh_until: datetime = FRESH_UNTIL,
    valid_until: datetime = VALID_UNTIL,
) -> str:
    """The unsigned consensus document, ending just before the signature items."""
    srv_previous = base64.b64encode(SRV_PREVIOUS).decode("ascii")
    srv_current = base64.b64encode(SRV_CURRENT).decode("ascii")
    return (
        "network-status-version 3 microdesc\n"
        "vote-status consensus\n"
        "consensus-method 33\n"
        f"valid-after {_timestamp(valid_after)}\n"
        f"fresh-until {_timestamp(fresh_until)}\n"
        f"valid-until {_timestamp(valid_until)}\n"
        "voting-delay 300 300\n"
        "client-versions 0.4.8.14\n"
        "server-versions 0.4.8.14\n"
        "known-flags Authority BadExit Exit Fast Guard HSDir MiddleOnly"
        " NoEdConsensus Running Stable StaleDesc V2Dir Valid\n"
        "params bwweightscale=10000 circwindow=1000"
        " sendme_accept_min_version=1 sendme_emit_min_version=1\n"
        f"shared-rand-previous-value 9 {srv_previous}\n"
        f"shared-rand-current-value 9 {srv_current}\n"
        f"{authority_section}"
        f"{router_section}"
        "directory-footer\n"
        "bandwidth-weights Wbd=0 Wbe=0 Wbg=4000 Wbm=10000 Wdb=10000 Wed=10000"
        " Wee=10000 Weg=10000 Wem=10000 Wgb=10000 Wgd=0 Wgg=6000 Wgm=6000"
        " Wmb=10000 Wmd=0 Wme=0 Wmg=4000 Wmm=10000\n"
    )


def sign_consensus(
    body: str,
    signers: tuple[tuple[DirectoryAuthority, rsa.RSAPrivateKey], ...],
    *,
    algorithm: str = "sha256",
) -> str:
    """Append ``directory-signature`` items covering the spec's signed region.

    Every signature covers ``body`` through the space after the first
    ``directory-signature`` keyword, so the digest is computed once, before any
    signature item is appended.
    """
    digest = hashlib.sha256((body + "directory-signature ").encode("utf-8")).digest()
    document = body
    for authority, key in signers:
        signature = base64.b64encode(sign_document_digest(key, digest)).decode("ascii")
        key_digest = signing_key_digest(key.public_key())
        document += (
            f"directory-signature {algorithm} {authority.v3ident.hex().upper()}"
            f" {key_digest.hex().upper()}\n"
            "-----BEGIN SIGNATURE-----\n"
            f"{_wrap64(signature)}\n"
            "-----END SIGNATURE-----\n"
        )
    return document


@lru_cache(maxsize=1)
def synthetic_directory() -> SyntheticDirectory:
    """Build (once per test session) the signed synthetic network."""
    signers = []
    authorities = []
    for nickname in ("authwest", "authnorth", "autheast"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        authority = DirectoryAuthority(
            nickname=nickname,
            v3ident=hashlib.sha1(b"synthetic authority: " + nickname.encode()).digest(),
            signing_key_pem=pem,
        )
        authorities.append(authority)
        signers.append((authority, key))

    microdescriptors = {spec.nickname: _microdescriptor(spec) for spec in _ROUTERS}
    expected = {}
    for spec in _ROUTERS:
        md_text = microdescriptors[spec.nickname]
        expected[spec.nickname] = RouterExpectation(
            nickname=spec.nickname,
            fingerprint=_fingerprint(spec.nickname),
            address=spec.address,
            or_port=spec.or_port,
            dir_port=spec.dir_port,
            flags=frozenset(spec.flags.split()),
            bandwidth=spec.bandwidth,
            ntor_onion_key=_ntor_key(spec.nickname),
            ed25519_id=_ed_identity(spec.nickname),
            md_digest=hashlib.sha256(md_text.encode("utf-8")).digest(),
        )

    ordered = sorted(_ROUTERS, key=lambda spec: _fingerprint(spec.nickname))
    router_section = "".join(
        _router_entry(spec, expected[spec.nickname].md_digest) for spec in ordered
    )
    authority_section = _authority_section(tuple(signers))
    body = consensus_body(authority_section=authority_section, router_section=router_section)
    return SyntheticDirectory(
        authorities=tuple(authorities),
        signers=tuple(signers),
        consensus_text=sign_consensus(body, tuple(signers)),
        unsigned_body=body,
        microdescriptors_text="".join(microdescriptors[spec.nickname] for spec in ordered),
        authority_section=authority_section,
        router_section=router_section,
        expected=expected,
    )
