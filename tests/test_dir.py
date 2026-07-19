"""Tests for the directory layer: parsing, verification, and path selection."""

from __future__ import annotations

import base64
import dataclasses
import gzip
import hashlib
import random
import urllib.request
import zlib
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from torquests._client import bootstrap
from torquests._client.bootstrap import LiveDirectory, _authorities_with_keys
from torquests._dir.authorities import DEFAULT_AUTHORITIES
from torquests._dir.consensus import (
    signing_key_digest,
    verify_consensus,
    verify_document_signature,
)
from torquests._dir.consensus_store import ConsensusStore
from torquests._dir.dirhttp import dir_get
from torquests._dir.guards import GuardManager
from torquests._dir.keycerts import KeyCertificate, parse_key_certificates
from torquests._dir.microdesc import usable_ed_identity
from torquests._dir.models import Consensus, RouterStatus
from torquests._dir.parsers import parse_consensus, parse_microdescriptors
from torquests._dir.pathselect import BandwidthWeights, PathSelector
from torquests.exceptions import ConsensusError, DirectoryError

from .dir_fixtures import (
    FRESH_UNTIL,
    NOW_LIVE,
    SRV_CURRENT,
    SRV_PREVIOUS,
    VALID_AFTER,
    VALID_UNTIL,
    SyntheticDirectory,
    consensus_body,
    sign_consensus,
    sign_document_digest,
    synthetic_directory,
)


@pytest.fixture(scope="module")
def network() -> SyntheticDirectory:
    return synthetic_directory()


@pytest.fixture(scope="module")
def consensus(network: SyntheticDirectory) -> Consensus:
    return parse_consensus(network.consensus_text)


@pytest.fixture(scope="module")
def matched(network: SyntheticDirectory, consensus: Consensus) -> dict[str, RouterStatus]:
    # Bind each microdescriptor to its router by the consensus 'm' digest and apply
    # the NoEdConsensus rule, so tests of the kept selectors see the same populated
    # RouterStatus the live client builds on demand.
    by_digest = {md.digest: md for md in parse_microdescriptors(network.microdescriptors_text)}
    routers: list[RouterStatus] = []
    for router in consensus.routers:
        descriptor = (
            by_digest.get(router.microdescriptor_digest)
            if router.microdescriptor_digest is not None
            else None
        )
        if descriptor is None:
            routers.append(router)
            continue
        ed_identity = usable_ed_identity(router.flags, descriptor)
        routers.append(
            dataclasses.replace(router, microdescriptor=descriptor, ed_identity=ed_identity)
        )
    return {router.nickname: router for router in routers}


# --------------------------------------------------------------------------- #
# Consensus parsing
# --------------------------------------------------------------------------- #


def test_parse_consensus_preamble(consensus: Consensus) -> None:
    assert consensus.valid_after == VALID_AFTER
    assert consensus.fresh_until == FRESH_UNTIL
    assert consensus.valid_until == VALID_UNTIL
    assert consensus.shared_random_current == SRV_CURRENT
    assert consensus.shared_random_previous == SRV_PREVIOUS
    assert consensus.params["circwindow"] == 1000
    assert consensus.params["bwweightscale"] == 10000
    assert consensus.is_live(NOW_LIVE)
    assert not consensus.is_live(datetime(2027, 1, 1, tzinfo=timezone.utc))


def test_parse_consensus_routers(network: SyntheticDirectory, consensus: Consensus) -> None:
    assert len(consensus.routers) == len(network.expected)
    by_nickname = {router.nickname: router for router in consensus.routers}
    for nickname, want in network.expected.items():
        router = by_nickname[nickname]
        assert router.fingerprint == want.fingerprint
        assert (router.address, router.or_port, router.dir_port) == (
            want.address,
            want.or_port,
            want.dir_port,
        )
        assert router.flags == want.flags
        assert router.bandwidth == want.bandwidth
        assert router.microdescriptor_digest == want.md_digest
        assert router.ed_identity is None  # not known before microdescriptors
    guardian1 = by_nickname["guardian1"]
    assert guardian1.is_guard and guardian1.is_hsdir and not guardian1.is_exit
    assert not by_nickname["rottenexit"].is_exit  # BadExit disqualifies
    assert by_nickname["exitpoint"].is_exit


def test_parse_consensus_signatures(network: SyntheticDirectory, consensus: Consensus) -> None:
    assert len(consensus.signatures) == 3
    identities = {signature.identity for signature in consensus.signatures}
    assert identities == {authority.v3ident for authority in network.authorities}
    assert all(signature.algorithm == "sha256" for signature in consensus.signatures)


def test_parse_consensus_bandwidth_weights(consensus: Consensus) -> None:
    weights = consensus.bandwidth_weights
    assert weights["Wgg"] == 6000  # Guard-flagged relay in the guard position
    assert weights["Wgd"] == 0  # a Guard+Exit relay is not wasted as a guard here
    assert weights["Wmg"] == 4000  # Guard-flagged relay down-weighted as a middle
    assert weights["Wmm"] == 10000  # a plain middle relay at full weight
    assert weights["Wee"] == 10000  # an exit at full weight in the exit position


def test_parse_rejects_non_microdesc_flavor(network: SyntheticDirectory) -> None:
    ns_flavored = network.consensus_text.replace(
        "network-status-version 3 microdesc", "network-status-version 3", 1
    )
    with pytest.raises(ConsensusError, match="microdesc"):
        parse_consensus(ns_flavored)


def test_parse_rejects_unsigned_document(network: SyntheticDirectory) -> None:
    with pytest.raises(ConsensusError, match="directory-signature"):
        parse_consensus(network.unsigned_body)


def test_parse_rejects_malformed_r_line(network: SyntheticDirectory) -> None:
    truncated = network.consensus_text.replace(" 2038-01-01 00:00:00 10.3.0.1 9001 0", "", 1)
    with pytest.raises(ConsensusError, match="r line"):
        parse_consensus(truncated)


def test_parse_rejects_bad_microdescriptor_digest(network: SyntheticDirectory) -> None:
    first_m = next(line for line in network.consensus_text.split("\n") if line.startswith("m "))
    mangled = network.consensus_text.replace(first_m, "m !!!not-base64!!!", 1)
    with pytest.raises(ConsensusError, match="base64"):
        parse_consensus(mangled)


def test_parse_rejects_missing_validity(network: SyntheticDirectory) -> None:
    body = network.consensus_text
    start = body.index("valid-until ")
    end = body.index("\n", start) + 1
    with pytest.raises(ConsensusError, match="valid-until"):
        parse_consensus(body[:start] + body[end:])


# --------------------------------------------------------------------------- #
# Microdescriptors
# --------------------------------------------------------------------------- #


def test_parse_microdescriptors_fields(network: SyntheticDirectory) -> None:
    descriptors = parse_microdescriptors(network.microdescriptors_text)
    assert len(descriptors) == len(network.expected)
    by_digest = {descriptor.digest: descriptor for descriptor in descriptors}
    for want in network.expected.values():
        descriptor = by_digest[want.md_digest]
        assert descriptor.ntor_onion_key == want.ntor_onion_key
        assert descriptor.ed25519_id == want.ed25519_id
    exitpoint = by_digest[network.expected["exitpoint"].md_digest]
    assert exitpoint.exit_policy is not None and exitpoint.exit_policy.accept
    assert exitpoint.exit_policy.allows(443)
    assert exitpoint.exit_policy.allows(8500)
    assert not exitpoint.exit_policy.allows(22)
    kinsman_id = "$" + network.expected["kinsman"].fingerprint.hex().upper()
    assert kinsman_id in exitpoint.family
    middleman = by_digest[network.expected["middleman"].md_digest]
    assert middleman.exit_policy is None  # no 'p' line: reject everything


def test_parse_microdescriptors_edge_cases() -> None:
    assert parse_microdescriptors("") == []
    with pytest.raises(ConsensusError, match="ntor-onion-key"):
        parse_microdescriptors("onion-key\np accept 80\n")
    with pytest.raises(ConsensusError, match="onion-key"):
        parse_microdescriptors("ntor-onion-key AAAA\n")


# --------------------------------------------------------------------------- #
# Consensus verification
# --------------------------------------------------------------------------- #


def test_verify_consensus_all_signatures(network: SyntheticDirectory) -> None:
    verified = verify_consensus(network.consensus_text, network.authorities, now=NOW_LIVE)
    assert len(verified.routers) == len(network.expected)


def test_verify_consensus_majority_is_enough(network: SyntheticDirectory) -> None:
    two_of_three = sign_consensus(network.unsigned_body, network.signers[:2])
    verified = verify_consensus(two_of_three, network.authorities, now=NOW_LIVE)
    assert verified.valid_after == VALID_AFTER


def test_verify_consensus_minority_fails(network: SyntheticDirectory) -> None:
    one_of_three = sign_consensus(network.unsigned_body, network.signers[:1])
    with pytest.raises(ConsensusError, match="1 of 3"):
        verify_consensus(one_of_three, network.authorities, now=NOW_LIVE)


def test_verify_consensus_quorum_counts_keyless_authorities(
    network: SyntheticDirectory,
) -> None:
    # Withholding an authority's signing-key cert must not lower the majority
    # threshold. Here only one authority has a key and its signature verifies, but
    # one valid signature is a minority of the FULL three-authority set (the other
    # two are keyless), so the consensus is rejected as "1 of 3", not accepted as
    # "1 of 1".
    one_signed = sign_consensus(network.unsigned_body, network.signers[:1])
    keyed, *keyless = network.authorities
    authorities = [keyed, *(dataclasses.replace(a, signing_key_pem=None) for a in keyless)]
    with pytest.raises(ConsensusError, match="1 of 3"):
        verify_consensus(one_signed, authorities, now=NOW_LIVE)


def test_authorities_with_keys_covers_full_set() -> None:
    # The helper always returns one entry per authority, carrying the fetched key
    # where a cert exists and staying bare otherwise, so the denominator the quorum
    # is measured against is always the full authority set.
    authorities = list(DEFAULT_AUTHORITIES)  # production authorities carry no key
    certs = {
        a.v3ident: KeyCertificate(a.v3ident, f"PEM-{i}".encode())
        for i, a in enumerate(authorities[:2])
    }
    result = _authorities_with_keys(authorities, certs)
    assert len(result) == len(authorities)
    assert [a.v3ident for a in result] == [a.v3ident for a in authorities]
    assert result[0].signing_key_pem == b"PEM-0"
    assert result[1].signing_key_pem == b"PEM-1"
    assert all(a.signing_key_pem is None for a in result[2:])  # bare where no cert


def test_verify_consensus_tampered_body_fails(network: SyntheticDirectory) -> None:
    tampered = network.consensus_text.replace("w Bandwidth=15000", "w Bandwidth=99999")
    assert tampered != network.consensus_text
    with pytest.raises(ConsensusError, match="0 of 3"):
        verify_consensus(tampered, network.authorities, now=NOW_LIVE)


def test_verify_consensus_unknown_algorithm_not_counted(
    network: SyntheticDirectory,
) -> None:
    exotic = sign_consensus(network.unsigned_body, network.signers, algorithm="sha512")
    with pytest.raises(ConsensusError, match="0 of 3"):
        verify_consensus(exotic, network.authorities, now=NOW_LIVE)


def test_verify_consensus_expired(network: SyntheticDirectory) -> None:
    body = consensus_body(
        authority_section=network.authority_section,
        router_section=network.router_section,
        valid_after=datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc),
        fresh_until=datetime(2025, 1, 1, 13, 0, tzinfo=timezone.utc),
        valid_until=datetime(2025, 1, 1, 15, 0, tzinfo=timezone.utc),
    )
    expired = sign_consensus(body, network.signers)
    with pytest.raises(ConsensusError, match="expired"):
        verify_consensus(expired, network.authorities, now=NOW_LIVE)


def test_verify_consensus_not_yet_valid(network: SyntheticDirectory) -> None:
    with pytest.raises(ConsensusError, match="not yet valid"):
        verify_consensus(
            network.consensus_text,
            network.authorities,
            now=datetime(2025, 12, 31, 23, 0, tzinfo=timezone.utc),
        )


def test_verify_consensus_requires_aware_now(network: SyntheticDirectory) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        verify_consensus(
            network.consensus_text, network.authorities, now=datetime(2026, 1, 1, 12, 30)
        )


def test_verify_consensus_requires_authorities(network: SyntheticDirectory) -> None:
    with pytest.raises(ConsensusError, match="no directory authorities"):
        verify_consensus(network.consensus_text, [], now=NOW_LIVE)


def test_verify_document_signature_helper() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    digest = hashlib.sha256(b"a known signed region").digest()
    signature = sign_document_digest(key, digest)
    assert verify_document_signature(key.public_key(), signature, digest)
    other = hashlib.sha256(b"a different region").digest()
    assert not verify_document_signature(key.public_key(), signature, other)
    corrupted = bytes([signature[0] ^ 0x01]) + signature[1:]
    assert not verify_document_signature(key.public_key(), corrupted, digest)
    # A standard PKCS#1 v1.5 signature embeds DigestInfo, which Tor omits; the
    # helper must therefore reject what cryptography's hash-and-sign produces.
    standard = key.sign(b"a known signed region", padding.PKCS1v15(), hashes.SHA256())
    assert not verify_document_signature(key.public_key(), standard, digest)


# --------------------------------------------------------------------------- #
# Authority key certificates (the consensus trust anchor)
# --------------------------------------------------------------------------- #


def _pkcs1_pem(key: rsa.RSAPrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
        .decode("ascii")
    )


def _key_certificate_text(
    identity_key: rsa.RSAPrivateKey,
    signing_key: rsa.RSAPrivateKey,
    *,
    fingerprint: str | None = None,
    signer: rsa.RSAPrivateKey | None = None,
) -> str:
    """Assemble a ``dir-key-certificate-version 3`` document (dir-spec).

    The identity key certifies the signing key: the ``fingerprint`` names the
    identity key (its PKCS#1 SHA-1 digest) and the ``dir-key-certification``
    signature is a Tor-style PKCS#1 signature by the identity key over the region
    up to and including that keyword line. ``fingerprint``/``signer`` overrides
    drive the mismatch and forged-signature rejections.
    """
    if fingerprint is None:
        fingerprint = signing_key_digest(identity_key.public_key()).hex().upper()
    prefix = (
        "dir-key-certificate-version 3\n"
        f"fingerprint {fingerprint}\n"
        "dir-identity-key\n"
        f"{_pkcs1_pem(identity_key)}"
        "dir-key-published 2026-01-01 00:00:00\n"
        "dir-key-expires 2027-01-01 00:00:00\n"
        "dir-signing-key\n"
        f"{_pkcs1_pem(signing_key)}"
        "dir-key-certification\n"
    )
    digest = hashlib.sha1(prefix.encode("ascii")).digest()
    signature = sign_document_digest(signer or identity_key, digest)
    encoded = base64.b64encode(signature).decode("ascii")
    wrapped = "\n".join(encoded[i : i + 64] for i in range(0, len(encoded), 64))
    return prefix + f"-----BEGIN SIGNATURE-----\n{wrapped}\n-----END SIGNATURE-----\n"


def _rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def test_key_certificate_binds_signing_key() -> None:
    identity, signing = _rsa_key(), _rsa_key()
    (cert,) = parse_key_certificates(_key_certificate_text(identity, signing))
    # The verified cert carries the identity's v3ident and binds the signing key.
    assert cert.v3ident == signing_key_digest(identity.public_key())
    bound = serialization.load_pem_public_key(cert.signing_key_pem)
    assert isinstance(bound, rsa.RSAPublicKey)
    assert bound.public_numbers() == signing.public_key().public_numbers()


def test_key_certificate_forged_self_signature_is_dropped() -> None:
    identity, signing, attacker = _rsa_key(), _rsa_key(), _rsa_key()
    # The dir-key-certification is signed by an attacker key, not the identity, so
    # it does not verify under the identity key and must be dropped.
    text = _key_certificate_text(identity, signing, signer=attacker)
    assert parse_key_certificates(text) == []


def test_key_certificate_fingerprint_mismatch_is_dropped() -> None:
    identity, signing = _rsa_key(), _rsa_key()
    # The fingerprint does not match the identity key's digest: the cert claims an
    # identity it cannot prove, so it is rejected before its signature is trusted.
    text = _key_certificate_text(identity, signing, fingerprint="00" * 20)
    assert parse_key_certificates(text) == []


# --------------------------------------------------------------------------- #
# Path selection
# --------------------------------------------------------------------------- #


def _selector(matched: dict[str, RouterStatus], *nicknames: str, seed: int = 1234) -> PathSelector:
    routers = [matched[nickname] for nickname in nicknames] if nicknames else list(matched.values())
    return PathSelector(routers, rng=random.Random(seed))


def test_select_guard_rejects_shared_subnet(matched: dict[str, RouterStatus]) -> None:
    selector = _selector(matched, "guardian1", "nearguard")
    with pytest.raises(ConsensusError, match="guard"):
        selector.select_guard(exclude=[matched["guardian1"]])


def test_select_middle_rejects_family(matched: dict[str, RouterStatus]) -> None:
    conflicted = _selector(matched, "exitpoint", "kinsman")
    with pytest.raises(ConsensusError, match="middle"):
        conflicted.select_middle(exclude=[matched["exitpoint"]])
    fallback = _selector(matched, "exitpoint", "kinsman", "middleman")
    for seed in range(10):
        selector = _selector(matched, "exitpoint", "kinsman", "middleman", seed=seed)
        assert selector.select_middle(exclude=[matched["exitpoint"]]).nickname == "middleman"
    assert fallback.select_middle(exclude=[matched["exitpoint"]]).nickname == "middleman"


def test_selection_is_bandwidth_weighted(matched: dict[str, RouterStatus]) -> None:
    selector = _selector(matched, "guardian1", "guardian2", seed=0)
    picks = [selector.select_guard().nickname for _ in range(2000)]
    share = picks.count("guardian1") / len(picks)
    assert 0.55 < share < 0.65  # 30000 / (30000 + 20000) = 0.6


def _router_status(flags: set[str], *, bandwidth: int = 1000, nickname: str = "r") -> RouterStatus:
    return RouterStatus(
        nickname=nickname,
        fingerprint=hashlib.sha1(nickname.encode()).digest(),
        address="10.9.0.1",
        or_port=9001,
        dir_port=0,
        flags=frozenset(flags),
        bandwidth=bandwidth,
        microdescriptor_digest=None,
    )


def test_bandwidth_weights_factor_by_position_and_class(consensus: Consensus) -> None:
    weights = BandwidthWeights(consensus.bandwidth_weights, 10000)
    guard_only = _router_status({"Guard", "Running", "Valid"})
    exit_only = _router_status({"Exit", "Running", "Valid"})
    dual = _router_status({"Guard", "Exit", "Running", "Valid"})
    plain = _router_status({"Running", "Valid"})
    assert weights.factor(guard_only, "guard") == 0.6  # Wgg=6000
    assert weights.factor(exit_only, "guard") == 0.0  # an exit-only relay cannot guard
    assert weights.factor(guard_only, "middle") == 0.4  # Wmg=4000
    assert weights.factor(plain, "middle") == 1.0  # Wmm=10000
    assert weights.factor(exit_only, "middle") == 0.0  # Wme=0
    assert weights.factor(dual, "exit") == 1.0  # Wed=10000, a dual relay as an exit
    assert weights.factor(exit_only, "exit") == 1.0  # Wee=10000
    assert weights.factor(guard_only, "hsdir") == 1.0  # unweighted position stays raw


def test_selection_applies_position_weights(
    consensus: Consensus, matched: dict[str, RouterStatus]
) -> None:
    weights = BandwidthWeights(consensus.bandwidth_weights, consensus.params["bwweightscale"])
    routers = [matched["guardian1"], matched["middleman"]]
    weighted = PathSelector(routers, rng=random.Random(0), weights=weights)
    weighted_share = [weighted.select_middle().nickname for _ in range(3000)].count(
        "guardian1"
    ) / 3000
    # guardian1 (Guard-flagged, bw 30000) is down-weighted to Wmg=0.4x as a middle:
    # 30000*0.4 / (30000*0.4 + 15000) = 12000/27000 = 0.444.
    assert 0.41 < weighted_share < 0.48
    raw = PathSelector(routers, rng=random.Random(0))
    raw_share = [raw.select_middle().nickname for _ in range(3000)].count("guardian1") / 3000
    # Without weights it tracks raw bandwidth: 30000 / (30000 + 15000) = 0.667.
    assert 0.62 < raw_share < 0.71


# --------------------------------------------------------------------------- #
# Guards
# --------------------------------------------------------------------------- #


def test_guard_manager_samples_primary_guards(
    matched: dict[str, RouterStatus],
) -> None:
    routers = list(matched.values())
    manager = GuardManager(sample_size=2, rng=random.Random(7))
    manager.update(routers)
    primary = manager.primary_guards(routers)
    assert len(primary) == 2
    assert all(
        router.flags >= {"Guard", "Stable", "Fast", "V2Dir", "Running", "Valid"}
        for router in primary
    )


def test_guard_manager_replaces_unlisted_and_relists(
    matched: dict[str, RouterStatus],
) -> None:
    routers = list(matched.values())
    manager = GuardManager(sample_size=1, rng=random.Random(7))
    manager.update(routers)
    (original,) = manager.primary_guards(routers)
    without = [router for router in routers if router.nickname != original.nickname]
    manager.update(without)
    (replacement,) = manager.primary_guards(without)
    assert replacement.nickname != original.nickname
    # The original returns: it regains its place at the head of the sample order.
    manager.update(routers)
    assert manager.primary_guards(routers)[0].nickname == original.nickname


# --------------------------------------------------------------------------- #
# Directory HTTP
# --------------------------------------------------------------------------- #


class FakeDirStream:
    """A stream-shaped object replaying one canned HTTP response."""

    def __init__(self, response: bytes) -> None:
        self._response = response
        self._position = 0
        self.sent = bytearray()

    def send(self, data: bytes) -> None:
        self.sent += data

    def recv(self, max_bytes: int) -> bytes:
        chunk = self._response[self._position : self._position + max_bytes]
        self._position += len(chunk)
        return chunk


def _response(body: bytes, *headers: str, status: str = "200 OK") -> bytes:
    head = f"HTTP/1.0 {status}\r\n" + "".join(h + "\r\n" for h in headers) + "\r\n"
    return head.encode("ascii") + body


def test_dir_get_content_length() -> None:
    stream = FakeDirStream(_response(b"consensus bytes", "Content-Length: 15"))
    body = dir_get(stream, "/tor/status-vote/current/consensus-microdesc")
    assert body == b"consensus bytes"
    request = bytes(stream.sent).decode("ascii")
    assert request.startswith("GET /tor/status-vote/current/consensus-microdesc HTTP/1.0\r\n")
    assert "Host: 127.0.0.1\r\n" in request
    assert request.endswith("\r\n\r\n")


def test_dir_get_reads_to_eof_without_content_length() -> None:
    stream = FakeDirStream(_response(b"x" * 10000))
    assert dir_get(stream, "/tor/micro/d/xyz") == b"x" * 10000


def test_dir_get_rejects_non_200() -> None:
    stream = FakeDirStream(_response(b"nope", status="404 Not found"))
    with pytest.raises(DirectoryError, match="404"):
        dir_get(stream, "/tor/micro/d/missing")


def test_dir_get_inflates_deflate_and_gzip() -> None:
    payload = b"microdescriptor " * 100
    deflated = zlib.compress(payload)
    stream = FakeDirStream(
        _response(deflated, f"Content-Length: {len(deflated)}", "Content-Encoding: deflate")
    )
    assert dir_get(stream, "/tor/micro/d/abc.z") == payload
    gzipped = gzip.compress(payload)
    stream = FakeDirStream(_response(gzipped, "Content-Encoding: gzip"))
    assert dir_get(stream, "/tor/micro/d/abc") == payload


def test_dir_get_truncated_body_fails() -> None:
    stream = FakeDirStream(_response(b"short", "Content-Length: 100"))
    with pytest.raises(DirectoryError, match="truncated"):
        dir_get(stream, "/tor/status-vote/current/consensus-microdesc")


def test_dir_get_rejects_unknown_encoding() -> None:
    stream = FakeDirStream(_response(b"data", "Content-Encoding: br"))
    with pytest.raises(DirectoryError, match="Content-Encoding"):
        dir_get(stream, "/tor/micro/d/abc")


# --------------------------------------------------------------------------- #
# LiveDirectory: a stable entry guard across circuits (guard-spec)
# --------------------------------------------------------------------------- #


def _live_directory(
    consensus: Consensus,
    network: SyntheticDirectory,
    monkeypatch: pytest.MonkeyPatch,
    *,
    seed: int,
) -> LiveDirectory:
    def fake_fetch(path: str, mirrors: object, timeout: float, rng: random.Random) -> str:
        return network.microdescriptors_text  # every micro/d fetch serves the whole batch

    monkeypatch.setattr(bootstrap, "_fetch", fake_fetch)
    return LiveDirectory(consensus, [("dir.example", 80)], timeout=1.0, rng=random.Random(seed))


def test_live_directory_reuses_one_stable_guard(
    consensus: Consensus, network: SyntheticDirectory, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = _live_directory(consensus, network, monkeypatch, seed=3)
    target = next(r for r in consensus.routers if r.nickname == "middleman")
    guards = [
        live.path_provider("example.com", 443)[0].identity_digest,
        live.path_to(target)[0].identity_digest,
        live.rendezvous_path()[0].identity_digest,
        live.path_provider("other.example", 443)[0].identity_digest,
    ]
    assert len(set(guards)) == 1  # every path enters through the same guard
    guard = next(r for r in consensus.routers if r.fingerprint == guards[0])
    assert guard.flags >= {"Guard", "Stable", "Fast", "V2Dir", "Running", "Valid"}


def test_live_directory_guard_changes_only_when_it_leaves_consensus(
    consensus: Consensus, network: SyntheticDirectory, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = _live_directory(consensus, network, monkeypatch, seed=3)
    guard_fp = live.path_provider("example.com", 443)[0].identity_digest
    # Same consensus, same seed: the very same guard. It is stable, not re-rolled.
    again = LiveDirectory(consensus, [("dir.example", 80)], timeout=1.0, rng=random.Random(3))
    assert again.path_provider("example.com", 443)[0].identity_digest == guard_fp
    # Drop that guard from the consensus: a different, still-valid guard is used.
    reduced = dataclasses.replace(
        consensus, routers=[r for r in consensus.routers if r.fingerprint != guard_fp]
    )
    other = LiveDirectory(reduced, [("dir.example", 80)], timeout=1.0, rng=random.Random(3))
    other_fp = other.path_provider("example.com", 443)[0].identity_digest
    assert other_fp != guard_fp
    replacement = next(r for r in reduced.routers if r.fingerprint == other_fp)
    assert replacement.flags >= {"Guard", "Stable", "Fast", "V2Dir", "Running", "Valid"}


# --------------------------------------------------------------------------- #
# LiveDirectory: family separation and NoEdConsensus in the production path
# --------------------------------------------------------------------------- #


def test_usable_ed_identity_honors_noedconsensus(
    network: SyntheticDirectory, matched: dict[str, RouterStatus]
) -> None:
    nearguard = matched["nearguard"]
    assert nearguard.microdescriptor is not None
    # The microdescriptor names an ed key, but the NoEdConsensus flag forbids it.
    assert "NoEdConsensus" in nearguard.flags
    assert usable_ed_identity(nearguard.flags, nearguard.microdescriptor) is None
    guardian1 = matched["guardian1"]
    assert guardian1.microdescriptor is not None
    assert usable_ed_identity(guardian1.flags, guardian1.microdescriptor) == (
        network.expected["guardian1"].ed25519_id
    )


def test_live_relay_info_drops_noedconsensus_identity(
    consensus: Consensus, network: SyntheticDirectory, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = _live_directory(consensus, network, monkeypatch, seed=1)
    live._fetch_microdescriptors(list(consensus.routers))
    nearguard = next(r for r in consensus.routers if r.nickname == "nearguard")
    # The live path must apply the same NoEdConsensus rule as attach: a relay whose
    # ed identity the consensus disavows cannot become a usable RelayInfo.
    with pytest.raises(DirectoryError, match="ed25519"):
        live._relay_info(nearguard)
    guardian1 = next(r for r in consensus.routers if r.nickname == "guardian1")
    assert live._relay_info(guardian1).ed_identity == network.expected["guardian1"].ed25519_id


def test_live_path_provider_excludes_same_family(
    consensus: Consensus, network: SyntheticDirectory, monkeypatch: pytest.MonkeyPatch
) -> None:
    # exitpoint and kinsman declare each other in family; kinsman is otherwise a
    # fine middle. With exitpoint forced as the 443 exit, the middle must never be
    # its family member. Reduce the consensus so kinsman and middleman are the only
    # middle candidates, making the constraint easy to violate by chance.
    by_nick = {r.nickname: r for r in consensus.routers}
    reduced = dataclasses.replace(
        consensus,
        routers=[by_nick[n] for n in ("guardian2", "exitpoint", "kinsman", "middleman")],
    )
    exit_fp = network.expected["exitpoint"].fingerprint
    kinsman_fp = network.expected["kinsman"].fingerprint
    middles: set[bytes] = set()
    for seed in range(20):
        live = _live_directory(reduced, network, monkeypatch, seed=seed)
        path = live.path_provider("example.com", 443)
        assert path[-1].identity_digest == exit_fp  # exitpoint is the only 443 exit
        middles.add(path[1].identity_digest)
    assert kinsman_fp not in middles  # the exit's family member is never the middle
    assert middles == {network.expected["middleman"].fingerprint}


# --------------------------------------------------------------------------- #
# Bootstrap fetch fingerprint (no tool User-Agent, shuffled mirror order)
# --------------------------------------------------------------------------- #


def test_http_get_sends_no_tool_identifying_user_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def read(self) -> bytes:
            return b"body"

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> _Response:
        captured["user_agent"] = request.get_header("User-agent")
        captured["headers"] = request.header_items()
        return _Response()

    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", fake_urlopen)
    assert bootstrap._http_get("dir.example", 80, "/tor/keys/all", 1.0) == b"body"
    user_agent = captured["user_agent"]
    # An explicit empty User-Agent is set on the request, which suppresses urllib's
    # "Python-urllib/<ver>" default (verified against urllib: it then sends
    # "User-Agent:" with no value rather than substituting its own).
    assert user_agent == ""
    assert "torquests" not in str(user_agent).lower()
    headers = captured["headers"]
    assert isinstance(headers, list)
    assert all("torquests" not in str(value).lower() for _, value in headers)
    assert all("python-urllib" not in str(value).lower() for _, value in headers)


def test_fetch_shuffles_the_mirror_order(monkeypatch: pytest.MonkeyPatch) -> None:
    mirrors = [("m1", 1), ("m2", 2), ("m3", 3), ("m4", 4), ("m5", 5)]
    contacted: list[tuple[str, int]] = []

    def fake_http_get(host: str, port: int, path: str, timeout: float) -> bytes:
        contacted.append((host, port))
        raise OSError("unreachable")

    monkeypatch.setattr(bootstrap, "_http_get", fake_http_get)
    with pytest.raises(DirectoryError):
        bootstrap._fetch("/tor/keys/all", mirrors, 1.0, random.Random(1))
    assert sorted(contacted) == sorted(mirrors)  # each mirror is tried once: a permutation
    assert contacted != mirrors  # and not in the fixed input order


def test_get_directory_rebootstraps_when_the_consensus_expires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A client created after the cached consensus expires gets a fresh directory."""

    class _Consensus:
        def __init__(self, live: bool) -> None:
            self._live = live

        def is_live(self, now: object) -> bool:
            return self._live

    class _Directory:
        def __init__(self, live: bool) -> None:
            self.consensus = _Consensus(live)

    produced = [_Directory(live=False), _Directory(live=True)]
    builds: list[int] = []

    def fake_bootstrap(*, timeout: float = 60.0, cache_dir: object = None) -> object:
        directory = produced[len(builds)]
        builds.append(1)
        return directory

    monkeypatch.setattr(bootstrap, "_cached_directory", None)
    monkeypatch.setattr(bootstrap, "bootstrap", fake_bootstrap)

    first = bootstrap.get_directory()  # cache empty: build the (already expired) directory
    second = bootstrap.get_directory()  # cached is expired: rebuild into the live one
    third = bootstrap.get_directory()  # cached is live: reuse, no rebuild

    assert first is produced[0]
    assert second is produced[1]
    assert third is produced[1]
    assert len(builds) == 2


def test_get_directory_forwards_cache_dir_to_bootstrap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The cache directory set on a client reaches the bootstrap that reads it."""
    seen: dict[str, object] = {}

    def fake_bootstrap(*, timeout: float = 60.0, cache_dir: object = None) -> object:
        seen["cache_dir"] = cache_dir
        return object()

    monkeypatch.setattr(bootstrap, "_cached_directory", None)
    monkeypatch.setattr(bootstrap, "bootstrap", fake_bootstrap)
    bootstrap.get_directory(cache_dir=tmp_path)
    assert seen["cache_dir"] == tmp_path


def _offline_cache_bootstrap(
    network: SyntheticDirectory,
    monkeypatch: pytest.MonkeyPatch,
    consensus_fetches: list[str],
) -> None:
    """Wire bootstrap() to run fully offline against the synthetic network at NOW_LIVE.

    Key certificates are stubbed to the synthetic authorities' own keys, the mirror
    fetch serves the signed consensus (recording only the consensus fetches), and the
    clock is pinned inside the fixture's validity window so verification passes.
    """
    certs = [KeyCertificate(a.v3ident, a.signing_key_pem) for a in network.authorities]
    # bootstrap() imports parse_key_certificates lazily, so patch it on its source
    # module; the call-time `from .._dir.keycerts import ...` then picks up the stub.
    monkeypatch.setattr("torquests._dir.keycerts.parse_key_certificates", lambda text: certs)

    def fake_fetch(path: str, mirrors: object, timeout: float, rng: random.Random) -> str:
        if "consensus" in path:
            consensus_fetches.append(path)
            return network.consensus_text
        return "stub key-certificate document"

    monkeypatch.setattr(bootstrap, "_fetch", fake_fetch)

    class _FrozenClock:
        @staticmethod
        def now(tz: object = None) -> datetime:
            return NOW_LIVE

    monkeypatch.setattr(bootstrap, "datetime", _FrozenClock)


def test_bootstrap_writes_then_reuses_the_consensus_cache(
    network: SyntheticDirectory, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fetches: list[str] = []
    _offline_cache_bootstrap(network, monkeypatch, fetches)

    first = bootstrap.bootstrap(authorities=network.authorities, cache_dir=tmp_path)
    assert first.consensus.valid_after == VALID_AFTER
    assert (tmp_path / "cached-microdesc-consensus").exists()
    assert len(fetches) == 1  # a cold start fetches the consensus once

    second = bootstrap.bootstrap(authorities=network.authorities, cache_dir=tmp_path)
    assert second.consensus.valid_after == VALID_AFTER
    assert len(fetches) == 1  # a warm start reuses the cached consensus, no refetch


def test_bootstrap_survives_an_unwritable_cache(
    network: SyntheticDirectory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fetches: list[str] = []
    _offline_cache_bootstrap(network, monkeypatch, fetches)

    def unwritable(self: ConsensusStore, consensus_text: str) -> None:
        raise OSError("read-only file system")

    monkeypatch.setattr(ConsensusStore, "save", unwritable)
    with caplog.at_level("WARNING"):
        directory = bootstrap.bootstrap(authorities=network.authorities, cache_dir=tmp_path)
    # The cache write failed, but the bootstrap itself did not: it warns and carries on.
    assert directory.consensus.valid_after == VALID_AFTER
    assert any("consensus cache" in record.message for record in caplog.records)
