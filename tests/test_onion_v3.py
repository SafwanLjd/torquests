"""Tests for the v3 HSDir hash ring and descriptor decoder.

The hash-ring functions are pinned structurally against the spec formulas (in
particular the deliberately different field order between ``hs_index`` and
``hsdir_index``), and the selection is checked for determinism and against an
independent ring walk. The descriptor decoder is exercised end-to-end with a
service-side builder (``onion_fixtures``), including tamper, wrong-subcredential,
and client-authorization paths.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from tests import onion_fixtures as fx
from torquests._crypto import ed25519_blind as kb
from torquests._crypto.primitives import sha3_256, x25519_keypair
from torquests._onion import hsdir
from torquests._onion.descriptor import (
    decrypt_first_layer,
    derive_descriptor_cookie,
    parse_descriptor,
    parse_descriptor_with_auth,
)
from torquests._proto.constants import CertType
from torquests.exceptions import DescriptorError, OnionClientAuthRequired

from .crypto_helpers import ed25519_public_from_seed

SERVICE_SEED = bytes(range(32))

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _int8(value: int) -> bytes:
    return struct.pack(">Q", value)


# --------------------------------------------------------------------------- #
# Hash ring
# --------------------------------------------------------------------------- #


def test_hs_index_matches_spec_formula() -> None:
    bp = ed25519_public_from_seed(SERVICE_SEED)
    replica, plen, pnum = 1, 1440, 16903
    expected = sha3_256(b"store-at-idx" + bp + _int8(replica) + _int8(plen) + _int8(pnum))
    assert hsdir.hs_index(bp, replica, plen, pnum) == expected


def test_hsdir_index_matches_spec_formula() -> None:
    node_id = sha3_256(b"node")
    srv = sha3_256(b"srv")
    pnum, plen = 16903, 1440
    expected = sha3_256(b"node-idx" + node_id + srv + _int8(pnum) + _int8(plen))
    assert hsdir.hsdir_index(node_id, srv, pnum, plen) == expected


def test_index_field_order_differs() -> None:
    # hs_index feeds period_length then period_num; hsdir_index feeds the reverse.
    # Swapping the two arguments must change each digest (they are not symmetric).
    bp = ed25519_public_from_seed(SERVICE_SEED)
    assert hsdir.hs_index(bp, 1, 1440, 16903) != hsdir.hs_index(bp, 1, 16903, 1440)
    node_id = sha3_256(b"n")
    srv = sha3_256(b"s")
    assert hsdir.hsdir_index(node_id, srv, 16903, 1440) != hsdir.hsdir_index(
        node_id, srv, 1440, 16903
    )


def test_disaster_srv_matches_spec_formula() -> None:
    plen, pnum = 1440, 16903
    expected = sha3_256(b"shared-random-disaster" + _int8(plen) + _int8(pnum))
    assert hsdir.disaster_srv(plen, pnum) == expected


@dataclass(frozen=True)
class _Node:
    ed_identity: bytes


def _make_nodes(count: int) -> list[_Node]:
    return [_Node(sha3_256(b"node" + _int8(i))) for i in range(count)]


def _reference_selection(
    blinded_pubkey: bytes,
    nodes: list[_Node],
    srv: bytes,
    period_num: int,
    period_length: int,
    n_replicas: int,
    spread_fetch: int,
) -> list[_Node]:
    """An independent ring walk (linear search) to cross-check the module."""
    ordered = sorted(
        nodes, key=lambda n: hsdir.hsdir_index(n.ed_identity, srv, period_num, period_length)
    )
    indices = [hsdir.hsdir_index(n.ed_identity, srv, period_num, period_length) for n in ordered]
    total = len(ordered)
    chosen: list[_Node] = []
    seen: set[bytes] = set()
    for replica in range(1, n_replicas + 1):
        target = hsdir.hs_index(blinded_pubkey, replica, period_length, period_num)
        start = next((i for i, idx in enumerate(indices) if idx >= target), total) % total
        pos, added = start, 0
        while added < spread_fetch:
            node = ordered[pos]
            if node.ed_identity not in seen:
                seen.add(node.ed_identity)
                chosen.append(node)
                added += 1
            pos = (pos + 1) % total
            if pos == start:
                break
    return chosen


def test_responsible_hsdirs_deterministic_and_correct() -> None:
    bp = ed25519_public_from_seed(SERVICE_SEED)
    srv = sha3_256(b"the-srv")
    nodes = _make_nodes(30)
    pnum, plen = 16903, 1440

    first = hsdir.responsible_hsdirs(bp, nodes, srv, pnum, plen)
    second = hsdir.responsible_hsdirs(bp, nodes, srv, pnum, plen)
    assert [n.ed_identity for n in first] == [n.ed_identity for n in second]

    # Default replicas=2, spread_fetch=3 -> up to 6 distinct relays.
    assert 0 < len(first) <= 6
    assert len({n.ed_identity for n in first}) == len(first)
    node_ids = {n.ed_identity for n in nodes}
    assert all(n.ed_identity in node_ids for n in first)

    reference = _reference_selection(bp, nodes, srv, pnum, plen, 2, 3)
    assert [n.ed_identity for n in first] == [n.ed_identity for n in reference]


def test_responsible_hsdirs_spread_parameters() -> None:
    bp = ed25519_public_from_seed(SERVICE_SEED)
    srv = sha3_256(b"srv2")
    nodes = _make_nodes(40)
    picked = hsdir.responsible_hsdirs(bp, nodes, srv, 16903, 1440, n_replicas=3, spread_fetch=4)
    assert len(picked) == 12
    assert len({n.ed_identity for n in picked}) == 12


def test_responsible_hsdirs_fewer_nodes_than_slots() -> None:
    bp = ed25519_public_from_seed(SERVICE_SEED)
    srv = sha3_256(b"srv3")
    nodes = _make_nodes(4)
    picked = hsdir.responsible_hsdirs(bp, nodes, srv, 16903, 1440)
    # Cannot pick more distinct relays than exist.
    assert len(picked) == 4
    assert len({n.ed_identity for n in picked}) == 4


def test_responsible_hsdirs_empty() -> None:
    bp = ed25519_public_from_seed(SERVICE_SEED)
    assert hsdir.responsible_hsdirs(bp, [], sha3_256(b"x"), 16903, 1440) == []


# --------------------------------------------------------------------------- #
# Descriptor round trip
# --------------------------------------------------------------------------- #


def test_fixture_derives_expected_blinded_key_and_subcredential() -> None:
    built = fx.build_descriptor(SERVICE_SEED, [fx.random_intro_point()])
    identity_pub = ed25519_public_from_seed(SERVICE_SEED)
    assert built.blinded_pubkey == kb.blind_public_key(
        identity_pub, fx.DEFAULT_PERIOD_NUM, fx.DEFAULT_PERIOD_LENGTH
    )
    assert built.subcredential == kb.subcredential(identity_pub, built.blinded_pubkey)


def test_full_round_trip_recovers_intro_points() -> None:
    specs = [fx.random_intro_point() for _ in range(3)]
    built = fx.build_descriptor(SERVICE_SEED, specs, revision_counter=42, lifetime_minutes=180)

    desc = parse_descriptor(built.text, built.blinded_pubkey, built.subcredential)

    assert desc.lifetime == 180
    assert desc.revision_counter == 42
    assert len(desc.intro_points) == 3
    for spec, parsed in zip(specs, desc.intro_points, strict=True):
        assert parsed.link_specifiers == spec.link_specifiers
        assert parsed.onion_key == spec.onion_key
        assert parsed.auth_key == spec.auth_key_pubkey
        assert parsed.enc_key == spec.enc_key


def test_round_trip_no_intro_points() -> None:
    built = fx.build_descriptor(SERVICE_SEED, [])
    desc = parse_descriptor(built.text, built.blinded_pubkey, built.subcredential)
    assert desc.intro_points == []


def test_tampered_signature_rejected() -> None:
    built = fx.build_descriptor(SERVICE_SEED, [fx.random_intro_point()])
    lines = built.text.split("\n")
    sig_index = next(i for i, ln in enumerate(lines) if ln.startswith("signature "))
    keyword, value = lines[sig_index].split(" ", 1)
    # Flip one base64 character in the signature to a different valid character.
    flipped = ("A" if value[0] != "A" else "B") + value[1:]
    lines[sig_index] = f"{keyword} {flipped}"
    tampered = "\n".join(lines)
    with pytest.raises(DescriptorError):
        parse_descriptor(tampered, built.blinded_pubkey, built.subcredential)


def test_tampered_mac_rejected() -> None:
    built = fx.build_descriptor(SERVICE_SEED, [fx.random_intro_point()])
    # Corrupt a byte inside the ciphertext (past the 16-byte salt) and re-sign,
    # so the outer signature is valid but the first-layer MAC check must fail.
    blob = bytearray(built.superencrypted_blob)
    blob[32] ^= 0xFF
    tampered = fx.assemble_descriptor(built.prefix_lines, bytes(blob), built.desc_signing_seed)
    with pytest.raises(DescriptorError):
        parse_descriptor(tampered, built.blinded_pubkey, built.subcredential)


def test_wrong_subcredential_rejected() -> None:
    built = fx.build_descriptor(SERVICE_SEED, [fx.random_intro_point()])
    wrong_subcredential = bytes(32)
    with pytest.raises(DescriptorError):
        parse_descriptor(built.text, built.blinded_pubkey, wrong_subcredential)


def test_expired_signing_cert_rejected() -> None:
    # A descriptor whose signing-key cert has expired at ``now`` must be rejected:
    # otherwise a malicious HSDir could replay an old, validly-signed descriptor.
    built = fx.build_descriptor(
        SERVICE_SEED, [fx.random_intro_point()], signing_cert_expiration_hours=100
    )
    after_expiry = _EPOCH + timedelta(hours=101)
    with pytest.raises(DescriptorError, match="expired"):
        parse_descriptor(built.text, built.blinded_pubkey, built.subcredential, now=after_expiry)
    # Before the cert expires it still decodes cleanly (the check is time-bounded).
    before_expiry = _EPOCH + timedelta(hours=50)
    desc = parse_descriptor(
        built.text, built.blinded_pubkey, built.subcredential, now=before_expiry
    )
    assert len(desc.intro_points) == 1


def test_naive_now_is_rejected() -> None:
    built = fx.build_descriptor(SERVICE_SEED, [fx.random_intro_point()])
    with pytest.raises(ValueError, match="timezone-aware"):
        parse_descriptor(
            built.text, built.blinded_pubkey, built.subcredential, now=datetime(2026, 1, 1)
        )


def test_wrong_signing_cert_type_rejected() -> None:
    # The outer descriptor-signing-key cert must be type HS_DESC_SIGNING (0x08);
    # any other cert type is rejected before its signature is trusted.
    built = fx.build_descriptor(
        SERVICE_SEED, [fx.random_intro_point()], signing_cert_type=CertType.HS_IP_AUTH
    )
    with pytest.raises(DescriptorError, match="type"):
        parse_descriptor(built.text, built.blinded_pubkey, built.subcredential)


def test_wrong_blinded_key_rejected() -> None:
    built = fx.build_descriptor(SERVICE_SEED, [fx.random_intro_point()])
    other = ed25519_public_from_seed(bytes([9]) * 32)
    wrong_blinded = kb.blind_public_key(other, fx.DEFAULT_PERIOD_NUM, fx.DEFAULT_PERIOD_LENGTH)
    with pytest.raises(DescriptorError):
        parse_descriptor(built.text, wrong_blinded, built.subcredential)


# --------------------------------------------------------------------------- #
# Client authorization
# --------------------------------------------------------------------------- #


def test_client_auth_round_trip() -> None:
    client_priv, client_pub = x25519_keypair()
    specs = [fx.random_intro_point() for _ in range(2)]
    built = fx.build_descriptor(SERVICE_SEED, specs, authorized_client_pubkey=client_pub)
    assert built.descriptor_cookie is not None

    # Without a cookie the inner layer cannot be decrypted.
    with pytest.raises(OnionClientAuthRequired):
        parse_descriptor(built.text, built.blinded_pubkey, built.subcredential)

    # The client derives the cookie from its x25519 key and the first layer.
    first_layer = decrypt_first_layer(built.text, built.blinded_pubkey, built.subcredential)
    cookie = derive_descriptor_cookie(first_layer, built.subcredential, client_priv)
    assert cookie == built.descriptor_cookie

    desc = parse_descriptor(
        built.text, built.blinded_pubkey, built.subcredential, descriptor_cookie=cookie
    )
    assert len(desc.intro_points) == 2
    for spec, parsed in zip(specs, desc.intro_points, strict=True):
        assert parsed.onion_key == spec.onion_key
        assert parsed.auth_key == spec.auth_key_pubkey
        assert parsed.enc_key == spec.enc_key


def test_client_auth_unknown_client_gets_no_cookie() -> None:
    _, client_pub = x25519_keypair()
    built = fx.build_descriptor(
        SERVICE_SEED, [fx.random_intro_point()], authorized_client_pubkey=client_pub
    )
    # A different client is not in the auth-client list.
    stranger_priv, _ = x25519_keypair()
    first_layer = decrypt_first_layer(built.text, built.blinded_pubkey, built.subcredential)
    assert derive_descriptor_cookie(first_layer, built.subcredential, stranger_priv) is None


def test_client_auth_wrong_cookie_rejected() -> None:
    _, client_pub = x25519_keypair()
    built = fx.build_descriptor(
        SERVICE_SEED, [fx.random_intro_point()], authorized_client_pubkey=client_pub
    )
    with pytest.raises(DescriptorError):
        parse_descriptor(
            built.text, built.blinded_pubkey, built.subcredential, descriptor_cookie=bytes(16)
        )


def test_descriptor_cookie_length_validated() -> None:
    built = fx.build_descriptor(SERVICE_SEED, [fx.random_intro_point()])
    with pytest.raises(DescriptorError):
        parse_descriptor(
            built.text, built.blinded_pubkey, built.subcredential, descriptor_cookie=b"short"
        )


def test_parse_descriptor_with_auth_derives_cookie() -> None:
    # The client-path convenience folds decrypt_first_layer -> derive cookie ->
    # parse_descriptor into one call, so a client that holds its key decrypts a
    # client-authorized descriptor directly.
    client_priv, client_pub = x25519_keypair()
    specs = [fx.random_intro_point() for _ in range(2)]
    built = fx.build_descriptor(SERVICE_SEED, specs, authorized_client_pubkey=client_pub)

    desc = parse_descriptor_with_auth(
        built.text, built.blinded_pubkey, built.subcredential, client_auth_privkey=client_priv
    )
    assert len(desc.intro_points) == 2
    for spec, parsed in zip(specs, desc.intro_points, strict=True):
        assert parsed.enc_key == spec.enc_key


def test_parse_descriptor_with_auth_without_key_requires_auth() -> None:
    _, client_pub = x25519_keypair()
    built = fx.build_descriptor(
        SERVICE_SEED, [fx.random_intro_point()], authorized_client_pubkey=client_pub
    )
    with pytest.raises(OnionClientAuthRequired):
        parse_descriptor_with_auth(built.text, built.blinded_pubkey, built.subcredential)


def test_parse_descriptor_with_auth_stranger_key_still_requires_auth() -> None:
    # A key that is not in the descriptor's auth-client set derives no cookie, so
    # the inner layer stays locked and the failure is loud, not a silent empty read.
    _, client_pub = x25519_keypair()
    stranger_priv, _ = x25519_keypair()
    built = fx.build_descriptor(
        SERVICE_SEED, [fx.random_intro_point()], authorized_client_pubkey=client_pub
    )
    with pytest.raises(OnionClientAuthRequired):
        parse_descriptor_with_auth(
            built.text, built.blinded_pubkey, built.subcredential, client_auth_privkey=stranger_priv
        )


def test_parse_descriptor_with_auth_ignores_key_for_open_service() -> None:
    # Supplying a key for a service that does not require authorization is
    # harmless: no cookie is needed, and the descriptor still decodes.
    client_priv, _ = x25519_keypair()
    specs = [fx.random_intro_point()]
    built = fx.build_descriptor(SERVICE_SEED, specs)

    desc = parse_descriptor_with_auth(
        built.text, built.blinded_pubkey, built.subcredential, client_auth_privkey=client_priv
    )
    assert len(desc.intro_points) == 1
