"""Tests for the v3 .onion address codec, anchored on a real address."""

from __future__ import annotations

import base64

import pytest

from torquests._onion import address as addr
from torquests._onion.address import OnionAddress
from torquests.exceptions import InvalidOnionAddress

# DuckDuckGo's real v3 onion address (independent real-world gold).
DDG = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad"
DDG_HOST = DDG + ".onion"


def test_parse_real_address_roundtrips() -> None:
    parsed = addr.parse(DDG_HOST)
    assert isinstance(parsed, OnionAddress)
    assert len(parsed.identity_key) == 32
    assert parsed.label == DDG
    assert parsed.hostname == DDG_HOST
    assert str(parsed) == DDG_HOST
    # Encoding the recovered key reproduces the address.
    assert addr.encode(parsed.identity_key) == DDG_HOST


def test_parse_accepts_variants() -> None:
    assert addr.parse(DDG).identity_key == addr.parse(DDG_HOST).identity_key
    assert addr.parse(DDG_HOST.upper()).identity_key == addr.parse(DDG_HOST).identity_key
    assert addr.parse(f"  {DDG_HOST}  ").identity_key == addr.parse(DDG_HOST).identity_key


def test_parse_ignores_single_subdomain() -> None:
    # In v3 the onion address is the label right before ``.onion``; a leading
    # label is a subdomain (a vhost, or a redirect shape torpy hit in issue #22)
    # and must resolve to the underlying service rather than be rejected.
    assert addr.parse(f"www.{DDG_HOST}").identity_key == addr.parse(DDG_HOST).identity_key


def test_parse_ignores_multiple_subdomains() -> None:
    assert addr.parse(f"a.b.{DDG_HOST}").identity_key == addr.parse(DDG_HOST).identity_key


def test_parse_subdomain_before_wrong_length_label_still_raises() -> None:
    # The last label is validated; a subdomain does not smuggle a bad address in.
    with pytest.raises(InvalidOnionAddress, match="56 characters"):
        addr.parse("www.tooshort.onion")


def test_parse_subdomain_before_bad_checksum_label_still_raises() -> None:
    payload = bytearray(base64.b32decode(DDG.upper()))
    payload[33] ^= 0xFF  # corrupt a checksum byte of the real address label
    corrupted = base64.b32encode(bytes(payload)).decode().lower()
    with pytest.raises(InvalidOnionAddress, match="checksum"):
        addr.parse(f"www.{corrupted}.onion")


def test_parse_rejects_wrong_length() -> None:
    with pytest.raises(InvalidOnionAddress, match="56 characters"):
        addr.parse("tooshort.onion")


def test_parse_rejects_bad_checksum() -> None:
    payload = bytearray(base64.b32decode(DDG.upper()))
    payload[33] ^= 0xFF  # corrupt a checksum byte
    corrupted = base64.b32encode(bytes(payload)).decode().lower()
    with pytest.raises(InvalidOnionAddress, match="checksum"):
        addr.parse(corrupted)


def test_parse_rejects_bad_version() -> None:
    payload = bytearray(base64.b32decode(DDG.upper()))
    payload[34] = 0x02  # v2
    bad = base64.b32encode(bytes(payload)).decode().lower()
    with pytest.raises(InvalidOnionAddress, match="version"):
        addr.parse(bad)


def test_parse_rejects_non_base32() -> None:
    with pytest.raises(InvalidOnionAddress, match="base32"):
        addr.parse("1" * 56)  # '1' and '8','9','0' are outside the base32 alphabet


def test_parse_rejects_torsion_failure() -> None:
    # Build a checksum-valid address around an all-zero (small-order) key, which
    # passes the checksum but must fail the torsion check.
    from torquests._crypto.primitives import sha3_256

    key = bytes(32)
    checksum = sha3_256(b".onion checksum" + key + bytes([3]))[:2]
    label = base64.b32encode(key + checksum + bytes([3])).decode().lower()
    with pytest.raises(InvalidOnionAddress, match="prime-order"):
        addr.parse(label)


def test_encode_rejects_bad_key_length() -> None:
    with pytest.raises(ValueError):
        addr.encode(b"\x00" * 31)


def test_is_onion_host() -> None:
    assert addr.is_onion_host(DDG_HOST)
    assert addr.is_onion_host("Example.ONION")
    assert not addr.is_onion_host("example.com")
