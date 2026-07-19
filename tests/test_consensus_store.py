"""Tests for the on-disk consensus cache (:class:`ConsensusStore`).

Every load runs the stored bytes back through :func:`verify_consensus`, so the
cache is trusted no more than a freshly fetched document. These tests thread an
explicit ``now`` as the clock, so liveness is exercised without touching the
real wall clock, and write under ``tmp_path`` so they stay offline.
"""

from __future__ import annotations

import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from torquests._dir.consensus_store import ConsensusStore

from .dir_fixtures import (
    NOW_LIVE,
    VALID_AFTER,
    SyntheticDirectory,
    synthetic_directory,
)

_CACHE_FILE = "cached-microdesc-consensus"


@pytest.fixture(scope="module")
def network() -> SyntheticDirectory:
    return synthetic_directory()


def test_round_trip_returns_the_verified_consensus(
    network: SyntheticDirectory, tmp_path: Path
) -> None:
    store = ConsensusStore(tmp_path)
    store.save(network.consensus_text)
    loaded = store.load(network.authorities, now=NOW_LIVE)
    assert loaded is not None
    assert loaded.valid_after == VALID_AFTER
    assert len(loaded.routers) == len(network.expected)


def test_missing_file_is_a_miss(network: SyntheticDirectory, tmp_path: Path) -> None:
    # A cold cache directory holds no file yet: a miss, not an error.
    assert ConsensusStore(tmp_path).load(network.authorities, now=NOW_LIVE) is None


def test_expired_cache_is_discarded(network: SyntheticDirectory, tmp_path: Path) -> None:
    # Stored while live, read back past valid-until: verify_consensus rejects it, so
    # the store reports a miss and the caller re-bootstraps from the network.
    store = ConsensusStore(tmp_path)
    store.save(network.consensus_text)
    long_after = datetime(2027, 1, 1, tzinfo=timezone.utc)
    assert store.load(network.authorities, now=long_after) is None


def test_tampered_cache_is_discarded(network: SyntheticDirectory, tmp_path: Path) -> None:
    # Flip a byte in the signed body: the authority signatures no longer verify, so a
    # file an attacker rewrote is never trusted over a fresh fetch.
    store = ConsensusStore(tmp_path)
    store.save(network.consensus_text.replace("w Bandwidth=15000", "w Bandwidth=99999"))
    assert store.load(network.authorities, now=NOW_LIVE) is None


def test_save_preserves_the_exact_signed_bytes(network: SyntheticDirectory, tmp_path: Path) -> None:
    # The signature covers exact bytes, so the round trip must not rewrite line
    # endings (the Windows text-mode trap); the stored file is byte-identical.
    ConsensusStore(tmp_path).save(network.consensus_text)
    stored = (tmp_path / _CACHE_FILE).read_bytes()
    assert stored == network.consensus_text.encode("utf-8")
    assert b"\r\n" not in stored


def test_save_leaves_no_temporary_file(network: SyntheticDirectory, tmp_path: Path) -> None:
    # The atomic write replaces the target and cleans up after itself, so the
    # directory holds only the consensus, never a stray ".tmp".
    ConsensusStore(tmp_path).save(network.consensus_text)
    assert [entry.name for entry in tmp_path.iterdir()] == [_CACHE_FILE]


def test_save_overwrites_the_previous_consensus(
    network: SyntheticDirectory, tmp_path: Path
) -> None:
    store = ConsensusStore(tmp_path)
    store.save("stale earlier bytes")
    store.save(network.consensus_text)
    assert store.load(network.authorities, now=NOW_LIVE) is not None


def test_save_creates_missing_parent_directories(
    network: SyntheticDirectory, tmp_path: Path
) -> None:
    store = ConsensusStore(tmp_path / "cache" / "torquests")
    store.save(network.consensus_text)
    assert store.load(network.authorities, now=NOW_LIVE) is not None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
def test_cache_file_is_owner_only(network: SyntheticDirectory, tmp_path: Path) -> None:
    # State on disk is a metadata trace; keep the file unreadable to other users.
    ConsensusStore(tmp_path).save(network.consensus_text)
    mode = stat.S_IMODE(os.stat(tmp_path / _CACHE_FILE).st_mode)
    assert mode == 0o600


# --------------------------------------------------------------------------- #
# Corrupt, stale, and malformed files are all misses, never crashes
# --------------------------------------------------------------------------- #


def test_not_yet_valid_cache_is_discarded(network: SyntheticDirectory, tmp_path: Path) -> None:
    # A consensus read before its valid-after (a backward clock, or a file from the
    # future) is not live and must not be used.
    store = ConsensusStore(tmp_path)
    store.save(network.consensus_text)
    before = datetime(2025, 12, 31, 23, 0, tzinfo=timezone.utc)
    assert store.load(network.authorities, now=before) is None


def test_empty_file_is_discarded(network: SyntheticDirectory, tmp_path: Path) -> None:
    (tmp_path / _CACHE_FILE).write_bytes(b"")
    assert ConsensusStore(tmp_path).load(network.authorities, now=NOW_LIVE) is None


def test_garbage_file_is_discarded(network: SyntheticDirectory, tmp_path: Path) -> None:
    # Valid UTF-8 that is not a consensus at all: the parser rejects it as a miss.
    (tmp_path / _CACHE_FILE).write_text("not a consensus at all\n", encoding="utf-8")
    assert ConsensusStore(tmp_path).load(network.authorities, now=NOW_LIVE) is None


def test_truncated_consensus_is_discarded(network: SyntheticDirectory, tmp_path: Path) -> None:
    (tmp_path / _CACHE_FILE).write_text(network.consensus_text[:200], encoding="utf-8")
    assert ConsensusStore(tmp_path).load(network.authorities, now=NOW_LIVE) is None


def test_invalid_utf8_file_is_discarded(network: SyntheticDirectory, tmp_path: Path) -> None:
    # Raw bytes that are not UTF-8 (a corrupt or truncated write) decode-fail; the
    # store must treat that as a miss, not let UnicodeDecodeError escape.
    (tmp_path / _CACHE_FILE).write_bytes(b"\xff\xfe\x00\x80 not utf-8")
    assert ConsensusStore(tmp_path).load(network.authorities, now=NOW_LIVE) is None


def test_directory_in_place_of_file_is_a_miss(network: SyntheticDirectory, tmp_path: Path) -> None:
    # If the cache path is somehow a directory, reading it raises an OSError that the
    # store turns into a miss rather than a crash.
    (tmp_path / _CACHE_FILE).mkdir()
    assert ConsensusStore(tmp_path).load(network.authorities, now=NOW_LIVE) is None


def test_naive_now_is_rejected(network: SyntheticDirectory, tmp_path: Path) -> None:
    # A naive datetime is a caller bug, not a bad cache: it must fail loud, not be
    # swallowed as a miss (UnicodeDecodeError handling must not widen to ValueError).
    store = ConsensusStore(tmp_path)
    store.save(network.consensus_text)
    with pytest.raises(ValueError, match="timezone-aware"):
        store.load(network.authorities, now=datetime(2026, 1, 1, 12, 30))


def test_save_failure_cleans_up_and_raises(
    network: SyntheticDirectory, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A write that fails after the temp file is created (a full disk, say) must
    # propagate and leave no partial or stray ".tmp" file behind.
    def boom(*_args: object, **_kwargs: object) -> None:
        raise OSError("no space left on device")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="no space left"):
        ConsensusStore(tmp_path).save(network.consensus_text)
    assert list(tmp_path.iterdir()) == []
