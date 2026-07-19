"""On-disk consensus cache.

A verified microdescriptor consensus is public, authority-signed data, so caching
it costs no anonymity: the document is identical for every client in its validity
window and says nothing about this client's traffic. Keeping it on disk lets a
fresh process skip the network consensus fetch while the consensus is still live.
Only a strictly live consensus is reused (a miss once it passes valid-until); a
short-lived client does not need the reasonably-live grace or the randomized
refresh schedule that a long-running relay uses.

The bytes stored are the exact document the authorities signed. On load they run
back through :func:`verify_consensus`, so a cached file is trusted no more than a
freshly fetched one: a missing, unreadable, non-UTF-8, malformed, tampered,
expired, or not-yet-valid file yields ``None`` and the caller bootstraps from the
network. The file is named ``cached-microdesc-consensus`` to match the file C tor
keeps under its ``CacheDirectory`` (tor(1), FILES).
"""

from __future__ import annotations

import contextlib
import logging
import os
import tempfile
from typing import TYPE_CHECKING

from ..exceptions import ConsensusError
from .consensus import verify_consensus

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime
    from pathlib import Path

    from .authorities import DirectoryAuthority
    from .models import Consensus

logger = logging.getLogger(__name__)

#: The cache filename, matching C tor's ``CacheDirectory`` entry (tor(1), FILES).
CONSENSUS_FILENAME = "cached-microdesc-consensus"


class ConsensusStore:
    """Reads and writes the verified consensus under a single cache directory.

    One store maps to one ``cache_dir`` and owns exactly the consensus file inside
    it. Every load re-verifies, so nothing the store returns is trusted more than a
    document fetched fresh from the directory authorities.
    """

    def __init__(self, cache_dir: Path) -> None:
        self._path = cache_dir / CONSENSUS_FILENAME

    def load(
        self,
        authorities: Sequence[DirectoryAuthority],
        *,
        now: datetime | None = None,
    ) -> Consensus | None:
        """Return the cached consensus when it is present and still verifies.

        The stored bytes run back through :func:`verify_consensus` at ``now``.
        Every way the file can be unusable resolves to ``None`` so the caller
        bootstraps from the network: a missing path or one that is not a readable
        file (:class:`OSError`), bytes that are not UTF-8, or a document that is
        malformed, tampered, expired, or not yet valid (:class:`ConsensusError`).
        A naive ``now`` is a caller bug, not a bad cache, so it still raises.
        """
        try:
            raw = self._path.read_bytes()
        except OSError as exc:
            # No file, a directory in its place, or a permission error: there is no
            # cache to use. Debug, not warning, since a cold start is the norm.
            logger.debug("no usable consensus cache at %s: %s", self._path, exc)
            return None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            logger.debug("discarding non-UTF-8 consensus cache at %s: %s", self._path, exc)
            return None
        try:
            return verify_consensus(text, authorities, now=now)
        except ConsensusError as exc:
            logger.debug("discarding unusable consensus cache at %s: %s", self._path, exc)
            return None

    def save(self, consensus_text: str) -> None:
        """Write ``consensus_text`` to the cache, replacing any earlier file.

        The bytes are the exact signed document, written atomically (a temporary
        file in the same directory, then :func:`os.replace`), so a crash or a
        concurrent reader never sees a partial consensus and the previous cache
        survives until the new one is complete. The file is created owner-only
        where the platform enforces mode bits. Raises :class:`OSError` when the
        directory cannot be written; callers keep caching best-effort.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_bytes(self._path, consensus_text.encode("utf-8"))


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically, leaving no partial file behind.

    :func:`tempfile.mkstemp` creates the temporary file in the destination
    directory with owner-only permissions and on the same filesystem, so
    :func:`os.replace` (atomic on POSIX and Windows) swaps it into place without a
    cross-device copy. A failure before the replace removes the temporary file, so
    a full disk or a write error never strands a stray ``.tmp``.
    """
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f"{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
