"""Client configuration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class TorConfig:
    """Tunable parameters for a :class:`~torquests._client.torclient.TorClient`."""

    connect_timeout: float = 60.0
    #: Default per-read deadline when a request passes no ``timeout=``. Set to
    #: ``None`` for requests' block-forever semantics (risky over Tor, where a
    #: wedged circuit never delivers EOF).
    read_timeout: float | None = 60.0
    #: How many times to rebuild a circuit along a fresh path before giving up.
    #: Relays occasionally time out or drop a circuit mid-build; a fresh path
    #: almost always succeeds, so a few retries turn transient failures into
    #: a working connection.
    circuit_build_attempts: int = 3
    #: Directory for the on-disk consensus cache. When set, each verified
    #: consensus is written here and a later process reuses it in place of the
    #: network consensus fetch while it stays live. ``None`` (the default) keeps
    #: all directory state in memory and leaves nothing on disk. A cached file is
    #: re-verified on load, so it is trusted no more than a freshly fetched
    #: consensus.
    cache_dir: Path | None = None
