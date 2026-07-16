"""Client configuration."""

from __future__ import annotations

from dataclasses import dataclass


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
