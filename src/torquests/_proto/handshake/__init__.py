"""Circuit and onion-service handshakes.

``NtorHandshake`` builds ordinary circuit hops; ``HsNtorHandshake`` drives the v3
onion introduction and rendezvous. The two have different shapes and are used
directly by their callers, so there is no shared base protocol.
"""

from .hs_ntor import HsNtorHandshake, RendezvousKeys
from .ntor import NtorHandshake

__all__ = ["HsNtorHandshake", "NtorHandshake", "RendezvousKeys"]
