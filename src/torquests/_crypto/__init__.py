"""Cryptographic primitives and the ed25519 key-blinding operation.

This subpackage has no Tor semantics and does no I/O. It exists so the crypto
surface the rest of the library composes is small, typed, and auditable in one
place.
"""
