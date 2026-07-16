"""Tor wire formats and relay cryptography.

Pure, I/O-free translation between bytes and typed objects (cells, relay bodies,
link specifiers, certificates) plus the relay-cell crypto state. Nothing in this
subpackage opens a socket.
"""
