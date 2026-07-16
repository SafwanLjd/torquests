"""Reuse a circuit across requests, then rotate to a fresh exit.

A Session reuses a circuit per destination host across calls. new_identity()
drops those circuits and clears the cookie jar, so the next request takes a new
path through the network and cannot be relinked by a stored cookie.

Run it with:  python examples/session_and_identity.py
"""

import torquests

with torquests.Session() as session:
    first = session.get("https://check.torproject.org/api/ip", timeout=60)
    print(f"exit before rotate: {first.json()['IP']}")

    session.new_identity()

    second = session.get("https://check.torproject.org/api/ip", timeout=60)
    print(f"exit after  rotate: {second.json()['IP']}")
