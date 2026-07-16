"""The requests-facing HTTP plumbing.

Runs ``http.client`` (and, for HTTPS, TLS over a memory BIO) across a Tor stream
and turns the result into a fully-populated :class:`requests.Response`.
"""
