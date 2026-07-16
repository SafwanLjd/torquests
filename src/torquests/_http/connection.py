"""Drive ``http.client`` over a socket-shaped object.

The socket is a :class:`~torquests._http.streamsocket.TorStreamSocket` (plain
HTTP over a Tor stream) or a TLS wrapper around one. We replay the already-prepared
request through ``http.client`` so it produces a real ``HTTPResponse`` whose header
parsing and body framing the response builder can rely on.
"""

from __future__ import annotations

import http.client
from urllib.parse import urlsplit

import requests

from ..exceptions import StreamError, TorError
from .streamsocket import SocketLike


def perform_request(
    sock: SocketLike, request: requests.PreparedRequest
) -> http.client.HTTPResponse:
    """Send ``request`` over ``sock`` and return the raw ``http.client`` response."""
    split = urlsplit(request.url or "")
    host = split.hostname or ""
    port = split.port or (443 if split.scheme == "https" else 80)
    path = split.path or "/"
    if split.query:
        path = f"{path}?{split.query}"

    conn = http.client.HTTPConnection(host, port)
    conn.sock = sock  # a duck-typed socket, by design

    # Send the prepared headers as-is; http.client must not synthesize its own.
    # requests does not put a Host header in the prepared request (urllib3 normally
    # adds it), so we add one ourselves, omitting the port when it is the default.
    conn.putrequest(request.method or "GET", path, skip_host=True, skip_accept_encoding=True)
    if not any(name.lower() == "host" for name in request.headers):
        default_port = 443 if split.scheme == "https" else 80
        conn.putheader("Host", host if port == default_port else f"{host}:{port}")
    for name, value in request.headers.items():
        conn.putheader(name, value)

    body = request.body
    if isinstance(body, str):
        body = body.encode("utf-8")
    # When requests streams a length-less body (data=<generator>) it sets
    # Transfer-Encoding: chunked and leaves framing to the transport, so tell
    # http.client to chunk-frame; otherwise the generator's bytes go out raw and
    # the server misreads them as a chunk-size line.
    chunked = request.headers.get("Transfer-Encoding", "").lower() == "chunked"
    conn.endheaders(body, encode_chunked=chunked)

    try:
        return conn.getresponse()
    except TorError:
        # A Tor-layer failure (a read timeout, a circuit teardown) already carries
        # the right requests exception type; let it through rather than masking a
        # TorReadTimeout as a generic StreamError. TorError is an OSError, so it
        # must be caught before the broad handler below.
        raise
    except (http.client.HTTPException, OSError) as exc:
        raise StreamError(f"failed to read HTTP response: {exc}") from exc
