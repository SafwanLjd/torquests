"""Build a :class:`requests.Response` from an ``http.client`` response.

The raw ``http.client.HTTPResponse`` is wrapped in a ``urllib3.HTTPResponse`` with
``original_response`` set (without that, requests silently persists no cookies),
and every field requests expects on a response is populated the same way
``requests``' own ``HTTPAdapter.build_response`` does.
"""

from __future__ import annotations

import http.client

import requests
import urllib3
from requests.adapters import BaseAdapter
from requests.cookies import extract_cookies_to_jar
from requests.structures import CaseInsensitiveDict
from requests.utils import get_encoding_from_headers

from .streamsocket import SocketLike


class _SocketCloser:
    """Closes the Tor stream socket when the response is closed or released.

    It stands in for both the urllib3 connection (``close`` is called by
    ``HTTPResponse.close``) and its pool (``_put_conn`` is called by
    ``release_conn`` once the body is consumed); either path closes the stream.
    """

    def __init__(self, sock: SocketLike) -> None:
        self._sock = sock

    def close(self) -> None:
        self._sock.close()

    def _put_conn(self, _conn: object) -> None:
        self.close()


def build_response(
    request: requests.PreparedRequest,
    raw_response: http.client.HTTPResponse,
    adapter: BaseAdapter,
    sock: SocketLike,
) -> requests.Response:
    """Assemble the requests ``Response`` from a raw HTTP response."""
    raw = urllib3.HTTPResponse(
        body=raw_response,
        headers=urllib3.HTTPHeaderDict(list(raw_response.headers.items())),
        status=raw_response.status,
        version=raw_response.version,
        reason=raw_response.reason,
        preload_content=False,
        decode_content=False,
        original_response=raw_response,
        request_method=request.method,
    )
    # Closing the response (or releasing its connection once the body is read) must
    # close the Tor stream, which sends RELAY_END; otherwise streams accumulate on
    # the circuit. The closer stands in for both the connection and its pool.
    closer = _SocketCloser(sock)
    raw._connection = closer  # type: ignore[assignment]
    raw._pool = closer  # type: ignore[assignment]

    response = requests.Response()
    response.status_code = raw.status
    response.headers = CaseInsensitiveDict(raw.headers)
    response.encoding = get_encoding_from_headers(response.headers)
    response.raw = raw
    response.reason = raw.reason  # type: ignore[assignment]
    response.url = request.url or ""
    extract_cookies_to_jar(response.cookies, request, raw)  # type: ignore[no-untyped-call]
    response.request = request
    response.connection = adapter  # type: ignore[assignment]
    return response
