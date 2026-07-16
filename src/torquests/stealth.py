"""Browser-fingerprinted requests over Tor (optional extra: ``torquests[stealth]``).

The default transport speaks TLS with the standard library, whose ClientHello
(JA3/JA4) marks the client as non-browser Python. This module runs requests
through `curl_cffi <https://github.com/lexiforest/curl_cffi>`_, which reproduces a
real browser's TLS and HTTP/2 fingerprint, tunneled over torquests' own Tor
circuits by an in-process SOCKS5 proxy. The destination and the exit see a Tor
Browser handshake, not a Python one, while the traffic still travels through Tor.

    import torquests

    with torquests.stealth_session() as s:        # impersonate="tor" (Tor Browser)
        r = s.get("https://check.torproject.org/api/ip")
        print(r.json())                           # a real requests.Response

The result is an ordinary :class:`requests.Response`: :class:`StealthTorAdapter`
repackages curl_cffi's response, so redirects, cookies, and streaming
(``iter_content``) behave as they do with any other adapter. This spoofs the
*destination-facing* TLS; the link handshake to the entry guard stays torquests'
own (a browser handshake to a guard would itself be anomalous, and the guard is
already known to be a Tor relay).

Needs curl_cffi: ``pip install torquests[stealth]``.
"""

from __future__ import annotations

import contextlib
import http.client
import threading
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import requests
from requests.adapters import BaseAdapter
from requests.cookies import extract_cookies_to_jar
from requests.structures import CaseInsensitiveDict
from requests.utils import get_encoding_from_headers

from ._client.config import TorConfig
from ._client.torclient import TorClient
from .adapter import TimeoutSpec, TorConnector
from .socks import Socks5Server

if TYPE_CHECKING:
    from curl_cffi import requests as _curl_requests

#: The default impersonation profile: Tor Browser, so the client blends into the
#: Tor Browser crowd at the TLS/HTTP layer rather than standing out.
DEFAULT_IMPERSONATE = "tor"


def _load_curl() -> _curl_requests.Session:
    """Return a curl_cffi session, with a clear error when the extra is missing."""
    try:
        from curl_cffi import requests as curl_requests
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised without the extra
        raise ModuleNotFoundError(
            "stealth mode needs curl_cffi; install it with: pip install torquests[stealth]"
        ) from exc
    return curl_requests.Session()


def _header_message(headers: Any) -> http.client.HTTPMessage:
    """Build an ``http.client`` message so requests can extract ``Set-Cookie``.

    Repeated headers (``Set-Cookie`` above all) must survive as separate entries,
    so prefer curl_cffi's multi-value view when it exposes one.
    """
    message = http.client.HTTPMessage()
    pairs = headers.multi_items() if hasattr(headers, "multi_items") else headers.items()
    for name, value in pairs:
        message[name] = value
    return message


class _OriginalResponse:
    """The ``_original_response`` shape requests reaches through for cookies."""

    def __init__(self, headers: Any) -> None:
        self.msg = _header_message(headers)

    def close(self) -> None:
        return None


class _CurlRaw:
    """A urllib3-response-shaped view over a curl_cffi response.

    requests reads a body through ``raw.stream(...)`` and pulls cookies from
    ``raw._original_response.msg``; this exposes exactly that surface so a
    curl_cffi response drives a real :class:`requests.Response`.
    """

    def __init__(self, response: _curl_requests.Response, *, stream: bool) -> None:
        self._response = response
        self._stream = stream
        self.headers = response.headers
        self.status = response.status_code
        self.reason = response.reason
        self.version = 11
        self.decode_content = False
        self._original_response = _OriginalResponse(response.headers)

    def stream(self, amt: int | None = None, decode_content: bool | None = None) -> Iterator[bytes]:
        try:
            if self._stream:
                yield from self._response.iter_content(chunk_size=amt or 10240)
            else:
                yield self._response.content
        finally:
            self.release_conn()

    def read(self, amt: int | None = None, decode_content: bool | None = None) -> bytes:
        return bytes(self._response.content)

    def release_conn(self) -> None:
        with contextlib.suppress(Exception):
            self._response.close()

    def close(self) -> None:
        self.release_conn()


def _build_response(
    request: requests.PreparedRequest,
    curl_response: _curl_requests.Response,
    adapter: BaseAdapter,
    *,
    stream: bool,
) -> requests.Response:
    """Assemble a :class:`requests.Response` from a curl_cffi response."""
    response = requests.Response()
    response.status_code = curl_response.status_code
    response.headers = CaseInsensitiveDict(_header_message(curl_response.headers).items())
    response.encoding = get_encoding_from_headers(response.headers)
    response.reason = curl_response.reason or ""
    response.url = str(curl_response.url) if curl_response.url else (request.url or "")
    response.raw = _CurlRaw(curl_response, stream=stream)
    extract_cookies_to_jar(response.cookies, request, response.raw)  # type: ignore[no-untyped-call]
    response.request = request
    response.connection = adapter  # type: ignore[assignment]
    return response


class StealthTorAdapter(BaseAdapter):
    """A ``requests`` adapter that speaks a browser's TLS fingerprint over Tor.

    Each request is issued with curl_cffi (impersonating ``impersonate``) through
    an in-process SOCKS5-over-Tor proxy on ``127.0.0.1``, then repackaged as a
    :class:`requests.Response`. Names, ``.onion`` included, resolve at the exit
    (``socks5h``), so nothing reaches the local resolver. The proxy isolates
    circuits per destination host.
    """

    def __init__(
        self,
        *,
        impersonate: str = DEFAULT_IMPERSONATE,
        tor: TorConnector | None = None,
        connect_timeout: float = 60.0,
    ) -> None:
        super().__init__()
        self._session = _load_curl()
        self._impersonate = impersonate
        self._owns_tor = tor is None
        self._tor: TorConnector = tor or TorClient.bootstrap(TorConfig(read_timeout=None))
        # Bind the proxy to an ephemeral loopback port; it never leaves the host.
        self._server = Socks5Server(("127.0.0.1", 0), self._tor, connect_timeout=connect_timeout)
        self._proxy_url = f"socks5h://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="torquests-stealth-socks", daemon=True
        )
        self._thread.start()

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: TimeoutSpec = None,
        verify: bool | str = True,
        cert: Any = None,
        proxies: Any = None,
    ) -> requests.Response:
        # curl_cffi verifies against its built-in CA store and accepts only a bool
        # here, so a CA-bundle path cannot be honored. Reject it loudly rather than
        # silently verifying with the default store and ignoring the caller's bundle.
        if isinstance(verify, str):
            raise ValueError(
                "stealth sessions verify against curl_cffi's built-in CA store and "
                "cannot use a custom CA-bundle path; pass verify=True or verify=False"
            )
        # Redirects are followed by the requests Session (one curl_cffi call per
        # hop), so cookie and history semantics stay with requests. Our own
        # headers merge over the impersonated browser set (default_headers=True).
        curl_response = self._session.request(
            request.method or "GET",
            request.url or "",
            headers=dict(request.headers),
            data=request.body,
            impersonate=self._impersonate,
            proxies={"http": self._proxy_url, "https": self._proxy_url},
            default_headers=True,
            allow_redirects=False,
            stream=stream,
            verify=verify,
            timeout=timeout,
        )
        return _build_response(request, curl_response, self, stream=stream)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._session.close()
        with contextlib.suppress(Exception):
            self._server.shutdown()
        with contextlib.suppress(Exception):
            self._server.server_close()
        if self._owns_tor:
            with contextlib.suppress(Exception):
                self._tor.close()


def stealth_session(
    *,
    impersonate: str = DEFAULT_IMPERSONATE,
    tor: TorConnector | None = None,
) -> requests.Session:
    """Return a :class:`requests.Session` that speaks a browser's TLS over Tor.

    Requests go out with curl_cffi's impersonated TLS/HTTP fingerprint (Tor
    Browser by default) tunneled through torquests' Tor circuits, and come back
    as ordinary :class:`requests.Response` objects. Pass ``impersonate`` to choose
    another profile (for example ``"firefox"`` or ``"chrome"``), or ``tor`` to
    reuse an existing client. Circuits are isolated per destination host. Needs
    the ``torquests[stealth]`` extra.
    """
    session = requests.Session()
    session.trust_env = False
    # Let curl_cffi supply the impersonated browser's exact header set; a stdlib
    # default header set here would clash with the spoofed fingerprint.
    session.headers.clear()
    adapter = StealthTorAdapter(impersonate=impersonate, tor=tor)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session
