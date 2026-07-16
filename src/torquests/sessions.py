"""``requests``-compatible sessions that route over Tor.

:class:`Session` subclasses ``requests.Session`` and mounts a single
:class:`~torquests.adapter.TorAdapter` on both schemes, so every request,
clearnet or ``.onion``, goes through Tor. It defaults ``trust_env`` to ``False``
so environment proxies, netrc credentials, and CA-bundle variables cannot leak,
and it presents a Tor-Browser-shaped header set so a request does not name the
tool. :class:`MixedSession` sends only ``.onion`` traffic through Tor and reaches
clearnet directly.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import requests
from requests.adapters import BaseAdapter, HTTPAdapter

from ._client.torclient import TorClient
from ._onion.address import is_onion_host
from .adapter import IsolationPolicy, TorAdapter, TorConnector
from .exceptions import OnionRedirectError

#: The default User-Agent: current Tor Browser (Firefox ESR). A browser string
#: avoids naming the tool at the HTTP layer, which matters most for plain-HTTP
#: onion services. It does not hide the TLS fingerprint: a pure-Python client
#: cannot match Tor Browser's ClientHello (JA3/JA4) or HTTP/2 behaviour, so a
#: destination can still tell it apart. For a matching TLS fingerprint use
#: ``torquests.stealth_session()`` (the ``torquests[stealth]`` extra); SECURITY.md
#: has the full picture.
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"

#: The default request headers, in Firefox order. ``Accept`` is the Firefox 128
#: (Tor Browser) value for a top-level document request; Firefox dropped the
#: ``image/avif,image/webp`` types from that header in 120. ``Accept-Encoding``
#: deliberately lists only the codecs the client always decodes, so it omits the
#: ``br``/``zstd`` a real browser advertises: a minor tell in exchange for never
#: claiming an encoding the standard-library stack cannot inflate.
_DEFAULT_HEADERS: tuple[tuple[str, str], ...] = (
    ("User-Agent", DEFAULT_USER_AGENT),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.5"),
    ("Accept-Encoding", "gzip, deflate"),
    ("Connection", "keep-alive"),
    ("Upgrade-Insecure-Requests", "1"),
)


def _require_client(
    tor: TorConnector | None, onion_auth: Mapping[str, bytes] | None
) -> TorConnector:
    if tor is not None:
        if onion_auth is not None:
            raise ValueError(
                "onion_auth cannot be combined with an explicit tor client; "
                "configure client authorization on that client instead"
            )
        return tor
    return TorClient.bootstrap(onion_auth=onion_auth)


class Session(requests.Session):
    """A ``requests`` session whose transport is Tor."""

    def __init__(
        self,
        *,
        tor: TorConnector | None = None,
        isolation: IsolationPolicy = "host",
        isolation_token: object | None = None,
        onion_auth: Mapping[str, bytes] | None = None,
    ) -> None:
        super().__init__()
        self.trust_env = False
        # Replace the python-requests default headers with a Tor-Browser-shaped
        # set, in Firefox order, so the request blends in and does not name the tool.
        self.headers.clear()
        for name, value in _DEFAULT_HEADERS:
            self.headers[name] = value
        self._owns_client = tor is None
        self._tor = _require_client(tor, onion_auth)
        adapter = TorAdapter(self._tor, isolation=isolation, isolation_token=isolation_token)
        self.mount("http://", adapter)
        self.mount("https://", adapter)

    def new_identity(self) -> None:
        """Rotate circuits and clear session state so later requests are unlinkable.

        Drops the pooled circuits, so subsequent requests take fresh paths and
        exits, and clears the cookie jar, so a site cannot relink the new
        identity to the old one through a stored cookie.
        """
        self._tor.new_identity()
        self.cookies.clear()

    def close(self) -> None:
        super().close()
        if self._owns_client:
            self._tor.close()


class MixedSession(Session):
    """Routes ``.onion`` hosts through Tor and clearnet hosts directly.

    Clearnet requests leave over the real IP by design. So that an onion
    browsing session does not leak, a redirect from an onion service to a
    clearnet host is refused rather than followed directly (see :meth:`send`).
    """

    def __init__(
        self,
        *,
        tor: TorConnector | None = None,
        isolation: IsolationPolicy = "host",
        isolation_token: object | None = None,
        onion_auth: Mapping[str, bytes] | None = None,
    ) -> None:
        super().__init__(
            tor=tor,
            isolation=isolation,
            isolation_token=isolation_token,
            onion_auth=onion_auth,
        )
        self._direct_adapter = HTTPAdapter()
        self._redirect_origin = threading.local()

    def close(self) -> None:
        super().close()
        self._direct_adapter.close()

    def get_adapter(self, url: str) -> BaseAdapter:
        host = urlsplit(url).hostname or ""
        if is_onion_host(host):
            return super().get_adapter(url)
        return self._direct_adapter

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        """Send a request, refusing any onion-to-clearnet redirect hop.

        ``requests`` follows redirects by re-entering ``send`` once per hop. This
        remembers the previous hop's host, so a hop that crosses from an onion
        service to a clearnet host is rejected with
        :class:`~torquests.exceptions.OnionRedirectError` before it can be fetched
        directly over the real IP. The check is per-hop, so it holds at any point
        in a redirect chain, not only when the chain began at an onion service.
        """
        origin = self._redirect_origin
        host = urlsplit(request.url or "").hostname or ""
        this_onion = is_onion_host(host)
        if not getattr(origin, "active", False):
            origin.active = True
            origin.prev_onion = this_onion
            try:
                return super().send(request, **kwargs)
            finally:
                origin.active = False
        if getattr(origin, "prev_onion", False) and not this_onion:
            raise OnionRedirectError(
                f"refusing to follow a redirect from an onion service to {host!r}, "
                "which would be fetched directly over the real IP"
            )
        origin.prev_onion = this_onion
        return super().send(request, **kwargs)
