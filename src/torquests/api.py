"""The module-level functional API, mirroring ``requests``.

Each verb runs through an ephemeral :class:`Session` over a process-global
:class:`TorClient`. The client bootstraps a verified consensus of the Tor network
on first use and is shared across calls, so repeated requests do not re-bootstrap.
"""

from __future__ import annotations

import threading
from typing import Any

import requests

from ._client.torclient import TorClient
from .adapter import TorConnector
from .sessions import Session

_lock = threading.Lock()
_client: TorConnector | None = None
# A stable token so the ephemeral per-call sessions reuse the process-global
# client's per-host pooled circuits, rather than each leaking a fresh circuit.
_ISOLATION_TOKEN = object()


def _default_client() -> TorConnector:
    global _client
    with _lock:
        if _client is None:
            _client = TorClient.bootstrap()
        return _client


def request(method: str, url: str, **kwargs: Any) -> requests.Response:
    """Send a request over Tor and return the response."""
    with Session(tor=_default_client(), isolation_token=_ISOLATION_TOKEN) as session:
        return session.request(method, url, **kwargs)


def get(url: str, **kwargs: Any) -> requests.Response:
    """Send a ``GET`` request over Tor. See :func:`request`."""
    return request("GET", url, **kwargs)


def head(url: str, **kwargs: Any) -> requests.Response:
    """Send a ``HEAD`` request over Tor (redirects off by default). See :func:`request`."""
    kwargs.setdefault("allow_redirects", False)
    return request("HEAD", url, **kwargs)


def post(url: str, **kwargs: Any) -> requests.Response:
    """Send a ``POST`` request over Tor. See :func:`request`."""
    return request("POST", url, **kwargs)


def put(url: str, **kwargs: Any) -> requests.Response:
    """Send a ``PUT`` request over Tor. See :func:`request`."""
    return request("PUT", url, **kwargs)


def patch(url: str, **kwargs: Any) -> requests.Response:
    """Send a ``PATCH`` request over Tor. See :func:`request`."""
    return request("PATCH", url, **kwargs)


def delete(url: str, **kwargs: Any) -> requests.Response:
    """Send a ``DELETE`` request over Tor. See :func:`request`."""
    return request("DELETE", url, **kwargs)


def options(url: str, **kwargs: Any) -> requests.Response:
    """Send an ``OPTIONS`` request over Tor. See :func:`request`."""
    return request("OPTIONS", url, **kwargs)


def new_identity() -> None:
    """Rotate the global client's circuits, if it has been created."""
    with _lock:
        client = _client
    if client is not None:
        client.new_identity()


def close() -> None:
    """Tear down the global client (mainly for tests and clean shutdown)."""
    global _client
    with _lock:
        client, _client = _client, None
    if client is not None:
        client.close()
