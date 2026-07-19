"""torquests: a pure-Python Tor client with a requests-compatible API.

Route HTTP requests through the Tor network, clearnet or v3 ``.onion``, with the
API you already know from ``requests``::

    import torquests

    r = torquests.get("https://check.torproject.org/api/ip")

    with torquests.Session() as session:
        session.get("http://example.onion")

The first call bootstraps a verified consensus of the Tor network and reuses it
across the process. To reuse a client explicitly, construct a :class:`TorClient`
and pass ``Session(tor=client)``.

Common ``requests`` names are re-exported so ``import torquests as requests``
works for the usual idioms (``codes``, ``Response``, ``HTTPError``, ...).
"""

from __future__ import annotations

import logging

from requests import PreparedRequest, Request, Response, codes
from requests.exceptions import (
    ConnectionError,
    ConnectTimeout,
    HTTPError,
    JSONDecodeError,
    ReadTimeout,
    RequestException,
    Timeout,
    TooManyRedirects,
    URLRequired,
)

from . import exceptions
from .adapter import IsolationPolicy, TorAdapter
from .api import (
    close,
    delete,
    get,
    head,
    new_identity,
    options,
    patch,
    post,
    put,
    request,
)
from .client import TorClient, TorConfig
from .exceptions import TorError
from .sessions import MixedSession, Session
from .stealth import StealthTorAdapter, stealth_session

__version__ = "1.0.1"

# A library should not configure logging; attach a no-op handler so emitting a
# record without a configured handler does not warn.
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "ConnectTimeout",
    "ConnectionError",
    "HTTPError",
    "IsolationPolicy",
    "JSONDecodeError",
    "MixedSession",
    "PreparedRequest",
    "ReadTimeout",
    "Request",
    "RequestException",
    "Response",
    "Session",
    "StealthTorAdapter",
    "Timeout",
    "TooManyRedirects",
    "TorAdapter",
    "TorClient",
    "TorConfig",
    "TorError",
    "URLRequired",
    "__version__",
    "close",
    "codes",
    "delete",
    "exceptions",
    "get",
    "head",
    "new_identity",
    "options",
    "patch",
    "post",
    "put",
    "request",
    "stealth_session",
]
