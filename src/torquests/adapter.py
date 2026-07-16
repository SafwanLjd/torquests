"""The Tor transport adapter for ``requests``.

``TorAdapter`` implements the two-method ``BaseAdapter`` contract directly rather
than subclassing ``HTTPAdapter``. That coupling is what tied torpy to urllib3
internals that later changed. ``send`` opens a Tor stream to the target through a
connector, runs ``http.client`` over it (wrapping it in TLS for HTTPS), and
returns a fully-populated ``requests.Response``. Clearnet and ``.onion`` targets
go through the same path; the connector decides how the stream is built.
"""

from __future__ import annotations

import contextlib
import os
import ssl
from collections.abc import Mapping
from typing import Literal, Protocol, get_args
from urllib.parse import urlsplit

import requests
from requests.adapters import BaseAdapter

from ._http.connection import perform_request
from ._http.response import build_response
from ._http.streamsocket import SocketLike, TorStreamSocket
from ._http.tlssocket import TlsStreamSocket
from ._net.stream import Stream
from ._onion.address import is_onion_host
from ._onion.address import parse as parse_onion
from .exceptions import ProxyUnsupportedError

TimeoutSpec = float | tuple[float | None, float | None] | None

#: How circuits are shared across requests. ``"session"`` reuses one circuit for
#: the whole session, ``"host"`` uses one per target host, and ``"request"`` builds
#: a fresh circuit per request (maximum unlinkability, highest cost).
IsolationPolicy = Literal["session", "host", "request"]


class TorConnector(Protocol):
    """Opens connected Tor streams; implemented by the Tor client."""

    def connect_stream(
        self,
        host: str,
        port: int,
        *,
        isolation_key: object,
        connect_timeout: float | None,
        read_timeout: float | None,
    ) -> Stream: ...

    def new_identity(self) -> None: ...

    def close(self) -> None: ...


def _split_timeout(timeout: TimeoutSpec) -> tuple[float | None, float | None]:
    if timeout is None:
        return None, None
    if isinstance(timeout, tuple):
        try:
            connect, read = timeout
        except ValueError as exc:
            raise ValueError(
                f"Invalid timeout {timeout}. Pass a (connect, read) timeout tuple, "
                f"or a single float to set both timeouts to the same value."
            ) from exc
        return connect, read
    return timeout, timeout


CertSpec = bytes | str | tuple[bytes | str, bytes | str] | None


def _tls_context(verify: bool | str, cert: CertSpec) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Offer ALPN and a modern floor so the ClientHello is a little less of a
    # bare-stdlib outlier. Pure Python cannot match Tor Browser's TLS fingerprint
    # (extension order, GREASE); SECURITY.md documents the residual gap.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with contextlib.suppress(NotImplementedError):
        context.set_alpn_protocols(["http/1.1"])
    if verify is False:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    elif isinstance(verify, str):
        # requests treats a directory verify string as a CA path (capath).
        if os.path.isdir(verify):
            context.load_verify_locations(capath=verify)
        else:
            context.load_verify_locations(cafile=verify)
    else:
        context.load_default_certs()
    if isinstance(cert, tuple):
        context.load_cert_chain(cert[0], cert[1])
    elif cert is not None:
        context.load_cert_chain(cert)
    return context


class TorAdapter(BaseAdapter):
    """Routes ``requests`` traffic over Tor."""

    _ISOLATION_POLICIES = get_args(IsolationPolicy)

    def __init__(
        self,
        connector: TorConnector,
        *,
        isolation: IsolationPolicy = "host",
        owns_connector: bool = False,
        isolation_token: object | None = None,
    ) -> None:
        super().__init__()
        if isolation not in self._ISOLATION_POLICIES:
            raise ValueError(
                f"unknown isolation policy {isolation!r}; "
                f"expected one of {self._ISOLATION_POLICIES}"
            )
        self._connector = connector
        self._isolation = isolation
        self._owns_connector = owns_connector
        # A live object held for the adapter's lifetime: a stable identity for
        # "session"/"host" isolation that cannot collide the way id(self) can be
        # recycled. A caller may inject a shared token so several short-lived
        # adapters reuse one pooled circuit (the module-level verbs do this).
        self._isolation_token = isolation_token if isolation_token is not None else object()

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: TimeoutSpec = None,
        verify: bool | str = True,
        cert: CertSpec = None,
        proxies: Mapping[str, str] | None = None,
    ) -> requests.Response:
        if proxies and any(proxies.values()):
            raise ProxyUnsupportedError(
                "Tor is the transport; a proxies= argument is not supported"
            )

        split = urlsplit(request.url or "")
        scheme = split.scheme
        host = split.hostname or ""
        port = split.port or (443 if scheme == "https" else 80)
        if is_onion_host(host):
            parse_onion(host)  # validate checksum/version/torsion; raises InvalidOnionAddress

        connect_timeout, read_timeout = _split_timeout(timeout)
        tor_stream = self._connector.connect_stream(
            host,
            port,
            isolation_key=self._isolation_key(host),
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )

        sock: SocketLike = TorStreamSocket(tor_stream, timeout=read_timeout)
        if scheme == "https":
            sock = TlsStreamSocket(_tls_context(verify, cert), sock, server_hostname=host)

        raw_response = perform_request(sock, request)
        return build_response(request, raw_response, self, sock)

    def _isolation_key(self, host: str) -> object:
        if self._isolation == "session":
            return self._isolation_token
        if self._isolation == "host":
            return (self._isolation_token, host)
        return None  # "request": unpooled -> a fresh circuit that closes with its stream

    def close(self) -> None:
        if self._owns_connector:
            self._connector.close()
