"""End-to-end tests: a real requests.Session driven over Tor via the fake relay."""

from __future__ import annotations

import ssl

import pytest
import requests

from torquests._http.tlssocket import TlsStreamSocket
from torquests._net.channel import Channel
from torquests._net.circuit import build_circuit
from torquests._net.stream import Stream
from torquests.adapter import TorAdapter, _tls_context
from torquests.exceptions import (
    InvalidOnionAddress,
    ProxyUnsupportedError,
    TorError,
    TorTLSError,
)

from .fakes import FakeRelay, FakeRelayTransport


def make_http(
    body: bytes,
    content_type: str = "text/plain; charset=utf-8",
    set_cookie: str | None = None,
) -> bytes:
    lines = ["HTTP/1.1 200 OK", f"Content-Type: {content_type}", f"Content-Length: {len(body)}"]
    if set_cookie is not None:
        lines.append(f"Set-Cookie: {set_cookie}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


class FakeConnector:
    """A minimal TorConnector that builds one circuit over a fake relay."""

    def __init__(self, relay: FakeRelay) -> None:
        self._transport = FakeRelayTransport(relay)
        self._channel: Channel | None = None
        self._circuit = None

    def _ensure(self) -> None:
        if self._circuit is None:
            self._channel = Channel.open(self._transport, "203.0.113.1")
            self._circuit = build_circuit(self._channel, self._transport.relay.path())

    def connect_stream(self, host, port, *, isolation_key, connect_timeout, read_timeout) -> Stream:
        self._ensure()
        assert self._circuit is not None
        stream = Stream(self._circuit, self._circuit.next_stream_id(), read_timeout=read_timeout)
        stream.connect(host, port, timeout=connect_timeout)
        return stream

    def close(self) -> None:
        if self._channel is not None:
            self._channel.close()


def tor_session(relay: FakeRelay) -> tuple[requests.Session, FakeConnector]:
    connector = FakeConnector(relay)
    session = requests.Session()
    adapter = TorAdapter(connector, owns_connector=True)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session, connector


def test_get_over_tor_populates_response() -> None:
    relay = FakeRelay(http_response=make_http(b"hello onion", set_cookie="session=abc"))
    session, _ = tor_session(relay)
    try:
        r = session.get("http://example.com/path?q=1")
        assert r.status_code == 200
        assert r.reason == "OK"
        assert r.text == "hello onion"
        assert r.encoding == "utf-8"
        assert r.headers["Content-Type"].startswith("text/plain")
        assert r.url == "http://example.com/path?q=1"
        assert r.request.method == "GET"
        assert r.ok
        # The cookie only persists if raw._original_response was populated.
        assert session.cookies.get("session") == "abc"
    finally:
        session.close()


def test_json_response() -> None:
    relay = FakeRelay(http_response=make_http(b'{"ok": true}', content_type="application/json"))
    session, _ = tor_session(relay)
    try:
        assert session.get("http://example.com/").json() == {"ok": True}
    finally:
        session.close()


def test_post_body_is_sent() -> None:
    relay = FakeRelay(http_response=make_http(b"received"))
    session, _ = tor_session(relay)
    try:
        r = session.post("http://example.com/submit", data=b"payload")
        assert r.status_code == 200
        assert r.text == "received"
    finally:
        session.close()


def test_chunked_generator_body_is_framed_on_the_wire() -> None:
    # requests sets Transfer-Encoding: chunked for a length-less (generator) body
    # and leaves framing to the transport; the exit must receive proper chunks.
    relay = FakeRelay(http_response=make_http(b"ok"))
    session, _ = tor_session(relay)
    try:

        def gen():
            yield b"hello "
            yield b"world"

        r = session.post("http://example.com/upload", data=gen())
        assert r.status_code == 200
        received = b"".join(bytes(buf) for buf in relay._stream_buffers.values())
        assert b"transfer-encoding: chunked" in received.lower()
        assert b"6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n" in received
    finally:
        session.close()


def test_raise_for_status_ok() -> None:
    relay = FakeRelay(http_response=make_http(b"fine"))
    session, _ = tor_session(relay)
    try:
        session.get("http://example.com/").raise_for_status()
    finally:
        session.close()


def test_read_timeout_during_headers_surfaces_as_requests_timeout() -> None:
    # The exit connects but never sends a response, so reading the status line
    # times out. Vanilla requests surfaces a header/first-response read timeout as
    # a requests ReadTimeout (a Timeout); the Tor transport must match, rather than
    # masking it as a StreamError/ConnectionError.
    relay = FakeRelay(http_response=make_http(b"never delivered"), stall_after_bytes=0)
    session, _ = tor_session(relay)
    try:
        with pytest.raises(requests.exceptions.Timeout) as excinfo:
            session.get("http://example.com/", timeout=0.3)
        assert isinstance(excinfo.value, requests.exceptions.ReadTimeout)
        assert not isinstance(excinfo.value, requests.exceptions.ConnectionError)
    finally:
        session.close()


def test_read_timeout_during_body_matches_requests_parity() -> None:
    # The exit sends complete headers plus a few body bytes, then stalls without an
    # END, so a body read past the prefix times out. Vanilla requests maps a
    # streaming body read timeout to a plain ConnectionError -- not a
    # ChunkedEncodingError and not a ReadTimeout -- and the Tor transport must
    # produce exactly that.
    full = make_http(b"Z" * 4096)
    header_end = full.index(b"\r\n\r\n") + 4
    relay = FakeRelay(http_response=full, stall_after_bytes=header_end + 8)
    session, _ = tor_session(relay)
    try:
        response = session.get("http://example.com/", timeout=0.3, stream=True)
        assert response.status_code == 200
        with pytest.raises(requests.exceptions.ConnectionError) as excinfo:
            _ = response.content
        assert not isinstance(excinfo.value, requests.exceptions.ChunkedEncodingError)
        assert not isinstance(excinfo.value, requests.exceptions.ReadTimeout)
    finally:
        session.close()


def test_proxies_are_rejected() -> None:
    adapter = TorAdapter(FakeConnector(FakeRelay()))
    request = requests.Request("GET", "http://example.com").prepare()
    with pytest.raises(ProxyUnsupportedError):
        adapter.send(request, proxies={"http": "http://127.0.0.1:8080"})


def test_invalid_onion_is_rejected() -> None:
    adapter = TorAdapter(FakeConnector(FakeRelay()))
    request = requests.Request("GET", "http://tooshort.onion/").prepare()
    with pytest.raises(InvalidOnionAddress):
        adapter.send(request)


def test_isolation_key_policies() -> None:
    conn = FakeConnector(FakeRelay())
    session_iso = TorAdapter(conn, isolation="session")
    assert session_iso._isolation_key("x.com") is session_iso._isolation_key("y.com")

    # "request": an unpooled key (None) -> a fresh circuit that closes with its stream.
    request_iso = TorAdapter(conn, isolation="request")
    assert request_iso._isolation_key("x.com") is None

    host_iso = TorAdapter(conn, isolation="host")
    assert host_iso._isolation_key("x.com") == host_iso._isolation_key("x.com")
    assert host_iso._isolation_key("x.com") != host_iso._isolation_key("y.com")

    with pytest.raises(ValueError):
        TorAdapter(conn, isolation="bogus")


def test_default_isolation_is_per_host() -> None:
    # The default keeps a separate circuit (and exit) per destination host, so
    # one exit does not see every site the session visits.
    adapter = TorAdapter(FakeConnector(FakeRelay()))
    assert adapter._isolation == "host"
    assert adapter._isolation_key("x.com") == adapter._isolation_key("x.com")
    assert adapter._isolation_key("x.com") != adapter._isolation_key("y.com")


def test_tls_context_offers_alpn_and_modern_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    # The context must both floor at TLS 1.2 and actually offer ALPN. Spy on
    # set_alpn_protocols so deleting the ALPN call in _tls_context fails this test.
    captured: list[list[str]] = []
    original = ssl.SSLContext.set_alpn_protocols

    def spy(self: ssl.SSLContext, protocols: list[str]) -> None:
        captured.append(list(protocols))
        original(self, protocols)

    monkeypatch.setattr(ssl.SSLContext, "set_alpn_protocols", spy)

    context = _tls_context(True, None)

    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert captured, "set_alpn_protocols was never called; ALPN is not offered"
    assert "http/1.1" in captured[-1]


class _PlaintextPeerSock:
    """A SocketLike whose peer answers the TLS ClientHello with plaintext and then
    closes -- an HTTPS request landing on a plain-HTTP port, which makes the
    handshake fail with ``ssl.SSLError``."""

    def __init__(self) -> None:
        self.sent = bytearray()
        self._replied = False

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, bufsize: int) -> bytes:
        if self._replied:
            return b""  # EOF: the peer hangs up after its plaintext reply
        self._replied = True
        return b"HTTP/1.1 400 Bad Request\r\n\r\n"

    def settimeout(self, timeout: float | None) -> None:
        pass

    def close(self) -> None:
        pass


def test_destination_tls_handshake_failure_surfaces_typed() -> None:
    # A destination TLS handshake failure must surface as the typed TorTLSError --
    # both a TorError and a requests.exceptions.SSLError -- rather than a bare
    # ssl.SSLError that would slip past a caller's `except requests...SSLError` or
    # `except TorError`.
    context = _tls_context(True, None)
    with pytest.raises(TorTLSError) as excinfo:
        TlsStreamSocket(context, _PlaintextPeerSock(), server_hostname="example.com")
    assert isinstance(excinfo.value, TorError)
    assert isinstance(excinfo.value, requests.exceptions.SSLError)
    assert not isinstance(excinfo.value, ssl.SSLError)
    assert excinfo.value.__cause__ is not None  # chains the underlying ssl.SSLError


def test_response_close_releases_the_tor_stream() -> None:
    relay = FakeRelay(http_response=make_http(b"bye"))
    connector = FakeConnector(relay)
    session = requests.Session()
    session.mount("http://", TorAdapter(connector, owns_connector=True))
    try:
        r = session.get("http://example.com/")
        assert r.text == "bye"
        assert connector._circuit is not None
        r.close()
        # Closing the response releases the connection, which closes the Tor stream
        # (sending RELAY_END) and deregisters it, no leak.
        assert not connector._circuit._streams
    finally:
        session.close()
