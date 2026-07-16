"""Tests for the public Session/API surface, driven offline via the fake relay."""

from __future__ import annotations

import pytest
import requests

from torquests import MixedSession, Session, TorAdapter
from torquests._client.torclient import TorClient
from torquests.exceptions import OnionRedirectError, TorBootstrapError

from .fakes import FakeRelay, FakeRelayTransport
from .test_adapter import FakeConnector, make_http

DDG_ONION = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"


def make_redirect(location: str) -> bytes:
    """A 302 response body pointing at ``location`` (an empty-bodied redirect)."""
    lines = ["HTTP/1.1 302 Found", f"Location: {location}", "Content-Length: 0"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def make_client(relay: FakeRelay) -> TorClient:
    transport = FakeRelayTransport(relay)
    return TorClient(
        path_provider=lambda host, port: relay.path(),
        transport_factory=lambda guard: transport,
    )


def test_session_get_over_tor() -> None:
    relay = FakeRelay(http_response=make_http(b"hi from a session", set_cookie="s=1"))
    with Session(tor=make_client(relay)) as session:
        r = session.get("http://example.com/page")
        assert r.status_code == 200
        assert r.text == "hi from a session"
        assert session.cookies.get("s") == "1"
        assert session.trust_env is False


def test_new_identity_rotates_circuits() -> None:
    relay = FakeRelay(http_response=make_http(b"ok"))
    client = make_client(relay)
    with Session(tor=client) as session:
        session.get("http://example.com/")
        session.new_identity()  # must not raise; drops pooled circuits


def test_default_headers_do_not_name_the_tool_and_look_like_a_browser() -> None:
    # The default request must not carry a tool-identifying User-Agent and must
    # present a browser-shaped header set (Firefox UA, a real Accept, an
    # Accept-Language) in Firefox order, so it does not single the client out.
    relay = FakeRelay(http_response=make_http(b"ok"))
    with Session(tor=make_client(relay)) as session:
        session.get("http://example.com/")
        sent = b"".join(bytes(buf) for buf in relay._stream_buffers.values()).decode("latin-1")

    assert "torquests" not in sent.lower()
    header_lines = [line for line in sent.split("\r\n") if ": " in line]
    headers = dict(line.split(": ", 1) for line in header_lines)
    assert headers["User-Agent"].startswith("Mozilla/5.0")
    assert "Firefox/" in headers["User-Agent"]
    assert headers["Accept"] != "*/*"
    assert "text/html" in headers["Accept"]
    assert "Accept-Language" in headers

    order = [line.split(":", 1)[0] for line in header_lines]
    assert order.index("User-Agent") < order.index("Accept") < order.index("Accept-Language")
    assert (
        order.index("Accept-Language") < order.index("Accept-Encoding") < order.index("Connection")
    )


def test_new_identity_clears_cookies() -> None:
    # Rotating identity must wipe session state; a pre-rotation tracking cookie
    # must not survive to relink the new identity.
    relay = FakeRelay(http_response=make_http(b"ok", set_cookie="track=abc"))
    with Session(tor=make_client(relay)) as session:
        session.get("http://example.com/")
        assert session.cookies.get("track") == "abc"
        session.new_identity()
        assert len(session.cookies) == 0


def test_mixed_session_refuses_onion_to_clearnet_redirect() -> None:
    # A redirect from an onion origin to a clearnet host must raise before any
    # request leaves over the real IP, rather than being followed by the direct
    # adapter.
    session = MixedSession(tor=make_client(FakeRelay()))
    try:
        origin = session._redirect_origin
        origin.active = True  # a redirect chain is in flight
        origin.prev_onion = True  # the hop we just came from was an onion service
        leak = requests.Request("GET", "http://tracker.example/beacon").prepare()
        with pytest.raises(OnionRedirectError):
            session.send(leak, allow_redirects=False)
    finally:
        session.close()


def test_mixed_session_refuses_onion_to_clearnet_redirect_end_to_end() -> None:
    # Drive the whole requests redirect machinery: a fake onion service answers the
    # onion request with a 302 to a clearnet host. The onion->clearnet hop must
    # raise OnionRedirectError before the direct adapter opens a socket. Sockets are
    # disabled, so a real leak would instead surface as a pytest-socket block (a
    # different, distinguishable failure); getting OnionRedirectError proves no
    # direct request was attempted over the real IP.
    relay = FakeRelay(http_response=make_redirect("http://tracker.example/beacon"))
    connector = FakeConnector(relay)
    session = MixedSession(tor=connector)
    try:
        with pytest.raises(OnionRedirectError):
            session.get(f"http://{DDG_ONION}/start", allow_redirects=True)
    finally:
        session.close()
        connector.close()


def test_mixed_session_routes_by_host() -> None:
    session = MixedSession(tor=make_client(FakeRelay()))
    try:
        onion_adapter = session.get_adapter(f"http://{DDG_ONION}/")
        clearnet_adapter = session.get_adapter("http://example.com/")
        assert isinstance(onion_adapter, TorAdapter)
        assert isinstance(clearnet_adapter, requests.adapters.HTTPAdapter)
        assert not isinstance(clearnet_adapter, TorAdapter)
    finally:
        session.close()


def test_session_without_client_attempts_bootstrap() -> None:
    # With no tor= given, Session() bootstraps over the network. Offline (sockets
    # disabled) the blocked directory fetch surfaces as a typed TorBootstrapError
    # (its DirectoryError subclass), not a raw socket error; the live path is
    # exercised by the integration suite.
    with pytest.raises(TorBootstrapError):
        Session()


def test_session_onion_auth_forwards_to_the_bootstrapped_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # onion_auth on a client-owning Session is threaded into the client it
    # bootstraps, which is where the .onion connect path reads it.
    key = bytes(range(32))
    captured: dict[str, object] = {}

    def fake_bootstrap(config: object = None, *, timeout: float = 60.0, onion_auth: object = None):  # type: ignore[no-untyped-def]
        captured["onion_auth"] = onion_auth
        return make_client(FakeRelay())

    monkeypatch.setattr(TorClient, "bootstrap", staticmethod(fake_bootstrap))
    with Session(onion_auth={DDG_ONION: key}):
        pass
    assert captured["onion_auth"] == {DDG_ONION: key}


def test_session_onion_auth_conflicts_with_an_explicit_client() -> None:
    # A caller-supplied client already carries its own onion_auth, so combining the
    # two would silently drop one; refuse it instead of guessing.
    client = make_client(FakeRelay())
    try:
        with pytest.raises(ValueError, match="onion_auth"):
            Session(tor=client, onion_auth={DDG_ONION: bytes(32)})
    finally:
        client.close()
