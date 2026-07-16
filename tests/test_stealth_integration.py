"""Live-network tests for stealth mode (browser-fingerprinted requests over Tor).

Deselected by default. Run the live stealth suite with
``uv run pytest --run-integration -m integration`` (needs Tor reachable and
the ``torquests[stealth]`` extra installed). The unit suite never reaches the
network.
"""

from __future__ import annotations

import pytest
import requests

import torquests

pytestmark = pytest.mark.integration

# Skip the whole module cleanly when the optional extra is absent.
pytest.importorskip("curl_cffi")


def test_stealth_session_returns_a_requests_response_over_tor() -> None:
    with torquests.stealth_session(impersonate="tor") as session:
        response = session.get("https://check.torproject.org/api/ip", timeout=90)
        assert isinstance(response, requests.Response)
        assert response.status_code == 200
        assert response.json()["IsTor"] is True


def test_stealth_session_presents_a_browser_tls_fingerprint() -> None:
    with torquests.stealth_session(impersonate="tor") as session:
        fingerprint = session.get("https://tls.browserleaks.com/json", timeout=90).json()
    # A real browser ClientHello negotiates HTTP/2 (ALPN h2); the stdlib client
    # cannot. A JA4 of the form "t13d...h2..." marks the browser fingerprint.
    assert fingerprint["ja4"].startswith("t13d")
    assert "h2" in fingerprint["ja4"]


def test_stealth_session_streams_iter_content() -> None:
    with (
        torquests.stealth_session(impersonate="tor") as session,
        session.get("https://check.torproject.org/api/ip", stream=True, timeout=90) as response,
    ):
        body = b"".join(response.iter_content(chunk_size=16))
    assert b"IsTor" in body
