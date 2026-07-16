"""Live integration tests against the real Tor network.

These are deselected by default (they need a reachable Tor network and are slow).
Run them with::

    uv run pytest --run-integration -m integration

Each test asserts a real anonymity or onion-service property, not just an HTTP
200: the exit IP must differ from the host's real IP, check.torproject.org must
report ``IsTor``, and v3 onion services must be reachable over the rendezvous
protocol. External echo services are used sparingly and only where their outage
would be obvious.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
import urllib.request

import pytest

import torquests
from torquests._client.bootstrap import LiveDirectory, get_directory
from torquests._client.torclient import TorClient
from torquests._crypto import ed25519_blind
from torquests._dir.dirhttp import dir_get
from torquests._net.stream import Stream
from torquests._onion import address as onion_address
from torquests._onion import descriptor as onion_descriptor
from torquests._proto.certs import Ed25519Certificate
from torquests._proto.constants import CertType
from torquests.exceptions import ChannelError, CircuitError, DirectoryError, StreamError

pytestmark = pytest.mark.integration

# A stable, well-known v3 onion that serves HTTPS (:443) and a second that serves
# plain HTTP (:80), so both onion transport paths are exercised.
DDG_ONION = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
TORPROJECT_ONION = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/"


@pytest.fixture(scope="module")
def real_ip() -> str:
    """This host's real public IP, fetched directly (not over Tor) for comparison."""
    with urllib.request.urlopen("https://check.torproject.org/api/ip", timeout=30) as resp:
        return json.loads(resp.read())["IP"]


def test_clearnet_is_anonymized(real_ip: str) -> None:
    r = torquests.get("https://check.torproject.org/api/ip", timeout=90)
    assert r.status_code == 200
    data = r.json()
    assert data["IsTor"] is True, data
    assert data["IP"] != real_ip, "exit IP equals the host's real IP, not anonymized"


def test_get_returns_parsed_json() -> None:
    r = torquests.get("https://check.torproject.org/api/ip", timeout=90)
    assert r.status_code == 200
    assert set(r.json()) >= {"IsTor", "IP"}


def test_post_round_trips_json() -> None:
    payload = {"hello": "tor", "n": 42}
    r = torquests.post("https://postman-echo.com/post", json=payload, timeout=90)
    assert r.status_code == 200
    assert r.json()["json"] == payload


def test_session_persists_cookies_across_redirect() -> None:
    with torquests.Session() as session:
        r = session.get("https://check.torproject.org/api/ip", timeout=90)  # warm a circuit
        assert r.status_code == 200
        r2 = session.get("https://postman-echo.com/cookies/set?tor_session=abc123", timeout=90)
        assert r2.status_code == 200
        assert session.cookies.get("tor_session") == "abc123"


def test_new_identity_yields_a_working_circuit() -> None:
    with torquests.Session() as session:
        r1 = session.get("https://check.torproject.org/api/ip", timeout=90)
        session.new_identity()
        r2 = session.get("https://check.torproject.org/api/ip", timeout=90)
        assert r1.json()["IsTor"] and r2.json()["IsTor"]


def test_streaming_download() -> None:
    with torquests.Session() as session:
        r = session.get("https://check.torproject.org/", stream=True, timeout=90)
        total = sum(len(chunk) for chunk in r.iter_content(8192))
        assert r.status_code == 200
        assert total > 1000


def test_onion_v3_over_https() -> None:
    r = torquests.get(DDG_ONION, timeout=120)
    assert r.status_code == 200
    assert b"duckduckgo" in r.content.lower()


def test_onion_v3_over_http() -> None:
    r = torquests.get(TORPROJECT_ONION, timeout=120)
    assert r.status_code == 200
    assert len(r.content) > 1000


def _fetch_descriptor_text(
    client: TorClient,
    directory: LiveDirectory,
    blinded_pubkey: bytes,
    *,
    timeout: float,
) -> str:
    """Fetch a service's raw v3 descriptor text from a responsible HSDir.

    Reuses the client's own fetch path: the responsible HSDirs for the current
    (then the previous) shared-random value are walked in order, a circuit is
    built to each, a directory stream is opened, and the first served descriptor
    is returned as text. The blinded key both locates the HSDirs on the hash ring
    and forms the ``/tor/hs/3/<z>`` request path, exactly as the real client does.
    """
    z = base64.b64encode(blinded_pubkey).decode("ascii").rstrip("=")
    failures: list[str] = []
    for use_previous in (False, True):
        for hsdir in directory.responsible_hsdirs(blinded_pubkey, use_previous_srv=use_previous):
            circuit = None
            try:
                circuit = client._build_circuit_along(directory.path_to(hsdir), timeout)
                stream = Stream(circuit, circuit.next_stream_id(), read_timeout=timeout)
                stream.connect_dir(timeout=timeout)
                return dir_get(stream, f"/tor/hs/3/{z}").decode("ascii", "replace")
            except (CircuitError, ChannelError, StreamError, DirectoryError, ValueError) as exc:
                failures.append(f"{hsdir.nickname}: {exc}")
            finally:
                if circuit is not None:
                    circuit.close()
    raise AssertionError(f"no responsible HSDir served a descriptor: {'; '.join(failures)}")


def _descriptor_blinded_key(descriptor_text: str) -> bytes:
    """Return the blinded ed25519 key the descriptor's signing cert is signed under.

    A v3 descriptor's outer ``descriptor-signing-key-cert`` is a type-0x08 Tor
    certificate whose mandatory ``signed-with-ed25519-key`` extension (type 0x04)
    carries the blinded public key that certifies and signs the descriptor signing
    key. That extension value is the ground-truth blinded key the service itself
    published for the current time period.
    """
    for keyword, _args, obj in onion_descriptor._iter_items(descriptor_text):
        if keyword == "descriptor-signing-key-cert" and obj is not None:
            cert = Ed25519Certificate.parse(obj)
            assert cert.cert_type == CertType.HS_DESC_SIGNING, cert.cert_type
            signing_key = cert.signing_key
            assert signing_key is not None, "signing cert lacks a signed-with-ed25519-key extension"
            return signing_key
    raise AssertionError("descriptor has no descriptor-signing-key-cert")


@pytest.mark.integration
def test_client_blinded_key_matches_live_descriptor() -> None:
    """Cross-check client key-blinding against a live onion-service descriptor.

    The offline vectors only prove the ed25519 blinding is internally consistent.
    This derives the blinded public key for the current time period from the
    ``.onion`` address alone, fetches the service's real descriptor from a
    responsible HSDir, and asserts that the blinded key inside the descriptor's
    type-0x08 signing certificate equals the derived one. That validates the
    blinding factor, the base-point constants, and the time-period math against
    live network ground truth, not just against the offline vectors.
    """
    timeout = 180.0

    # (a) Parse the .onion to its 32-byte ed25519 identity public key.
    host = urllib.parse.urlsplit(TORPROJECT_ONION).hostname
    assert host is not None
    address = onion_address.parse(host)

    # (b) Derive the blinded key for the current period, exactly as the client
    #     does: the period number comes from the live consensus valid-after.
    directory = get_directory(timeout=timeout)
    period = directory.time_period()
    blinded = ed25519_blind.blind_public_key(address.identity_key, period)
    subcredential = ed25519_blind.subcredential(address.identity_key, blinded)

    # (c) Fetch the real descriptor from a responsible HSDir.
    with TorClient.bootstrap(timeout=timeout) as client:
        descriptor_text = _fetch_descriptor_text(client, directory, blinded, timeout=timeout)

    # (d) Ground truth: the derived blinded key equals the one the live
    #     descriptor's signing certificate is published and signed under.
    assert _descriptor_blinded_key(descriptor_text) == blinded

    # The whole descriptor also decodes under the derived blinded key and
    # subcredential, exercising the full derivation chain rather than blinding
    # alone; a reachable service always publishes introduction points.
    parsed = onion_descriptor.parse_descriptor(descriptor_text, blinded, subcredential)
    assert parsed.intro_points, "live descriptor carried no introduction points"
