# Stealth mode

The default transport speaks TLS with the standard library, so its ClientHello
(JA3/JA4) reads as non-browser Python. `stealth_session()` instead sends requests
through [curl_cffi](https://github.com/lexiforest/curl_cffi), which reproduces a
real browser's TLS and HTTP/2 fingerprint, tunneled over torquests' own Tor
circuits. The destination and the exit see a Tor Browser handshake; the traffic
still travels through Tor.

Install the extra:

```bash
pip install "torquests[stealth]"
```

It behaves like any session and returns real `requests.Response` objects:

```python
import torquests

with torquests.stealth_session() as s:        # impersonate="tor" (Tor Browser)
    r = s.get("https://check.torproject.org/api/ip")
    print(r.json())                           # {"IsTor": true, ...}
    r = s.get("http://youraddress.onion/")    # .onion works too
```

Pick another profile with `impersonate`:

```python
torquests.stealth_session(impersonate="tor")       # Tor Browser (default)
torquests.stealth_session(impersonate="firefox")   # latest Firefox
torquests.stealth_session(impersonate="chrome")    # latest Chrome
```

## What it hides

Stealth mode spoofs the **destination-facing** TLS, what the exit relay and the
server see. That is the surface a site uses to fingerprint the client, and with
the `tor` profile it matches the Tor Browser crowd.

It leaves the **link handshake** to your entry guard as torquests' own, by design:
a browser handshake to a guard would itself be anomalous, and the guard's address
already identifies it as a Tor relay, so the link fingerprint tells a local
observer nothing new.

`stealth_session()` runs an in-process SOCKS5-over-Tor proxy on `127.0.0.1` and
points curl_cffi at it with `socks5h`, so clearnet names resolve at the exit and
`.onion` addresses route over rendezvous, never the local resolver.
