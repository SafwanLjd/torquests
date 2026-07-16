# Safety

torquests routes your traffic through Tor and works to blend in by default. Read this before
you rely on it for anonymity.

## What it does for you

- Sends a Firefox-shaped header set with no tool-identifying `User-Agent`.
- Keeps a stable entry guard and isolates a circuit per destination host.
- Clears cookies on `new_identity()`.
- Resolves clearnet names at the exit and reaches `.onion` addresses over the rendezvous
  protocol, so no destination name reaches your local resolver.
- Tunnels its on-demand microdescriptor fetches over a Tor circuit, so an observer of your
  directory traffic does not learn which relay a circuit is about to use. This is
  best-effort: it fetches the tunnel circuit's own three relays in cleartext once while
  building that circuit, and if a later tunneled fetch fails it logs a warning and falls back
  to a cleartext fetch.
- Refuses onion-to-clearnet redirects in a `MixedSession`.

## What it cannot do

A pure-Python client cannot look like Tor Browser on the wire. The standard-library TLS
stack and `http.client` emit a TLS ClientHello (JA3/JA4) and HTTP/1.1 behavior distinct from
Firefox, so a destination or a hostile exit can fingerprint the client as a Python Tor
client. torquests does not manage a browser fingerprint, run JavaScript, or defend against an
adversary who watches both ends of the network. For those threat models, use Tor Browser.

## Can I make it look like another Tor client?

Yes, with **stealth mode**. `stealth_session()` (the `torquests[stealth]` extra) sends
requests through curl_cffi, which reproduces a real browser's ClientHello (JA3/JA4) and
HTTP/2 fingerprint. The `tor` profile matches Tor Browser, and the traffic still routes over
Tor and returns ordinary `requests.Response` objects. See [Stealth mode](stealth.md).

Without the extra, only the **HTTP** identity is yours to shape. torquests sends a
Firefox-shaped header set, the main signal a plain-HTTP onion service sees, though a
standard-library client cannot reproduce every header a browser sends: it omits the
`Sec-Fetch-*` and `Priority` hints and advertises only the `gzip`/`deflate` encodings it can
decode. The **TLS** handshake still reads as Python, and pairing a Firefox `User-Agent` with
it is a mismatch a server can key on, more distinctive than either alone. To blend the TLS
layer too, use stealth mode or Tor Browser.

## Reporting a vulnerability

Report suspected anonymity or cryptographic defects privately through a GitHub Security
Advisory. See [SECURITY.md](https://github.com/SafwanLjd/torquests/blob/main/.github/SECURITY.md).
