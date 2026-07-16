<p align="center">
  <img src="https://raw.githubusercontent.com/SafwanLjd/torquests/gh-pages/assets/torquests.png" alt="torquests" width="200">
</p>

<h1 align="center">torquests</h1>

<p align="center"><strong>Tor in your Python process, with the <code>requests</code> API you already know.</strong></p>

[![CI](https://github.com/SafwanLjd/torquests/actions/workflows/ci.yml/badge.svg)](https://github.com/SafwanLjd/torquests/actions/workflows/ci.yml)
[![docs](https://img.shields.io/badge/docs-safwanljd.github.io-blue)](https://safwanljd.github.io/torquests/)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
[![license](https://img.shields.io/badge/license-GPLv3-green)](LICENSE)
![types](https://img.shields.io/badge/mypy-strict-blue)
![style](https://img.shields.io/badge/lint-ruff-orange)

torquests speaks the Tor protocol itself. No Tor daemon, no Stem, no C extension past the
crypto libraries. You `pip install` it and your program gets its own Tor client, so a call
returns a real `requests.Response` that happened to travel through three relays.

```python
import torquests

r = torquests.get("https://check.torproject.org/api/ip")
print(r.json())        # {"IsTor": true, "IP": "185.220.101.4"}
```

One line built a circuit, ran an ntor handshake at each hop, and carried your HTTP over it.

## Why torquests

- **v3 onion services.** Fetch a `.onion` the way you fetch anything else: blinded-key
  derivation, the HSDir hash ring, two-layer descriptor decryption, and the rendezvous
  handshake.
- **The same requests API.** Module verbs, a `Session`, real `requests.Response` objects,
  cookies, redirects, streaming, and an exception tree that subclasses the matching `requests`
  errors. Mount Tor as a transport and keep the code you have.
- **No daemon.** The whole client lives in your process. Nothing to install alongside it,
  start, or leave listening on a port.
- **A proxy and a CLI in the box.** Point a browser at the built-in SOCKS5 proxy, or fetch
  from a shell with `torquests get`.

## Install

Python 3.10+:

```bash
pip install torquests
```

For the TLS-fingerprint [stealth mode](https://safwanljd.github.io/torquests/stealth/), add the extra:

```bash
pip install "torquests[stealth]"
```

## Quickstart

The module verbs mirror `requests`. The first call bootstraps a verified consensus of the
Tor network and reuses it for the rest of the process:

```python
import torquests

r = torquests.get("https://httpbin.org/get", timeout=30)
torquests.post("https://httpbin.org/post", json={"hello": "tor"})
```

A `Session` keeps circuits and cookies across requests and adds a Tor control:

```python
with torquests.Session() as s:
    s.get("https://example.com")
    s.new_identity()          # fresh circuits, a new exit, and a cleared cookie jar
```

Runnable scripts for the common flows live in [examples/](examples/).

## Onion services

A `.onion` host routes over the rendezvous protocol. Same call, different address:

```python
url = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/"
r = torquests.get(url)
print(r.status_code)          # 200, fetched over an onion circuit
```

## Drop-in alias

torquests re-exports the `requests` names you reach for, so a lot of code ports by changing
one import:

```python
import torquests as requests

r = requests.get("https://check.torproject.org/api/ip")
if r.status_code == requests.codes.ok:
    print(r.json())
```

`Response`, `Request`, `PreparedRequest`, `codes`, and the exception aliases (`HTTPError`,
`ConnectionError`, `Timeout`, and the rest) all come along.

## More

The [documentation](https://safwanljd.github.io/torquests/) covers the rest:

- **[Circuit isolation](https://safwanljd.github.io/torquests/circuit-isolation/).** One
  circuit, and exit, per destination host by default; switch to per-session or per-request.
- **[Stealth mode](https://safwanljd.github.io/torquests/stealth/).** A real browser TLS and
  HTTP/2 fingerprint over Tor, through the `torquests[stealth]` extra.
- **[Command line](https://safwanljd.github.io/torquests/cli/).** `torquests get`,
  `torquests ip`, and `torquests socks` from any shell.
- **[SOCKS5 proxy](https://safwanljd.github.io/torquests/socks-proxy/).** Send any program's
  traffic over Tor, with names resolved remotely, never on your machine.
- **[Mixed routing](https://safwanljd.github.io/torquests/onion-services/).** `MixedSession`
  sends `.onion` over Tor and lets clearnet go out directly.

## Safety

By default torquests blends in: a Firefox-shaped header set with no tool-identifying
`User-Agent`, a stable entry guard, a circuit per destination host, cookies cleared on
`new_identity()`, clearnet names resolved at the exit, and `.onion` addresses reached over
rendezvous rather than resolved at an exit.

It cannot match Tor Browser's TLS ClientHello (JA3/JA4) on the wire, though. The
standard-library stack emits a Python-shaped handshake that a destination or a hostile exit
can fingerprint. To blend the TLS layer too, use
[stealth mode](https://safwanljd.github.io/torquests/stealth/) or Tor Browser. See
[Safety](https://safwanljd.github.io/torquests/safety/) and [SECURITY.md](.github/SECURITY.md).

## Credits

torquests is a modern successor to [torpy](https://github.com/torpyorg/torpy), whose ntor and
relay-cell cryptography it ports and modernizes. It is not affiliated with The Tor Project.
See [NOTICE](NOTICE).
