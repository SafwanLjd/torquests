<p align="center">
  <img src="assets/torquests.png" alt="torquests" width="200">
</p>

# torquests

**Tor in your Python process, with the `requests` API you already know.**

torquests speaks the Tor protocol itself. No Tor daemon, no Stem, no C extension past
the crypto libraries. You `pip install` it and your program gets its own Tor client, so a
call returns a real `requests.Response` that happened to travel through three relays.

```python
import torquests

r = torquests.get("https://check.torproject.org/api/ip")
print(r.json())        # {"IsTor": true, "IP": "185.220.101.4"}
```

One line built a circuit, ran an ntor handshake at each hop, and carried your HTTP over it.

<div class="grid cards" markdown>

-   :material-onion:{ .lg .middle } __v3 onion services__

    ---

    Fetch a `.onion` the way you fetch anything else: blinded-key derivation, the HSDir
    hash ring, two-layer descriptor decryption, and the introduce/rendezvous handshake.

    [:octicons-arrow-right-24: Onion services](onion-services.md)

-   :material-swap-horizontal:{ .lg .middle } __The same requests API__

    ---

    Module verbs, a `Session`, real `requests.Response` objects, cookies, redirects,
    streaming, and an exception tree that subclasses the matching `requests` errors.

    [:octicons-arrow-right-24: Quickstart](quickstart.md)

-   :material-package-variant-closed:{ .lg .middle } __No daemon__

    ---

    The whole client lives in your process. Nothing to install alongside it, start, or
    leave listening on a port.

    [:octicons-arrow-right-24: Installation](installation.md)

-   :material-shield-lock:{ .lg .middle } __Privacy by default__

    ---

    A stable entry guard, a circuit per destination host, names resolved at the exit, and
    an honest account of what a pure-Python client cannot hide.

    [:octicons-arrow-right-24: Safety](safety.md)

</div>

## Why torquests

- **v3 onion services.** The v2 protocol left the network in 2021, so torquests ships the
  v3 client end to end.
- **The same requests API.** Mount Tor as a transport and keep the code you have.
- **No daemon.** Nothing to run alongside your program.
- **A proxy and a CLI in the box.** Point a browser at the built-in SOCKS5 proxy, or fetch
  from a shell with `torquests get`.

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

## Where next

- New here? Start with [Installation](installation.md) and the [Quickstart](quickstart.md).
- Reaching a hidden service? See [Onion services](onion-services.md).
- Care about anonymity? Read [Safety](safety.md) first; it is candid about the limits.
- Need the details? The [API reference](api.md) is generated from the source.
