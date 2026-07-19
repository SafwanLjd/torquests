# Quickstart

The module verbs mirror `requests`. The first call bootstraps a verified microdescriptor
consensus of the Tor network and reuses it for the rest of the process, so later calls do
not re-bootstrap.

```python
import torquests

r = torquests.get("https://httpbin.org/get", timeout=30)
torquests.post("https://httpbin.org/post", json={"hello": "tor"})
```

Every verb returns a real `requests.Response`, so `.status_code`, `.headers`, `.json()`,
`.content`, and streaming all behave as they do in requests.

## Sessions

A `Session` keeps circuits and cookies across requests and adds a Tor control:

```python
import torquests

with torquests.Session() as s:
    s.get("https://example.com")
    s.new_identity()          # fresh circuits, a new exit, and a cleared cookie jar
```

`new_identity()` retires the session's circuits and clears its cookie jar, so the next
request starts from a clean, uncorrelated state.

!!! tip "Reuse one client"
    Each `Session` builds its own Tor client, sharing only the process-global consensus and
    guard set that the first call bootstraps. To reuse one client across sessions (say, to
    bound its lifetime or share circuits), construct one and pass it in:

    ```python
    from torquests import TorClient, Session

    client = TorClient.bootstrap()
    with Session(tor=client) as s:
        s.get("https://example.com")
    ```

## Caching the consensus

The first request in a process bootstraps a verified consensus, which takes a few
seconds. To carry that work across processes, point a client at a cache directory. The
client writes the verified consensus there, and a later run reuses it in place of the
network consensus fetch while it stays live.

```python
from pathlib import Path

from torquests import Session, TorClient, TorConfig

config = TorConfig(cache_dir=Path.home() / ".cache" / "torquests")
client = TorClient.bootstrap(config)

with Session(tor=client) as s:
    s.get("https://example.com")
```

The file holds only the public, authority-signed consensus, and every load re-verifies
it, so the client discards an expired or tampered cache and fetches a fresh one from the
network. Leaving `cache_dir` unset (the default) keeps all directory state in memory and
writes nothing to disk.

## Streaming

Large bodies stream without buffering the whole response in memory, and Tor's flow control
(authenticated SENDMEs) is handled underneath:

```python
import torquests

with torquests.Session() as s:
    r = s.get("https://speed.hetzner.de/100MB.bin", stream=True)
    for chunk in r.iter_content(chunk_size=65536):
        ...  # each chunk arrives as the circuit's window allows
```

## Errors

torquests raises the `requests` exception you would catch anyway; Tor-specific failures
subclass the matching `requests` error, so existing `except` blocks keep working:

```python
import torquests
from torquests import ConnectionError, Timeout

try:
    torquests.get("https://example.onion", timeout=30)
except Timeout:
    ...      # circuit or read timed out
except ConnectionError:
    ...      # could not build a working circuit to the destination
```

See the [API reference](api.md) for the full exception tree.
