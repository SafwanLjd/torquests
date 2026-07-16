# Installation

torquests needs Python 3.10 or newer. Its only runtime dependencies are `requests`,
`urllib3`, `cryptography`, and `PyNaCl`. Those libraries supply the crypto primitives; the
Tor protocol itself is pure Python.

## With pip

```bash
pip install torquests
```

Stealth mode (a browser TLS and HTTP/2 fingerprint over Tor) needs curl_cffi, pulled in by
the `stealth` extra:

```bash
pip install "torquests[stealth]"
```

## From source

To track the latest changes or hack on torquests, install from a clone with the development
tooling (tests, linters, docs):

```bash
git clone https://github.com/SafwanLjd/torquests
cd torquests
pip install -e ".[dev]"
```

## Verify

A quick smoke test that exercises a real circuit end to end:

```bash
torquests ip
```

It prints the exit IP that a destination would see. If it returns an address that is not
yours, the client bootstrapped a consensus and built a circuit successfully.

## What gets installed

- The importable package `torquests`, shipping a `py.typed` marker so type checkers see its
  annotations.
- A `torquests` command-line entry point (also reachable as `python -m torquests`).

There is nothing else to run: no daemon, no system Tor, no background service.
