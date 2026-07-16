# Command line

Installing torquests gives you a `torquests` command (also reachable as
`python -m torquests`). It is a thin shell over the same client the library exposes.

```bash
torquests get https://check.torproject.org/api/ip
torquests get http://youraddress.onion/ -H User-Agent curl/8 -o page.html
torquests ip                       # print your Tor exit IP
torquests socks --port 9050        # run a SOCKS5-over-Tor proxy
```

## Installing just the CLI

If you only want the `torquests` command, without adding torquests as a library
dependency, [pipx](https://pipx.pypa.io) installs it in its own isolated environment:

```bash
pipx install torquests
```

## Fetching

`torquests get <url>` builds a circuit and prints the response body to stdout. It handles
clearnet and `.onion` addresses the same way.

- `-H NAME VALUE` adds or overrides a request header. Repeat it for several headers.
- `-o FILE` writes the body to a file instead of stdout, so binary responses stay intact.

```bash
torquests get https://httpbin.org/get
torquests get https://httpbin.org/headers -H Accept application/json
torquests get https://speed.hetzner.de/100MB.bin -o download.bin
```

## Checking the exit

`torquests ip` prints the IP address a destination would see for your traffic. It confirms
the circuit is live and shows which exit you landed on:

```bash
torquests ip
```

## Running the proxy

`torquests socks` starts a local SOCKS5 server that forwards connections through Tor. Point
any SOCKS-aware program at it. See [SOCKS5 proxy](socks-proxy.md) for details.

```bash
torquests socks --port 9050
```
