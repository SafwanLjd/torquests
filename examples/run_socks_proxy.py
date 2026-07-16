"""Run a local SOCKS5 proxy that carries every connection over Tor.

Start it, then point any SOCKS5 program at 127.0.0.1:9050:

    python examples/run_socks_proxy.py
    curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

Names, .onion included, resolve at the exit, so nothing leaks to your resolver.
"""

from torquests.socks import serve

if __name__ == "__main__":
    print("SOCKS5 proxy on 127.0.0.1:9050 (Ctrl-C to stop)")
    serve(host="127.0.0.1", port=9050)
