# SOCKS5 proxy

torquests ships a local SOCKS5 server so any program that speaks SOCKS can send its
connections through Tor. No daemon, just your process.

```python
from torquests.socks import serve

serve(port=9050)                   # blocks until you stop it
```

Or from the shell:

```bash
torquests socks --port 9050
```

Then point a client at it:

```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
curl --socks5-hostname 127.0.0.1:9050 http://youraddress.onion/
```

## Names resolve at the exit

Use the client's *hostname* SOCKS mode (`socks5h` in curl, `--socks5-hostname` above), not
the plain `socks5` mode. In hostname mode the client hands torquests the name and the
**exit** resolves it; in plain mode the client resolves the name with your local resolver
first and only sends an IP, which leaks the destination to whoever watches your DNS.

torquests resolves clearnet names at the exit and reaches `.onion` addresses over the
rendezvous protocol. No destination hostname reaches your local resolver, as long as the
connecting program uses hostname mode. Always prefer `socks5h`.

!!! warning "Application leaks are yours to close"
    The proxy forwards what it is given. A browser or tool can still leak your identity
    around Tor: WebRTC, a plugin, `socks5` (numeric) DNS, or a request your program makes
    outside the proxy. torquests cannot see or stop those. For general browsing, Tor
    Browser is built to manage that whole surface; the proxy is best for scripts and tools
    whose traffic you control.
