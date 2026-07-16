# Examples

Small runnable scripts. Each one bootstraps Tor on first use, so give it a
minute and a working network connection.

| File | What it shows |
|------|---------------|
| [fetch_clearnet.py](fetch_clearnet.py) | A clearnet GET, with proof the exit is a Tor relay |
| [fetch_onion.py](fetch_onion.py) | A v3 `.onion` fetch over both HTTP and HTTPS |
| [session_and_identity.py](session_and_identity.py) | Reusing a circuit, then rotating the exit |
| [run_socks_proxy.py](run_socks_proxy.py) | A SOCKS5-over-Tor proxy for any program |

Run one with:

```bash
python examples/fetch_clearnet.py
```
