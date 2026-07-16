# Onion services

A `.onion` host routes over the v3 rendezvous protocol. The call is the same as any other;
only the address changes:

```python
import torquests

url = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/"
r = torquests.get(url)
print(r.status_code)          # 200, fetched over an onion circuit
```

Behind that call, torquests derives the service's blinded signing key for the current time
period, locates the responsible HSDirs on the hash ring, fetches and decrypts the two-layer
descriptor, and completes the introduce/rendezvous handshake before the request travels.

!!! note "v3 only"
    The v2 onion protocol was retired from the Tor network in 2021. torquests implements the
    v3 client only; 16-character v2 addresses are not supported because the network no longer
    serves them.

## Client authorization

Some v3 services answer only clients they have authorized. You hold an x25519 private key;
the operator registers its public half on the service. Supply your private key per address
through `onion_auth`, a mapping of onion host to the 32-byte x25519 client key:

```python
import base64
from torquests import Session

# The base32 key after "x25519:" in your Tor .auth_private line. Tor writes it
# without padding, so add the base32 padding back to recover the 32 raw bytes.
priv_b32 = "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ"
client_key = base64.b32decode(priv_b32 + "====")

with Session(onion_auth={"youraddress.onion": client_key}) as s:
    r = s.get("http://youraddress.onion/")
```

The key unlocks the descriptor's inner layer: torquests reads the service's ephemeral key
from the first layer, derives the descriptor cookie, and decrypts the introduction points
with it. Without a valid key, an authorized-only service raises `OnionClientAuthRequired`,
which tells you authorization failed rather than the service being unreachable.

`onion_auth` also works on `MixedSession`, and on a client you build yourself with
`TorClient.bootstrap(onion_auth=...)`. It cannot be combined with a `tor=` client you pass
in, since that client already carries its own authorization; configure the keys on that
client instead.

## Mixed clearnet and onion traffic

`MixedSession` sends `.onion` requests through Tor and lets everything else go out directly.
It is the right tool when only part of your traffic needs the network:

```python
from torquests import MixedSession

with MixedSession() as s:
    s.get("http://youraddress.onion/")   # over Tor
    s.get("https://example.com")         # straight out, no circuit
```

### Redirects cannot leak

A `MixedSession` refuses to follow a redirect that would carry an onion request out to the
clearnet. It raises `OnionRedirectError` (a `TorError`, which subclasses the `requests`
exception tree) instead of downgrading your anonymity, so a misbehaving or hostile service
cannot bounce your onion context onto a direct connection without you noticing.

```python
from torquests import MixedSession
from torquests.exceptions import OnionRedirectError

with MixedSession() as s:
    try:
        s.get("http://youraddress.onion/login")
    except OnionRedirectError:
        ...   # the service tried to redirect the onion request off Tor
```
