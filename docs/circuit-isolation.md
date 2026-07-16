# Circuit isolation

Isolation decides how much of your traffic shares a single circuit, and therefore a single
exit relay. It is the main privacy dial torquests exposes.

```python
import torquests

torquests.Session(isolation="host")      # one circuit per destination host (default)
torquests.Session(isolation="session")   # one circuit shared by the whole session
torquests.Session(isolation="request")   # a fresh circuit per request, torn down after
```

## The three policies

| Policy      | Circuits                                   | Use it when                                                        |
| ----------- | ------------------------------------------ | ----------------------------------------------------------------- |
| `host`      | One per destination host (the default)     | You visit several sites and do not want one exit to see them all. |
| `session`   | One shared by every request in the session | You make many requests to the same host and want to reuse a hop.  |
| `request`   | A fresh circuit per request, then torn down | You want no two requests linkable through a shared circuit.       |

Per-host is the default because fetching `a.example` and `b.example` then uses two exits,
so no single exit sees your whole browsing set. Circuits cost an ntor handshake per hop, so
`session` amortizes one circuit across many requests to a host, while `request` pays for a
fresh one each time in exchange for the strongest unlinkability. The
module-level verbs reuse a process-global client's per-host circuits.

## A new identity

Calling `new_identity()` on a session retires its circuits and clears its cookies, so
subsequent requests cannot be correlated with earlier ones through either a shared circuit
or a lingering cookie:

```python
with torquests.Session() as s:
    s.get("https://example.com")
    s.new_identity()
    s.get("https://example.com")   # new circuits, new exit, empty cookie jar
```
