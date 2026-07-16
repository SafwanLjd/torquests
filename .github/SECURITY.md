# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately. Do not open a public issue for a
security problem, and do not disclose the details publicly until a fix has shipped.

Report through **GitHub Security Advisories**: open a draft advisory at
https://github.com/SafwanLjd/torquests/security/advisories/new.

Please include the affected version, a description of the issue, and, where you can,
a minimal reproduction. This project treats anonymity and cryptographic defects as
security issues, not ordinary bugs, so report those through the same private channels.

Expect an acknowledgement within a few days. We will keep you informed while a fix
is prepared and will credit you in the advisory unless you ask otherwise. We welcome
good-faith research and will not pursue reporters who follow this policy.

## Supported versions

Only the latest published release receives security fixes. There are no long-term
support branches.

| Version | Supported |
| ------- | --------- |
| Latest release | Yes |
| Everything older | No |

## Anonymity limitations

torquests anonymizes the **transport**, not the application layer. It routes your
connection through Tor circuits and reaches v3 onion services directly, but it does
nothing to make the traffic it carries look like a browser's.

Understand these limits before relying on the library for anonymity:

- **The client is fingerprintable as non-browser Python.** torquests uses the
  standard library `ssl` module for TLS and `http.client` for HTTP/1.1. Neither can
  reproduce Tor Browser's TLS ClientHello (the cipher, extension, and curve ordering
  that JA3/JA4 hash) or its HTTP/2 frame and header behaviour. A destination server
  or a malicious exit relay can therefore fingerprint the client as a Python Tor
  client rather than Tor Browser, and can distinguish it from the Tor Browser crowd.
- **No application-layer or browser fingerprinting defenses.** The library does not
  address JavaScript execution, canvas or font fingerprinting, cookies, referrers,
  redirect chains, or any of the browser-level signals that deanonymize users. What
  your code sends in headers, request timing, and payloads is your responsibility.
- **No traffic-analysis or timing-correlation protection beyond what Tor circuits
  provide.** A global adversary able to observe both ends of a circuit is outside the
  threat model, as it is for Tor generally.
- **Entry guards are not persisted.** To leave no on-disk trace, the client draws a
  fresh guard set each process rather than pinning guards across runs as Tor does, which
  trades reduced forensic residue for more entry-guard exposure over time.
- **No warranty.** Do not use it where a deanonymization would put someone at risk
  without independent review.

To blend into the Tor Browser user base on the wire, enable **stealth mode** (the
`torquests[stealth]` extra), which routes through curl_cffi to present a real Tor
Browser TLS ClientHello and HTTP/2 fingerprint over Tor. For the full browser
threat model (JavaScript, canvas and font fingerprinting, and the rest), use
[Tor Browser](https://www.torproject.org/download/) itself. torquests is built for
programmatic access to Tor and onion services from Python.
