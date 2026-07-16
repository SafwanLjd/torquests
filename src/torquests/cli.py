"""Command-line interface: fetch a URL over Tor, or run a SOCKS5 proxy.

    torquests get https://check.torproject.org/api/ip
    torquests get http://example.onion -H User-Agent curl/8 -o page.html
    torquests ip
    torquests socks --port 9050

Also runnable as ``python -m torquests``.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="torquests",
        description="Route HTTP requests through Tor, or run a SOCKS5-over-Tor proxy.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    get = sub.add_parser("get", help="fetch a URL over Tor and write the body to stdout")
    get.add_argument("url", help="the URL to fetch (clearnet or .onion)")
    get.add_argument(
        "-H",
        "--header",
        nargs=2,
        action="append",
        metavar=("NAME", "VALUE"),
        default=[],
        help="add a request header (repeatable)",
    )
    get.add_argument("-o", "--output", help="write the body to a file instead of stdout")
    get.add_argument("-i", "--include", action="store_true", help="print status and headers too")
    get.add_argument("--timeout", type=float, default=60.0, help="per-request timeout in seconds")

    ip = sub.add_parser("ip", help="print the Tor exit IP as seen by check.torproject.org")
    ip.add_argument("--timeout", type=float, default=60.0, help="request timeout in seconds")

    socks = sub.add_parser("socks", help="run a local SOCKS5 proxy that tunnels over Tor")
    socks.add_argument("--host", default="127.0.0.1", help="address to bind (default 127.0.0.1)")
    socks.add_argument("-p", "--port", type=int, default=9050, help="port to bind (default 9050)")

    return parser


def _cmd_get(args: argparse.Namespace) -> int:
    import torquests

    headers = dict(args.header)
    response = torquests.get(args.url, headers=headers or None, timeout=args.timeout)
    if args.include:
        print(f"{response.status_code} {response.reason}", file=sys.stderr)
        for name, value in response.headers.items():
            print(f"{name}: {value}", file=sys.stderr)
        print(file=sys.stderr)
    if args.output:
        with open(args.output, "wb") as handle:
            handle.write(response.content)
    else:
        sys.stdout.buffer.write(response.content)
        sys.stdout.buffer.flush()
    return 0 if response.ok else 1


def _cmd_ip(args: argparse.Namespace) -> int:
    import torquests

    data = torquests.get("https://check.torproject.org/api/ip", timeout=args.timeout).json()
    print(data.get("IP", ""))
    return 0


def _cmd_socks(args: argparse.Namespace) -> int:
    from .socks import serve

    print(f"SOCKS5 proxy on {args.host}:{args.port} (bootstrapping Tor)...", file=sys.stderr)
    try:
        serve(args.host, args.port)
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    handler = {"get": _cmd_get, "ip": _cmd_ip, "socks": _cmd_socks}[args.command]
    try:
        return handler(args)
    except KeyboardInterrupt:
        # Ctrl-C during a command (often the multi-second bootstrap) is an abort,
        # not a crash: halt without a traceback and use the shell's SIGINT code.
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
