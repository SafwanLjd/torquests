"""HTTP/1.0 directory fetches over a Tor stream.

Directory documents are served over plain HTTP on a directory stream (a
BEGIN_DIR stream through a circuit; dir-spec/general-use-http-urls.md gives
the URL space, e.g. ``/tor/status-vote/current/consensus-microdesc``). One
request, one response, connection closed: HTTP/1.0 semantics with no
keep-alive, chunking, or redirects. Responses may be compressed; both
``deflate`` (a zlib stream in Tor's usage) and ``gzip`` are handled.
"""

from __future__ import annotations

import gzip
import zlib
from typing import Protocol

from ..exceptions import DirectoryError

_RECV_CHUNK = 4096
_DEFAULT_MAX_SIZE = 64 * 1024 * 1024  # far above any directory document


class DirStream(Protocol):
    """The stream surface a directory fetch needs (satisfied by ``Stream``)."""

    def send(self, data: bytes) -> None:
        """Send raw bytes to the directory server."""

    def recv(self, max_bytes: int) -> bytes:
        """Receive up to ``max_bytes``; ``b''`` means EOF."""


def _recv_or_fail(stream: DirStream, why: str) -> bytes:
    chunk = stream.recv(_RECV_CHUNK)
    if not chunk:
        raise DirectoryError(f"directory connection closed {why}")
    return chunk


def _parse_status_line(line: bytes) -> tuple[int, str]:
    parts = line.decode("latin-1").split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise DirectoryError(f"malformed directory response status line: {line!r}")
    try:
        status = int(parts[1])
    except ValueError as exc:
        raise DirectoryError(f"malformed directory response status: {parts[1]!r}") from exc
    return status, parts[2] if len(parts) == 3 else ""


def _parse_headers(lines: list[bytes]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in lines:
        name, sep, value = raw.decode("latin-1").partition(":")
        if not sep:
            raise DirectoryError(f"malformed directory response header: {raw!r}")
        headers[name.strip().lower()] = value.strip()
    return headers


def _decode_body(body: bytes, encoding: str) -> bytes:
    if encoding in ("", "identity"):
        return body
    if encoding == "deflate":
        # Tor's "deflate" is a zlib stream; accept raw deflate too, since the
        # label is historically ambiguous across HTTP implementations.
        try:
            return zlib.decompress(body)
        except zlib.error:
            try:
                return zlib.decompress(body, -zlib.MAX_WBITS)
            except zlib.error as exc:
                raise DirectoryError("malformed deflate body from directory") from exc
    if encoding in ("gzip", "x-gzip"):
        try:
            return gzip.decompress(body)
        except (OSError, EOFError, zlib.error) as exc:
            raise DirectoryError("malformed gzip body from directory") from exc
    raise DirectoryError(f"unsupported directory Content-Encoding: {encoding!r}")


def dir_get(
    stream: DirStream,
    path: str,
    host: str = "127.0.0.1",
    *,
    max_size: int = _DEFAULT_MAX_SIZE,
) -> bytes:
    """Fetch ``path`` from a directory server over ``stream``.

    Sends a minimal HTTP/1.0 GET, reads the whole response (honoring
    ``Content-Length`` when present, else to EOF), and returns the decompressed
    body. Raises :class:`DirectoryError` on a non-200 status, a malformed or
    truncated response, or a body larger than ``max_size``.
    """
    request = (
        f"GET {path} HTTP/1.0\r\nHost: {host}\r\nAccept-Encoding: deflate, gzip, identity\r\n\r\n"
    ).encode("ascii")
    stream.send(request)

    raw = bytearray()
    while b"\r\n\r\n" not in raw:
        raw += _recv_or_fail(stream, "before the response headers were complete")
        if len(raw) > max_size:
            raise DirectoryError("directory response headers too large")
    head, _, rest = bytes(raw).partition(b"\r\n\r\n")
    head_lines = head.split(b"\r\n")
    status, reason = _parse_status_line(head_lines[0])
    if status != 200:
        raise DirectoryError(f"directory request for {path} failed: HTTP {status} {reason}")
    headers = _parse_headers(head_lines[1:])

    body = bytearray(rest)
    content_length = headers.get("content-length")
    if content_length is not None:
        try:
            expected = int(content_length)
        except ValueError as exc:
            raise DirectoryError(
                f"malformed Content-Length from directory: {content_length!r}"
            ) from exc
        if expected > max_size:
            raise DirectoryError("directory response body too large")
        while len(body) < expected:
            body += _recv_or_fail(stream, "mid-body (truncated directory response)")
        del body[expected:]
    else:
        while True:
            chunk = stream.recv(_RECV_CHUNK)
            if not chunk:
                break
            body += chunk
            if len(body) > max_size:
                raise DirectoryError("directory response body too large")

    return _decode_body(bytes(body), headers.get("content-encoding", "").lower())
