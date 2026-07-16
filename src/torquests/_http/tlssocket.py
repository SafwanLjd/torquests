"""TLS over a Tor stream, using a memory BIO instead of a file descriptor.

A Tor stream has no real socket, and ``ssl.wrap_socket`` was removed in Python
3.12 anyway. Instead we drive an ``SSLObject`` over two ``ssl.MemoryBIO``s,
pumping ciphertext through the underlying :class:`TorStreamSocket` synchronously
on the caller's thread. The result presents the same small socket API, so
``http.client`` runs over HTTPS-in-Tor exactly as it does over plain HTTP.
"""

from __future__ import annotations

import io
import ssl

from ..exceptions import TorTLSError
from .streamsocket import SocketLike, StreamReader

_CHUNK = 65536


class TlsStreamSocket:
    """A TLS layer over a socket-shaped object, backed by memory BIOs."""

    def __init__(
        self, context: ssl.SSLContext, sock: SocketLike, *, server_hostname: str | None
    ) -> None:
        self._sock = sock
        self._server_hostname = server_hostname
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._tls = context.wrap_bio(
            self._incoming, self._outgoing, server_hostname=server_hostname
        )
        self._handshake()

    def _flush(self) -> None:
        data = self._outgoing.read()
        if data:
            self._sock.sendall(data)

    def _feed(self) -> None:
        data = self._sock.recv(_CHUNK)
        if data:
            self._incoming.write(data)
        else:
            self._incoming.write_eof()

    def _handshake(self) -> None:
        while True:
            try:
                self._tls.do_handshake()
                self._flush()
                return
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()
            except ssl.SSLError as exc:
                # A destination handshake failure (bad certificate, plaintext port,
                # protocol mismatch) is a bare ssl.SSLError, not a requests
                # exception. Fail loud with a typed error so callers catch it the
                # same way they catch a direct requests HTTPS failure.
                target = self._server_hostname or "the destination"
                raise TorTLSError(f"TLS handshake with {target} failed: {exc}") from exc

    def sendall(self, data: bytes) -> None:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            try:
                offset += self._tls.write(view[offset:])
                self._flush()
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()
            except ssl.SSLError as exc:
                # A TLS error while writing the request (renegotiation failure, a
                # dropped session) is a bare ssl.SSLError, like the handshake path
                # above. Wrap it in the same typed error so a send-phase failure is
                # caught as a requests.SSLError, not raised raw.
                target = self._server_hostname or "the destination"
                raise TorTLSError(f"TLS write to {target} failed: {exc}") from exc

    def recv(self, bufsize: int) -> bytes:
        while True:
            try:
                return self._tls.read(bufsize)
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""

    def makefile(self, mode: str = "rb", buffering: int | None = None, **_: object) -> io.IOBase:
        if "w" in mode or "a" in mode:
            raise ValueError(f"TlsStreamSocket only supports reading via makefile, not {mode!r}")
        reader = io.BufferedReader(StreamReader(self))
        return reader if "b" in mode else io.TextIOWrapper(reader)

    def settimeout(self, timeout: float | None) -> None:
        self._sock.settimeout(timeout)

    def setsockopt(self, *args: object) -> None:
        return None

    def fileno(self) -> int:
        return -1

    def close(self) -> None:
        self._sock.close()
