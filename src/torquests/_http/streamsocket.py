"""A socket-shaped facade over a Tor stream.

``http.client`` and ``ssl`` expect a socket object with a small set of methods.
``TorStreamSocket`` implements exactly that subset over a :class:`Stream`, with no
real file descriptor: ``sendall`` packages RELAY_DATA on the caller's thread and
``recv`` reads from the stream's inbound buffer. ``makefile('rb')`` returns a
buffered reader so ``http.client`` can parse a response.

:class:`SocketLike` is the shared contract the plain and TLS Tor sockets both
satisfy: the seam ``http.client`` and the response builder are typed against.
"""

from __future__ import annotations

import io
from typing import Protocol

from .._net.stream import Stream


class SupportsRecv(Protocol):
    """A blocking byte source. Both the plain and the TLS Tor sockets satisfy it."""

    def recv(self, bufsize: int) -> bytes: ...


class SocketLike(SupportsRecv, Protocol):
    """The duck-typed socket surface ``http.client``/``ssl`` drive over a Tor stream.

    Both :class:`TorStreamSocket` and
    :class:`~torquests._http.tlssocket.TlsStreamSocket` implement it.
    """

    def sendall(self, data: bytes) -> None: ...

    def settimeout(self, timeout: float | None) -> None: ...

    def makefile(
        self, mode: str = ..., buffering: int | None = ..., **kwargs: object
    ) -> io.IOBase: ...

    def setsockopt(self, *args: object) -> None: ...

    def fileno(self) -> int: ...

    def close(self) -> None: ...


class StreamReader(io.RawIOBase):
    """A raw reader that pulls bytes from any recv-capable socket."""

    def __init__(self, sock: SupportsRecv) -> None:
        self._sock = sock

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        data = self._sock.recv(len(buffer))
        if not data:
            return 0  # EOF
        n = len(data)
        buffer[:n] = data
        return n


class TorStreamSocket:
    """A minimal, blocking socket API backed by a Tor stream."""

    def __init__(self, stream: Stream, *, timeout: float | None = None) -> None:
        self._stream = stream
        self._timeout = timeout
        # Only override the stream's configured deadline when a timeout was
        # actually supplied; passing None must not turn a bounded read into a
        # block-forever one (that would silently defeat TorConfig.read_timeout).
        if timeout is not None:
            stream.set_read_timeout(timeout)

    def settimeout(self, timeout: float | None) -> None:
        self._timeout = timeout
        self._stream.set_read_timeout(timeout)

    def sendall(self, data: bytes) -> None:
        self._stream.send(bytes(data))

    def recv(self, bufsize: int) -> bytes:
        return self._stream.recv(bufsize)

    def makefile(self, mode: str = "rb", buffering: int | None = None, **_: object) -> io.IOBase:
        if "w" in mode or "a" in mode:
            raise ValueError(f"TorStreamSocket only supports reading via makefile, not {mode!r}")
        reader = io.BufferedReader(StreamReader(self))
        if "b" in mode:
            return reader
        return io.TextIOWrapper(reader)

    def setsockopt(self, *args: object) -> None:
        # No underlying socket to tune; http.client would set TCP_NODELAY in
        # connect(), which we bypass, so this is only defensive duck-type armor.
        return None

    def fileno(self) -> int:
        return -1

    def shutdown(self, how: int) -> None:
        return None

    def close(self) -> None:
        self._stream.close()
