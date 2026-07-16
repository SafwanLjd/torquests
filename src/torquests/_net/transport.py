"""The transport seam: the byte pipe a channel runs over.

A :class:`Transport` is a blocking, ordered byte stream to a guard relay plus the
digest of the peer's TLS certificate (which the link handshake binds to the
relay's identity). The real implementation speaks TLS; tests substitute an
in-memory transport, which is what lets every layer above this one run with
sockets disabled.
"""

from __future__ import annotations

import contextlib
import hashlib
import socket
import ssl
from typing import Protocol

from ..exceptions import ChannelError


class Transport(Protocol):
    """A blocking, ordered byte stream to a relay."""

    def connect(self) -> None:
        """Establish the connection. A no-op for an already-connected transport."""
        ...

    def send(self, data: bytes) -> None:
        """Send all of ``data``."""
        ...

    def recv_exact(self, n: int) -> bytes:
        """Return exactly ``n`` bytes, or raise :class:`ChannelError` on EOF."""
        ...

    def set_read_timeout(self, timeout: float | None) -> None:
        """Bound how long a read may block; ``None`` blocks indefinitely."""
        ...

    def close(self) -> None:
        """Close the transport; a blocked :meth:`recv_exact` must unblock."""
        ...

    @property
    def certificate_digest(self) -> bytes:
        """SHA-256 of the peer's TLS certificate (DER), for CERTS validation."""
        ...


class TlsTransport:
    """A TLS connection to a guard relay.

    The TLS layer is used only for confidentiality and framing; the relay's
    identity is authenticated by the link handshake's CERTS chain, not by X.509,
    so the context intentionally does not verify the certificate.
    """

    def __init__(self, host: str, port: int, *, connect_timeout: float | None = None) -> None:
        self._host = host
        self._port = port
        self._connect_timeout = connect_timeout
        self._sock: ssl.SSLSocket | None = None
        self._cert_digest = b""

    def connect(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            raw = socket.create_connection((self._host, self._port), timeout=self._connect_timeout)
        except OSError as exc:
            raise ChannelError(
                f"failed to connect to guard {self._host}:{self._port}: {exc}"
            ) from exc
        # From here the TCP socket is open; any failure below must close it (or the
        # SSLSocket that has taken over its fd) so a failed handshake leaks no fd.
        sock: ssl.SSLSocket | None = None
        try:
            sock = context.wrap_socket(raw, server_hostname=None)
            # Keep the connect budget on the socket through the link handshake, so a
            # guard that finishes TLS then goes silent cannot hang the caller; the
            # channel clears it once its receiver thread owns the socket.
            sock.settimeout(self._connect_timeout)
            der = sock.getpeercert(binary_form=True)
        except OSError as exc:
            with contextlib.suppress(OSError):
                (sock if sock is not None else raw).close()
            raise ChannelError(
                f"TLS handshake with guard {self._host}:{self._port} failed: {exc}"
            ) from exc
        if not der:
            with contextlib.suppress(OSError):
                sock.close()
            raise ChannelError("guard presented no TLS certificate")
        self._sock = sock
        self._cert_digest = hashlib.sha256(der).digest()

    def send(self, data: bytes) -> None:
        if self._sock is None:
            raise ChannelError("transport is not connected")
        try:
            self._sock.sendall(data)
        except OSError as exc:
            raise ChannelError(f"send failed: {exc}") from exc

    def recv_exact(self, n: int) -> bytes:
        if self._sock is None:
            raise ChannelError("transport is not connected")
        chunks: list[bytes] = []
        remaining = n
        while remaining > 0:
            try:
                chunk = self._sock.recv(remaining)
            except OSError as exc:
                raise ChannelError(f"recv failed: {exc}") from exc
            if not chunk:
                raise ChannelError("guard closed the connection")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def set_read_timeout(self, timeout: float | None) -> None:
        if self._sock is None:
            raise ChannelError("transport is not connected")
        self._sock.settimeout(timeout)

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.close()

    @property
    def certificate_digest(self) -> bytes:
        return self._cert_digest
