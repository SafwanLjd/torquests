"""A Tor stream: an application connection carried on a circuit.

A stream sends RELAY_BEGIN and waits for RELAY_CONNECTED, carries application
data in RELAY_DATA cells, and ends with RELAY_END. Inbound cells arrive on the
channel receiver thread and are buffered under a condition; the owning (caller)
thread blocks in :meth:`recv` until data, EOF, or an error is available. Sends
respect the stream's package window so a fast producer cannot outrun the peer.
"""

from __future__ import annotations

import contextlib
import threading

from .._proto.constants import (
    RELAY_PAYLOAD_LEN,
    STREAM_WINDOW_INCREMENT,
    STREAM_WINDOW_INITIAL,
    Relay,
)
from .._proto.relay import RelayCell, begin_body, end_body, parse_end_reason
from ..exceptions import (
    ChannelError,
    CircuitDestroyed,
    CircuitError,
    StreamConnectError,
    StreamConnectTimeout,
    TorReadTimeout,
)
from .circuit import Circuit
from .flowcontrol import PackageWindow

_DEFAULT_TIMEOUT = 60.0


class Stream:
    """One application stream on a circuit."""

    def __init__(
        self, circuit: Circuit, stream_id: int, *, read_timeout: float | None = None
    ) -> None:
        self._circuit = circuit
        self.stream_id = stream_id
        self._read_timeout = read_timeout
        self._cond = threading.Condition()
        self._buffer = bytearray()
        self._connected = False
        self._eof = False
        self._closed = False
        self._error: Exception | None = None
        self._end_reason: int | None = None
        self._package_window = PackageWindow(STREAM_WINDOW_INITIAL, STREAM_WINDOW_INCREMENT)
        # Emit a stream SENDME once the consumer has drained this many bytes, so
        # download backpressure is driven by consumption rather than receipt.
        self._sendme_after = STREAM_WINDOW_INCREMENT * RELAY_PAYLOAD_LEN
        self._consumed_since_sendme = 0

    # --- lifecycle --------------------------------------------------------- #

    def connect(self, host: str, port: int, *, timeout: float | None = None) -> None:
        """Open the stream with RELAY_BEGIN and wait for RELAY_CONNECTED."""
        self._open(
            RelayCell(Relay.BEGIN, self.stream_id, begin_body(host, port)),
            f"{host}:{port}",
            timeout,
        )

    def connect_dir(self, *, timeout: float | None = None) -> None:
        """Open a directory stream to the last hop with RELAY_BEGIN_DIR."""
        self._open(RelayCell(Relay.BEGIN_DIR, self.stream_id, b""), "directory", timeout)

    def _open(self, begin: RelayCell, label: str, timeout: float | None) -> None:
        budget = timeout if timeout is not None else _DEFAULT_TIMEOUT
        self._circuit.register_stream(self.stream_id, self)
        try:
            self._circuit.send_relay(begin)
            with self._cond:
                ready = self._cond.wait_for(
                    lambda: self._connected or self._eof or self._error is not None, budget
                )
                if not ready:
                    raise StreamConnectTimeout(f"timed out connecting to {label}")
                if self._error is not None:
                    raise self._error
                if not self._connected:
                    raise StreamConnectError(
                        f"connection to {label} refused (end reason {self._end_reason})"
                    )
        except BaseException:
            # The stream never opened, so drop the registration this method added.
            # The caller only tears down request-isolated circuits, not pooled ones,
            # so on a pooled circuit a failed BEGIN would otherwise leak the handler.
            self._circuit.unregister_stream(self.stream_id)
            raise

    def send(self, data: bytes) -> None:
        """Send application data, one RELAY_DATA cell at a time."""
        view = memoryview(data)
        for start in range(0, len(view), RELAY_PAYLOAD_LEN):
            chunk = view[start : start + RELAY_PAYLOAD_LEN]
            self._package_window.consume(self._read_timeout or _DEFAULT_TIMEOUT)
            self._circuit.send_relay(
                RelayCell(Relay.DATA, self.stream_id, bytes(chunk)), is_data=True
            )

    def recv(self, max_bytes: int) -> bytes:
        """Return up to ``max_bytes`` of buffered data, or ``b''`` at EOF."""
        with self._cond:
            ready = self._cond.wait_for(
                lambda: bool(self._buffer) or self._eof or self._error is not None,
                self._read_timeout,
            )
            if not ready:
                raise TorReadTimeout(f"stream {self.stream_id} read timed out")
            if self._buffer:
                data = bytes(self._buffer[:max_bytes])
                del self._buffer[:max_bytes]
            elif self._error is not None:
                raise self._error
            else:
                return b""
        # Credit the peer for consumed data outside the lock. Emitting SENDMEs on
        # the consumer thread (not on receipt) is what gives real download
        # backpressure and keeps the inbound buffer bounded.
        self._consumed_since_sendme += len(data)
        while self._consumed_since_sendme >= self._sendme_after:
            self._consumed_since_sendme -= self._sendme_after
            self._circuit.emit_stream_sendme(self.stream_id)
        return data

    def set_read_timeout(self, timeout: float | None) -> None:
        """Set the deadline :meth:`recv` waits for data before raising."""
        self._read_timeout = timeout

    def close(self) -> None:
        """End the stream and deregister it from the circuit."""
        with self._cond:
            if self._closed:
                return
            self._closed = True
            send_end = not self._eof
            # Wake any reader blocked in recv() so it returns EOF rather than
            # hanging until its own timeout (a relay proxy depends on this).
            self._eof = True
            self._cond.notify_all()
        if send_end:
            with contextlib.suppress(CircuitError, ChannelError):
                self._circuit.send_relay(RelayCell(Relay.END, self.stream_id, end_body()))
        self._package_window.close()
        self._circuit.unregister_stream(self.stream_id)

    # --- inbound (channel receiver thread) --------------------------------- #

    def handle_relay(self, cell: RelayCell) -> None:
        if cell.command == Relay.CONNECTED:
            with self._cond:
                self._connected = True
                self._cond.notify_all()
        elif cell.command == Relay.DATA:
            with self._cond:
                self._buffer += cell.data
                self._cond.notify_all()
        elif cell.command == Relay.END:
            with self._cond:
                self._eof = True
                self._end_reason = parse_end_reason(cell.data)
                self._cond.notify_all()
        elif cell.command == Relay.SENDME:
            self._package_window.refill()

    def on_circuit_closed(self, error: Exception | None) -> None:
        with self._cond:
            self._error = error or CircuitDestroyed("circuit closed")
            self._eof = True
            self._cond.notify_all()
        self._package_window.close()
