"""Flow-control windows.

Tor uses windowed flow control. A *package* window bounds how many cells may be
sent before the peer acknowledges them with a SENDME; when it reaches zero the
sender blocks. A *deliver* counter tracks cells received and signals when a SENDME
is due. Circuits and streams each hold both.
"""

from __future__ import annotations

import hmac
import threading
from collections import deque

from ..exceptions import CircuitDestroyed, TorReadTimeout


class PackageWindow:
    """The send-side window: block when it is exhausted, refill on a SENDME."""

    def __init__(self, initial: int, increment: int) -> None:
        self._value = initial
        self._increment = increment
        self._cond = threading.Condition()
        self._closed = False

    def consume(self, timeout: float | None = None) -> None:
        """Take one unit, blocking until one is available or the window closes."""
        with self._cond:
            while self._value <= 0 and not self._closed:
                if not self._cond.wait(timeout):
                    raise TorReadTimeout("timed out waiting for a SENDME")
            if self._closed:
                raise CircuitDestroyed("circuit closed while waiting to send")
            self._value -= 1

    def refill(self) -> None:
        with self._cond:
            self._value += self._increment
            self._cond.notify_all()

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    @property
    def remaining(self) -> int:
        """Units currently available to send (for observability and tests)."""
        with self._cond:
            return self._value


class DeliverCounter:
    """The receive-side counter: signals when a SENDME should be emitted."""

    def __init__(self, increment: int) -> None:
        self._increment = increment
        self._count = 0
        self._lock = threading.Lock()

    def note_received(self) -> bool:
        """Record one received cell; return True when a SENDME is now due."""
        with self._lock:
            self._count += 1
            if self._count >= self._increment:
                self._count = 0
                return True
            return False


class SendmeTracker:
    """Sender-side authenticated-SENDME bookkeeping.

    Counts outbound DATA cells and, at every ``increment`` boundary, remembers
    the forward running relay digest of the cell that will trigger the peer's
    acknowledgement. An incoming circuit SENDME must carry the oldest remembered
    digest, matched in order (FIFO); anything else is a forged or replayed
    acknowledgement and must not advance the send window.

    tor-spec (flow control, authenticating SENDMEs / proposal 289): the endpoint
    that receives a RELAY_SENDME remembers "the rolling digest of the relay cell
    that precedes (triggers) a RELAY_SENDME ... when the package window gets to a
    multiple of the circuit window increment", and "on failure to match, the
    circuit should be torn down".
    """

    #: Length of the authenticating digest carried in a v1 SENDME.
    DIGEST_LEN = 20

    def __init__(self, increment: int) -> None:
        self._increment = increment
        self._sent = 0
        self._expected: deque[bytes] = deque()
        self._lock = threading.Lock()

    def note_sent(self, digest: bytes) -> None:
        """Record one sent DATA cell, remembering its digest at each boundary."""
        with self._lock:
            self._sent += 1
            if self._sent >= self._increment:
                self._sent = 0
                self._expected.append(bytes(digest[: self.DIGEST_LEN]))

    def verify(self, digest: bytes) -> bool:
        """Return whether ``digest`` matches the next expected acknowledgement.

        Consumes one outstanding expectation. Returns ``False`` when the digest
        differs or when no acknowledgement is outstanding at all.
        """
        with self._lock:
            if not self._expected:
                return False
            expected = self._expected.popleft()
        return hmac.compare_digest(expected, bytes(digest[: self.DIGEST_LEN]))
