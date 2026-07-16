"""A channel: one authenticated guard link and the circuits multiplexed over it.

The channel owns the transport, the circuit registry, and the single write lock.
Its receiver thread reads cells and hands each to the registered sink for its
circuit id. By design the channel does not know what a circuit is; it talks to
the :class:`~torquests._net.sink.CellSink` interface, so the dependency
graph points from circuits down to the channel, never the reverse.
"""

from __future__ import annotations

import threading

from .._proto.cells import RawCell, read_cell
from .._proto.constants import CIRCID_MSB, Cell
from ..exceptions import ChannelError
from .link import do_link_handshake
from .sink import CellSink
from .transport import Transport

_JOIN_TIMEOUT = 10.0


class Channel:
    """A guard link carrying multiplexed circuits."""

    def __init__(self, transport: Transport, link_version: int, relay_identity: bytes) -> None:
        self._transport = transport
        self.link_version = link_version
        self.relay_identity = relay_identity
        self._sinks: dict[int, CellSink] = {}
        self._registry_lock = threading.Lock()
        self._io_lock = threading.Lock()
        self._closing = False
        self._next_circ_id = 0
        self._receiver = threading.Thread(
            target=self._receive_loop, name="torquests-receiver", daemon=True
        )

    @classmethod
    def open(
        cls,
        transport: Transport,
        peer_address: str,
        *,
        expected_identity: bytes | None = None,
        connect_timeout: float | None = None,
    ) -> Channel:
        """Connect, run the link handshake, and start the receiver.

        ``connect_timeout`` bounds the handshake reads, so a guard that accepts the
        connection then goes silent cannot hang the caller. Once the handshake
        returns, the socket is set blocking for the receiver thread, which waits for
        cells with no deadline.
        """
        transport.connect()
        if connect_timeout is not None:
            transport.set_read_timeout(connect_timeout)
        try:
            info = do_link_handshake(transport, peer_address, expected_identity=expected_identity)
        except BaseException:
            transport.close()  # a failed handshake must not leak the connection
            raise
        transport.set_read_timeout(None)
        channel = cls(transport, info.link_version, info.relay_ed_identity)
        channel._receiver.start()
        return channel

    # --- circuit registry -------------------------------------------------- #

    def new_circuit_id(self) -> int:
        """Allocate an unused, client-originated (MSB-set) circuit id."""
        with self._registry_lock:
            for _ in range(0x7FFFFFFF):
                self._next_circ_id = (self._next_circ_id + 1) & 0x7FFFFFFF
                circ_id = self._next_circ_id | CIRCID_MSB
                if circ_id not in self._sinks:
                    return circ_id
            raise ChannelError("no free circuit ids")  # pragma: no cover

    def register(self, circ_id: int, sink: CellSink) -> None:
        with self._registry_lock:
            if self._closing:
                raise ChannelError("channel is closed")
            if circ_id in self._sinks:
                raise ChannelError(f"circuit id {circ_id:#x} is already registered")
            self._sinks[circ_id] = sink

    def unregister(self, circ_id: int) -> None:
        with self._registry_lock:
            self._sinks.pop(circ_id, None)

    # --- sending ----------------------------------------------------------- #

    def send_cell(self, cell: RawCell) -> None:
        data = cell.pack(self.link_version)
        with self._io_lock:
            if self._closing:
                raise ChannelError("channel is closed")
            self._transport.send(data)

    # --- receiving --------------------------------------------------------- #

    def _receive_loop(self) -> None:
        error: Exception | None = None
        try:
            while not self._closing:
                cell = read_cell(self._transport.recv_exact, self.link_version)
                self._dispatch(cell)
        except Exception as exc:  # transport EOF/error or a framing failure
            if not self._closing:
                error = exc
        finally:
            self._shutdown(error)

    def _dispatch(self, cell: RawCell) -> None:
        if cell.command in (Cell.PADDING, Cell.VPADDING):
            return
        with self._registry_lock:
            sink = self._sinks.get(cell.circ_id)
        if sink is not None:
            sink.handle_cell(cell)
        # A cell for an unknown circuit (for example, one just torn down) is dropped.

    def _shutdown(self, error: Exception | None) -> None:
        with self._registry_lock:
            sinks = list(self._sinks.values())
            self._sinks.clear()
            self._closing = True
        for sink in sinks:
            sink.on_channel_closed(error)

    # --- teardown ---------------------------------------------------------- #

    @property
    def closed(self) -> bool:
        return self._closing

    def close(self) -> None:
        """Close the channel and join the receiver thread."""
        self._closing = True
        self._transport.close()
        if self._receiver.is_alive() and threading.current_thread() is not self._receiver:
            self._receiver.join(timeout=_JOIN_TIMEOUT)
