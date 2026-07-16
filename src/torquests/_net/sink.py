"""The cell-sink interface.

A :class:`CellSink` receives cells the channel receiver demultiplexes to it by
circuit id, and is told when the channel closes. Circuits implement this and
register themselves with a channel; the interface inverts what would otherwise be
a channel-to-circuit import, keeping the dependency graph pointing one way.
"""

from __future__ import annotations

from typing import Protocol

from .._proto.cells import RawCell


class CellSink(Protocol):
    """Something that consumes cells for one circuit id."""

    def handle_cell(self, cell: RawCell) -> None:
        """Handle one inbound cell for this sink's circuit."""
        ...

    def on_channel_closed(self, error: Exception | None) -> None:
        """Notify the sink that its channel has closed (cleanly if ``error`` is None)."""
        ...
