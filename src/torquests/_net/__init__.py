"""Live networking: the transport seam, guard channel, circuits, and streams.

This layer turns the pure wire formats and crypto below it into working circuits
and streams over a real (or, in tests, an in-memory) transport.
"""
