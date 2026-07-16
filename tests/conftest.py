"""Shared pytest configuration.

The unit suite runs with sockets disabled (``--disable-socket`` in
``pyproject.toml``) so no test can reach the real Tor network. Integration tests
that need a live connection are marked ``@pytest.mark.integration`` and are
deselected unless ``--run-integration`` is passed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

VECTORS_DIR = Path(__file__).parent / "vectors"


def load_vector(name: str) -> dict[str, str]:
    """Load a JSON gold-vector fixture from ``tests/vectors``."""
    return json.loads((VECTORS_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture
def hs_ntor_vector() -> dict[str, bytes]:
    """The official hs-ntor Appendix-G vector, hex fields decoded to bytes."""
    raw = load_vector("hs_ntor.json")
    return {k: bytes.fromhex(v) for k, v in raw.items() if not k.startswith("_")}


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="run the live-network integration tests (requires a reachable Tor network)",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    run_integration = config.getoption("--run-integration")
    skip_integration = pytest.mark.skip(reason="live-network test; pass --run-integration to run")
    for item in items:
        if "integration" not in item.keywords:
            continue
        if run_integration:
            # Re-enable sockets for the whole live test. pytest-socket honors this
            # marker in pytest_runtest_setup, before any fixture is set up, so even
            # a module- or session-scoped fixture that reaches the network works.
            # A function-scoped `socket_enabled` dependency would come too late.
            item.add_marker(pytest.mark.enable_socket)
        else:
            item.add_marker(skip_integration)
