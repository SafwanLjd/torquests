"""Tests for the public package surface: re-exports, TLS trust, isolation typing."""

from __future__ import annotations

import ssl
from typing import get_args

import torquests
from torquests.adapter import IsolationPolicy, _tls_context


def test_requests_idioms_are_reexported() -> None:
    # `import torquests as requests` should cover the usual requests idioms.
    names = {
        "Request",
        "Response",
        "PreparedRequest",
        "codes",
        "HTTPError",
        "ConnectionError",
        "Timeout",
        "ConnectTimeout",
        "ReadTimeout",
        "TooManyRedirects",
        "JSONDecodeError",
        "RequestException",
        "URLRequired",
    }
    assert names <= set(dir(torquests))
    assert torquests.codes.ok == 200
    assert issubclass(torquests.TorError, torquests.RequestException)


def test_verify_directory_is_treated_as_capath(tmp_path, monkeypatch) -> None:
    # requests routes a directory verify string to capath; a bare cafile call
    # would raise IsADirectoryError. Spy on load_verify_locations to confirm the
    # directory is actually routed through capath=, not merely that nothing raised.
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def spy(instance: ssl.SSLContext, *args: object, **kwargs: object) -> None:
        calls.append((args, kwargs))

    monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", spy)

    context = _tls_context(str(tmp_path), None)

    assert isinstance(context, ssl.SSLContext)
    assert calls == [((), {"capath": str(tmp_path)})]


def test_isolation_policies_derive_from_the_literal() -> None:
    assert set(get_args(IsolationPolicy)) == {"session", "host", "request"}
