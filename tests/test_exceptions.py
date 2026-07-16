"""Tests for the exception hierarchy and its requests compatibility."""

from __future__ import annotations

import requests.exceptions as rexc

import torquests.exceptions as exc


def test_every_error_is_a_tor_error_and_request_exception() -> None:
    for name in exc.__all__:
        cls = getattr(exc, name)
        assert issubclass(cls, exc.TorError)
        assert issubclass(cls, rexc.RequestException)
        # Instantiation would raise TypeError on an inconsistent MRO.
        assert isinstance(cls("boom"), cls)


def test_requests_compatibility_mappings() -> None:
    assert issubclass(exc.TorBootstrapError, rexc.ConnectionError)
    assert issubclass(exc.ChannelError, rexc.ConnectionError)
    assert issubclass(exc.CircuitError, rexc.ConnectionError)
    assert issubclass(exc.StreamError, rexc.ConnectionError)
    assert issubclass(exc.OnionServiceError, rexc.ConnectionError)
    assert issubclass(exc.CircuitBuildTimeout, rexc.ConnectTimeout)
    assert issubclass(exc.TorReadTimeout, rexc.ReadTimeout)
    assert issubclass(exc.InvalidOnionAddress, rexc.InvalidURL)
    assert issubclass(exc.ProxyUnsupportedError, rexc.InvalidSchema)


def test_specific_subclassing() -> None:
    assert issubclass(exc.ConsensusError, exc.TorBootstrapError)
    assert issubclass(exc.LinkAuthError, exc.ChannelError)
    assert issubclass(exc.CircuitDestroyed, exc.CircuitError)
    assert issubclass(exc.DescriptorNotFound, exc.DescriptorError)
    assert issubclass(exc.DescriptorError, exc.OnionServiceError)


def test_catchable_as_requests_connection_error() -> None:
    try:
        raise exc.CircuitDestroyed("circuit torn down")
    except rexc.ConnectionError as caught:
        assert isinstance(caught, exc.TorError)
    else:  # pragma: no cover
        raise AssertionError("should have been caught as a requests ConnectionError")
