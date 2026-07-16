"""Exception hierarchy.

Every Tor-specific error subclasses the marker :class:`TorError` *and* the
matching ``requests`` exception, so code written against ``requests`` keeps
working (``except requests.exceptions.ConnectionError``) while callers who want
to distinguish Tor failures can catch :class:`TorError`. This mirrors how
``requests`` itself composes exceptions (for example ``ConnectTimeout`` is both a
``ConnectionError`` and a ``Timeout``).

This module imports only ``requests``, so it sits outside the package's internal
layering and may be raised from anywhere.
"""

from __future__ import annotations

from requests.exceptions import ConnectionError as _RequestsConnectionError
from requests.exceptions import (
    ConnectTimeout,
    InvalidSchema,
    InvalidURL,
    ReadTimeout,
    RequestException,
)
from requests.exceptions import SSLError as _RequestsSSLError

__all__ = [
    "ChannelError",
    "CircuitBuildTimeout",
    "CircuitDestroyed",
    "CircuitError",
    "ConsensusError",
    "DescriptorError",
    "DescriptorNotFound",
    "DirectoryError",
    "IntroductionError",
    "InvalidOnionAddress",
    "LinkAuthError",
    "OnionClientAuthRequired",
    "OnionRedirectError",
    "OnionServiceError",
    "ProxyUnsupportedError",
    "RendezvousError",
    "StreamConnectError",
    "StreamConnectTimeout",
    "StreamError",
    "TorBootstrapError",
    "TorError",
    "TorReadTimeout",
    "TorTLSError",
]


class TorError(RequestException):
    """Base class for every error raised by torquests."""


# --- Bootstrap: consensus and directory ------------------------------------ #


class TorBootstrapError(TorError, _RequestsConnectionError):
    """The client could not bootstrap a usable view of the Tor network."""


class ConsensusError(TorBootstrapError):
    """The network consensus could not be fetched, parsed, or verified."""


class DirectoryError(TorBootstrapError):
    """A directory document (microdescriptors, certificates) could not be fetched."""


# --- Guard channel --------------------------------------------------------- #


class ChannelError(TorError, _RequestsConnectionError):
    """The TLS link to a guard relay failed."""


class LinkAuthError(ChannelError):
    """The guard's CERTS chain did not authenticate its identity."""


# --- Circuits -------------------------------------------------------------- #


class CircuitError(TorError, _RequestsConnectionError):
    """A circuit could not be built, extended, or used."""


class CircuitBuildTimeout(CircuitError, ConnectTimeout):
    """A circuit did not finish building within the connect budget."""


class CircuitDestroyed(CircuitError):
    """A DESTROY cell tore the circuit down while it was in use."""


# --- Streams --------------------------------------------------------------- #


class StreamError(TorError, _RequestsConnectionError):
    """A stream failed abnormally."""


class StreamConnectError(StreamError):
    """RELAY_BEGIN was refused (exit policy, unreachable host, or no route)."""


class StreamConnectTimeout(StreamError, ConnectTimeout):
    """RELAY_BEGIN did not produce a RELAY_CONNECTED within the connect budget.

    A timeout is a distinct failure from a refusal, so it maps to the ``requests``
    ``ConnectTimeout`` (a ``ConnectionError`` and a ``Timeout``) rather than to a
    bare :class:`StreamConnectError`.
    """


class TorReadTimeout(TorError, ReadTimeout, TimeoutError):
    """No data arrived on a stream within the read budget.

    It also subclasses :class:`TimeoutError` (``socket.timeout``) so that when it
    surfaces while urllib3 is reading a response body, urllib3's ``_error_catcher``
    classifies it as a read timeout (``ReadTimeoutError``) exactly as it would a
    real socket timeout, which ``requests`` then maps to the same exception a
    vanilla body-read timeout produces instead of a ``ChunkedEncodingError``.
    """


# --- Destination TLS ------------------------------------------------------- #


class TorTLSError(TorError, _RequestsSSLError):
    """The TLS handshake with the destination host failed.

    HTTPS-over-Tor runs the destination handshake in ``TlsStreamSocket``. A failure
    there (a certificate that does not verify, a plaintext port answering the
    ClientHello, a protocol-version mismatch) raises a bare ``ssl.SSLError``, which
    is *not* a ``requests`` exception. Wrapping it keeps the hierarchy's contract:
    a caller's ``except requests.exceptions.SSLError`` and ``except TorError`` both
    catch it, exactly as they would a direct ``requests`` HTTPS failure.
    """


# --- Onion services -------------------------------------------------------- #


class OnionServiceError(TorError, _RequestsConnectionError):
    """A v3 onion-service connection failed."""


class DescriptorError(OnionServiceError):
    """An onion-service descriptor could not be fetched, verified, or decrypted."""


class DescriptorNotFound(DescriptorError):
    """No responsible HSDir returned a descriptor for the address."""


class IntroductionError(OnionServiceError):
    """The introduction step failed for every introduction point."""


class RendezvousError(OnionServiceError):
    """The rendezvous step failed (no RENDEZVOUS2, or the handshake did not verify)."""


class OnionClientAuthRequired(OnionServiceError):
    """The descriptor is client-authorized and no matching key was supplied."""


# --- URL / configuration --------------------------------------------------- #


class InvalidOnionAddress(TorError, InvalidURL):
    """A ``.onion`` address failed length, version, checksum, or torsion validation."""


class ProxyUnsupportedError(TorError, InvalidSchema):
    """A ``proxies`` argument was passed to the Tor adapter; Tor is the transport."""


class OnionRedirectError(TorError):
    """A :class:`~torquests.MixedSession` refused a redirect from an onion service
    to a clearnet host, which would have been fetched directly over the real IP."""
