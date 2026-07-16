"""A local SOCKS5 proxy that tunnels every connection through Tor.

Point any SOCKS5-aware program (a browser, ``curl --socks5-hostname``, ...) at the
address this serves and its traffic, clearnet or ``.onion``, goes over Tor. Only
the CONNECT command is supported, and names are resolved by the exit (so ``.onion``
addresses and DNS never leak locally). This is the Unix-philosophy counterpart to
the Python API: one job, usable by anything that speaks SOCKS5.

    from torquests.socks import serve
    serve(port=9050)  # blocks; Ctrl-C to stop
"""

from __future__ import annotations

import contextlib
import socket
import socketserver
import struct
import sys
import threading

from ._client.config import TorConfig
from ._client.torclient import TorClient
from ._net.stream import Stream
from .adapter import TorConnector

# SOCKS5 constants (RFC 1928).
_VERSION = 0x05
_NO_AUTH = 0x00
_CMD_CONNECT = 0x01
_ATYP_IPV4 = 0x01
_ATYP_DOMAIN = 0x03
_ATYP_IPV6 = 0x04
_REP_SUCCESS = 0x00
_REP_GENERAL_FAILURE = 0x01
_REP_HOST_UNREACHABLE = 0x04
_REP_CMD_NOT_SUPPORTED = 0x07
_REP_ATYP_NOT_SUPPORTED = 0x08

_RELAY_CHUNK = 65536


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """Read exactly ``n`` bytes, or ``None`` if the peer closes early."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


def _reply(sock: socket.socket, code: int) -> None:
    # VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0.
    sock.sendall(bytes([_VERSION, code, 0x00, _ATYP_IPV4, 0, 0, 0, 0, 0, 0]))


class _Socks5Handler(socketserver.BaseRequestHandler):
    server: Socks5Server  # narrows the base type for the connector

    def handle(self) -> None:
        client = self.request
        target = self._negotiate(client)
        if target is None:
            return
        host, port = target

        try:
            tor_stream = self.server.tor.connect_stream(
                host,
                port,
                isolation_key=("socks", host),
                connect_timeout=self.server.connect_timeout,
                read_timeout=None,
            )
        except Exception:
            _reply(client, _REP_HOST_UNREACHABLE)
            return

        _reply(client, _REP_SUCCESS)
        _relay(client, tor_stream)

    def _negotiate(self, client: socket.socket) -> tuple[str, int] | None:
        """Run the SOCKS5 greeting and CONNECT request; return (host, port)."""
        greeting = _recv_exact(client, 2)
        if greeting is None or greeting[0] != _VERSION:
            return None
        if _recv_exact(client, greeting[1]) is None:  # method list
            return None
        client.sendall(bytes([_VERSION, _NO_AUTH]))

        request = _recv_exact(client, 4)
        if request is None or request[0] != _VERSION:
            return None
        if request[1] != _CMD_CONNECT:
            _reply(client, _REP_CMD_NOT_SUPPORTED)
            return None

        atyp = request[3]
        if atyp == _ATYP_IPV4:
            raw = _recv_exact(client, 4)
            host = socket.inet_ntoa(raw) if raw else None
        elif atyp == _ATYP_IPV6:
            raw = _recv_exact(client, 16)
            host = socket.inet_ntop(socket.AF_INET6, raw) if raw else None
        elif atyp == _ATYP_DOMAIN:
            length = _recv_exact(client, 1)
            raw = _recv_exact(client, length[0]) if length else None
            host = raw.decode("idna") if raw else None
        else:
            _reply(client, _REP_ATYP_NOT_SUPPORTED)
            return None

        port_bytes = _recv_exact(client, 2)
        if host is None or port_bytes is None:
            _reply(client, _REP_GENERAL_FAILURE)
            return None
        return host, struct.unpack(">H", port_bytes)[0]


def _relay(client: socket.socket, tor_stream: Stream) -> None:
    """Pump bytes both ways until either side closes, then tear both down."""

    def client_to_tor() -> None:
        with contextlib.suppress(Exception):
            while True:
                data = client.recv(_RELAY_CHUNK)
                if not data:
                    break
                tor_stream.send(data)

    pump = threading.Thread(target=client_to_tor, name="torquests-socks", daemon=True)
    pump.start()
    try:
        while True:
            data = tor_stream.recv(_RELAY_CHUNK)
            if not data:
                break
            client.sendall(data)
    except OSError:
        pass
    finally:
        # Closing both ends unblocks the other pump: the stream wakes its blocked
        # reader with EOF, and the socket shutdown unblocks client.recv().
        with contextlib.suppress(Exception):
            tor_stream.close()
        with contextlib.suppress(OSError):
            client.shutdown(socket.SHUT_RDWR)
        pump.join(timeout=5.0)


class Socks5Server(socketserver.ThreadingTCPServer):
    """A threaded SOCKS5 server whose CONNECTs are carried over Tor."""

    # On POSIX, SO_REUSEADDR is the safe TIME_WAIT-reuse convention. On Windows it
    # is a local-hijack vector: another local process can rebind 127.0.0.1:port and
    # steal SOCKS connections (a deanonymization risk). server_bind() drops it there
    # and takes exclusive ownership of the address instead.
    allow_reuse_address = True
    daemon_threads = True

    def server_bind(self) -> None:
        if sys.platform == "win32":
            # SO_EXCLUSIVEADDRUSE prevents any other socket from binding this
            # address via SO_REUSEADDR, which is the behavior Windows servers want
            # and the reason CPython's own socket.create_server() omits SO_REUSEADDR
            # off POSIX. Suppressing SO_REUSEADDR here keeps the base class from
            # re-enabling the hijack path.
            self.allow_reuse_address = False
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def __init__(
        self,
        address: tuple[str, int],
        tor: TorConnector,
        *,
        owns_tor: bool = False,
        connect_timeout: float = 60.0,
    ) -> None:
        super().__init__(address, _Socks5Handler)
        self.tor = tor
        self._owns_tor = owns_tor
        self.connect_timeout = connect_timeout

    def server_close(self) -> None:
        super().server_close()
        if self._owns_tor:
            self.tor.close()


def serve(host: str = "127.0.0.1", port: int = 9050, *, tor: TorConnector | None = None) -> None:
    """Run a SOCKS5-over-Tor proxy on ``host:port`` until interrupted.

    If no client is given, one is bootstrapped (with unbounded read timeouts, so
    idle proxied connections are not dropped) and closed on exit.
    """
    owns_tor = tor is None
    connector: TorConnector = tor or TorClient.bootstrap(TorConfig(read_timeout=None))
    server = Socks5Server((host, port), connector, owns_tor=owns_tor)
    try:
        server.serve_forever()
    finally:
        server.server_close()
