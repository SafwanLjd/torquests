"""Tests for the SOCKS5-over-Tor proxy, driven by the fake relay's echo exit."""

from __future__ import annotations

import socket
import struct
import sys
import threading

import pytest

from torquests.socks import Socks5Server

from .fakes import FakeRelay
from .test_adapter import FakeConnector


class _FakeSock:
    """An in-memory socket for exercising the SOCKS5 negotiation without I/O."""

    def __init__(self, inbound: bytes) -> None:
        self._in = bytearray(inbound)
        self.out = bytearray()

    def recv(self, n: int) -> bytes:
        chunk = bytes(self._in[:n])
        del self._in[:n]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.out += data


def test_negotiate_rejects_non_connect_command() -> None:
    from torquests.socks import _Socks5Handler

    # greeting (1 method, no-auth) + a BIND request (cmd 0x02) for 1.2.3.4:80
    payload = (
        bytes([0x05, 0x01, 0x00])
        + bytes([0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4])
        + struct.pack(">H", 80)
    )
    sock = _FakeSock(payload)
    handler = _Socks5Handler.__new__(_Socks5Handler)
    assert handler._negotiate(sock) is None  # type: ignore[arg-type]
    # last reply byte pair should carry REP=0x07 (command not supported)
    assert sock.out[-10] == 0x05
    assert sock.out[-9] == 0x07


def _socks_connect(proxy: tuple[str, int], host: str, port: int) -> socket.socket:
    client = socket.create_connection(proxy, timeout=10)
    client.sendall(bytes([0x05, 0x01, 0x00]))
    assert client.recv(2) == bytes([0x05, 0x00])
    request = bytes([0x05, 0x01, 0x00, 0x03, len(host)]) + host.encode() + struct.pack(">H", port)
    client.sendall(request)
    reply = client.recv(10)
    assert reply[0] == 0x05 and reply[1] == 0x00, reply
    return client


# A stand-in for Windows' SO_EXCLUSIVEADDRUSE, which is absent from the socket
# module off Windows; the real constant is negative, mirrored here.
_SO_EXCLUSIVEADDRUSE = -5


class _RecordingBindSock:
    """Captures setsockopt calls and satisfies TCPServer.server_bind's bind path."""

    def __init__(self) -> None:
        self.opts: list[tuple[int, int, int]] = []

    def setsockopt(self, level: int, option: int, value: int) -> None:
        self.opts.append((level, option, value))

    def bind(self, address: object) -> None:
        pass

    def getsockname(self) -> tuple[str, int]:
        return ("127.0.0.1", 9050)


def _bind_under_platform(monkeypatch: pytest.MonkeyPatch, platform: str) -> Socks5Server:
    """Drive Socks5Server.server_bind under a faked platform with a recording socket."""
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(socket, "SO_EXCLUSIVEADDRUSE", _SO_EXCLUSIVEADDRUSE, raising=False)
    server = Socks5Server.__new__(Socks5Server)  # bypass __init__ (and its real bind)
    server.socket = _RecordingBindSock()
    server.server_address = ("127.0.0.1", 9050)
    server.server_bind()
    return server


def test_socks5_server_takes_exclusive_bind_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    # On Windows, SO_REUSEADDR lets another local process rebind the port and hijack
    # SOCKS connections; the server must drop it and set SO_EXCLUSIVEADDRUSE instead.
    server = _bind_under_platform(monkeypatch, "win32")
    opts = server.socket.opts
    assert server.allow_reuse_address is False
    assert (socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1) in opts
    assert all(option != socket.SO_REUSEADDR for _, option, _ in opts)


def test_socks5_server_keeps_reuseaddr_on_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    # On POSIX, SO_REUSEADDR is the safe TIME_WAIT-reuse convention and must remain;
    # the Windows-only exclusive option must not be set.
    server = _bind_under_platform(monkeypatch, "linux")
    opts = server.socket.opts
    assert server.allow_reuse_address is True
    assert (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) in opts
    assert all(option != socket.SO_EXCLUSIVEADDRUSE for _, option, _ in opts)


@pytest.mark.usefixtures("socket_enabled")
def test_socks5_relays_bytes_through_tor() -> None:
    # The fake exit echoes DATA, so whatever we send through the proxy comes back.
    connector = FakeConnector(FakeRelay())
    server = Socks5Server(("127.0.0.1", 0), connector, owns_tor=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = _socks_connect(server.server_address, "example.com", 80)
        client.sendall(b"ping over socks")
        assert client.recv(64) == b"ping over socks"
        client.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
