"""An in-memory Tor path and transport for offline tests.

``FakeRelay`` simulates a whole circuit path: it performs the link handshake as
the guard, runs an ntor handshake per hop as circuits are built and extended, and
acts as a simple exit (answering BEGIN with CONNECTED and echoing DATA). Backward
cells are stamped and onion-encrypted hop by hop, exactly as a real path would.
``FakeRelayTransport`` shuttles bytes without a socket, which is what lets the
circuit, stream, and onion layers be tested with sockets disabled.
"""

from __future__ import annotations

import hashlib
import struct
import threading

from torquests._crypto.primitives import (
    hkdf_sha256_expand,
    hmac_sha256,
    x25519,
    x25519_keypair,
)
from torquests._net.hop import RelayInfo
from torquests._proto.cells import (
    CertsCell,
    Create2Cell,
    Created2Cell,
    NetInfoCell,
    RawCell,
    VersionsCell,
    read_cell,
)
from torquests._proto.constants import (
    CIRCUIT_WINDOW_INCREMENT,
    NTOR_PROTOID,
    RELAY_PAYLOAD_LEN,
    Cell,
    CertType,
    Relay,
    is_variable_cell,
)
from torquests._proto.relay import RelayCell, sendme_v1_body
from torquests._proto.relay_crypto import RelayCrypto
from torquests.exceptions import ChannelError

from .crypto_helpers import ed25519_public_from_seed, ed25519_sign


def _make_recv(data: bytes):
    buf = bytearray(data)

    def recv_exact(n: int) -> bytes:
        chunk = bytes(buf[:n])
        del buf[:n]
        return chunk

    return recv_exact


def build_cert(
    cert_type: int,
    certified_key: bytes,
    signer_seed: bytes,
    *,
    ext_identity: bytes | None = None,
    expiration_hours: int = 10_000_000,
) -> bytes:
    """Build a signed Tor ed25519 certificate."""
    body = bytes([1, cert_type]) + struct.pack(">I", expiration_hours) + bytes([1]) + certified_key
    if ext_identity is not None:
        ext = struct.pack(">H", 32) + bytes([0x04, 0x00]) + ext_identity
        body += bytes([1]) + ext
    else:
        body += bytes([0])
    return body + ed25519_sign(signer_seed, body)


class FakeHop:
    """One virtual relay on the path."""

    def __init__(self, index: int) -> None:
        base = hashlib.sha256(f"torquests-fake-hop-{index}".encode()).digest()
        self.identity_seed = base
        self.ed_identity = ed25519_public_from_seed(self.identity_seed)
        self.signing_seed = hashlib.sha256(base + b"signing").digest()
        self.signing_pub = ed25519_public_from_seed(self.signing_seed)
        self.tls_digest = hashlib.sha256(base + b"tls").digest()
        self.ntor_private, self.ntor_public = x25519_keypair()
        self.node_id = hashlib.sha1(self.ed_identity).digest()
        self.address = (f"10.0.0.{index + 1}", 9001)
        self.crypto: RelayCrypto | None = None

    def relay_info(self) -> RelayInfo:
        return RelayInfo(self.address, self.ntor_public, self.node_id, self.ed_identity)


class FakeRelay:
    """A simulated Tor path rooted at a guard."""

    def __init__(
        self,
        num_hops: int = 3,
        *,
        valid_certs: bool = True,
        refuse_begin: bool = False,
        stall_begin: bool = False,
        http_response: bytes | None = None,
        stall_after_bytes: int | None = None,
        dir_document: bytes | None = None,
        onion_service: object | None = None,
        send_circuit_sendmes: bool = True,
    ) -> None:
        self.hops = [FakeHop(i) for i in range(num_hops)]
        self._valid_certs = valid_certs
        self._refuse_begin = refuse_begin
        # When True the exit never answers RELAY_BEGIN, so the client's connect
        # blocks until its connect budget elapses (a timeout, not a refusal).
        self._stall_begin = stall_begin
        self._http_response = http_response  # when set, the exit acts as an HTTP origin
        # When set, the exit delivers only this many leading bytes of the response
        # and then goes silent (no RELAY_END), so a read past the prefix blocks
        # until the stream's read timeout fires.
        self._stall_after_bytes = stall_after_bytes
        # When set, the last hop acts as a directory cache: it answers BEGIN_DIR
        # with CONNECTED and serves this body for any tunneled directory GET.
        self._dir_document = dir_document
        self.onion_service = onion_service  # when set, handles rendezvous/introduce cells
        # When True the exit runs receive-side circuit flow control and returns an
        # authenticated v1 SENDME every window increment, as a real relay does.
        self._send_circuit_sendmes = send_circuit_sendmes
        self._exit_delivered = 0
        self._stream_buffers: dict[int, bytearray] = {}
        self._dir_streams: set[int] = set()
        self.dir_requests: list[str] = []  # request paths seen on BEGIN_DIR streams
        self.link_version = 2
        self.circ_id = 0
        self._inbuf = bytearray()

    # --- path exposure ----------------------------------------------------- #

    @property
    def guard(self) -> FakeHop:
        return self.hops[0]

    @property
    def tls_digest(self) -> bytes:
        return self.guard.tls_digest

    def path(self, length: int | None = None) -> list[RelayInfo]:
        hops = self.hops if length is None else self.hops[:length]
        return [hop.relay_info() for hop in hops]

    @property
    def _established(self) -> list[FakeHop]:
        return [hop for hop in self.hops if hop.crypto is not None]

    # --- link handshake ---------------------------------------------------- #

    def certs_cell(self) -> RawCell:
        guard = self.guard
        identity_cert = build_cert(
            CertType.IDENTITY_V_SIGNING,
            guard.signing_pub,
            guard.identity_seed,
            ext_identity=guard.ed_identity,
        )
        tls_signer = guard.signing_seed if self._valid_certs else guard.identity_seed
        tls_cert = build_cert(CertType.SIGNING_V_TLS, guard.tls_digest, tls_signer)
        return CertsCell(
            ((CertType.IDENTITY_V_SIGNING, identity_cert), (CertType.SIGNING_V_TLS, tls_cert))
        ).to_raw()

    # --- byte framing ------------------------------------------------------ #

    def process(self, data: bytes) -> bytes:
        self._inbuf += data
        out = bytearray()
        while (cell := self._frame_one()) is not None:
            out += self._handle(cell)
        return bytes(out)

    def _frame_one(self) -> RawCell | None:
        width = 4 if self.link_version >= 4 else 2
        if len(self._inbuf) < width + 1:
            return None
        command = self._inbuf[width]
        if is_variable_cell(command):
            if len(self._inbuf) < width + 3:
                return None
            (length,) = struct.unpack(">H", self._inbuf[width + 1 : width + 3])
            total = width + 3 + length
        else:
            total = width + 1 + 509
        if len(self._inbuf) < total:
            return None
        cell_bytes = bytes(self._inbuf[:total])
        del self._inbuf[:total]
        return read_cell(_make_recv(cell_bytes), self.link_version)

    # --- cell handling ----------------------------------------------------- #

    def _handle(self, cell: RawCell) -> bytes:
        if cell.command == Cell.VERSIONS:
            self.link_version = 5
            out = VersionsCell((4, 5)).to_raw().pack(link_version=2)
            out += self.certs_cell().pack(self.link_version)
            out += NetInfoCell(0, self.guard.address[0], ()).to_raw().pack(self.link_version)
            return out
        if cell.command == Cell.NETINFO:
            return b""
        if cell.command == Cell.CREATE2:
            self.circ_id = cell.circ_id
            reply = self._ntor_server(self.hops[0], Create2Cell.from_raw(cell).handshake_data)
            return Created2Cell(reply).to_raw(cell.circ_id).pack(self.link_version)
        if cell.command in (Cell.RELAY, Cell.RELAY_EARLY):
            return self._handle_forward(cell)
        if cell.command == Cell.DESTROY:
            return b""
        return b""

    def _ntor_server(self, hop: FakeHop, skin: bytes) -> bytes:
        node_id = skin[:20]
        client_pub = skin[52:84]
        y_priv, y_pub = x25519_keypair()
        secret_input = (
            x25519(y_priv, client_pub)
            + x25519(hop.ntor_private, client_pub)
            + hop.node_id
            + hop.ntor_public
            + client_pub
            + y_pub
            + NTOR_PROTOID
        )
        key_seed = hmac_sha256(NTOR_PROTOID + b":key_extract", secret_input)
        verify = hmac_sha256(NTOR_PROTOID + b":verify", secret_input)
        auth_input = (
            verify + node_id + hop.ntor_public + y_pub + client_pub + NTOR_PROTOID + b"Server"
        )
        auth = hmac_sha256(NTOR_PROTOID + b":mac", auth_input)
        hop.crypto = RelayCrypto.tor1(
            hkdf_sha256_expand(key_seed, NTOR_PROTOID + b":key_expand", 72)
        )
        return y_pub + auth

    def _handle_forward(self, cell: RawCell) -> bytes:
        body = cell.payload
        established = self._established
        for index, hop in enumerate(established):
            body = hop.crypto.apply_forward_cipher(body)  # type: ignore[union-attr]
            recognized = hop.crypto.recognize_forward(body)  # type: ignore[union-attr]
            if recognized is not None:
                out = bytearray()
                for reply in self._dispatch(recognized, index):
                    out += self._relay_backward(reply, index)
                return bytes(out)
        return b""

    def _dispatch(self, cell: RelayCell, hop_index: int) -> list[RelayCell]:
        if cell.command == Relay.EXTEND2:
            skin = cell.data[-84:]  # NODEID | B | X
            next_hop = self.hops[hop_index + 1]
            reply = self._ntor_server(next_hop, skin)
            return [RelayCell(Relay.EXTENDED2, 0, struct.pack(">H", len(reply)) + reply)]
        if cell.command == Relay.BEGIN:
            self._stream_buffers.pop(cell.stream_id, None)
            if self._stall_begin:
                return []  # never answer: the client's connect must time out
            if self._refuse_begin:
                return [RelayCell(Relay.END, cell.stream_id, bytes([3]))]  # CONNECTREFUSED
            connected = bytes([1, 2, 3, 4]) + struct.pack(">I", 3600)  # CONNECTED: 1.2.3.4, ttl
            return [RelayCell(Relay.CONNECTED, cell.stream_id, connected)]
        if cell.command == Relay.BEGIN_DIR:
            self._stream_buffers.pop(cell.stream_id, None)
            self._dir_streams.add(cell.stream_id)
            return [RelayCell(Relay.CONNECTED, cell.stream_id, b"")]  # dir CONNECTED, no address
        if cell.command == Relay.DATA:
            if cell.stream_id in self._dir_streams:
                return self._dir_data(cell)
            replies = self._exit_data(cell)
            replies.extend(self._maybe_circuit_sendme(hop_index))
            return replies
        if cell.command == Relay.ESTABLISH_RENDEZVOUS:
            return [RelayCell(Relay.RENDEZVOUS_ESTABLISHED, 0, b"")]
        if cell.command == Relay.INTRODUCE1:
            if self.onion_service is not None:
                self.onion_service.on_introduce1(cell.data)  # type: ignore[attr-defined]
            return [RelayCell(Relay.INTRODUCE_ACK, 0, struct.pack(">H", 0) + bytes([0]))]
        return []

    def _maybe_circuit_sendme(self, hop_index: int) -> list[RelayCell]:
        """Emit an authenticated v1 SENDME every window increment of DATA cells.

        The digest is the exit hop's forward running digest taken right after the
        boundary DATA cell was recognized, which is exactly the value the client
        recorded when it sent that cell (tor-spec, flow control / proposal 289).
        """
        if not self._send_circuit_sendmes:
            return []
        self._exit_delivered += 1
        if self._exit_delivered < CIRCUIT_WINDOW_INCREMENT:
            return []
        self._exit_delivered = 0
        digest = self._established[hop_index].crypto.forward_digest()[:20]  # type: ignore[union-attr]
        return [RelayCell(Relay.SENDME, 0, sendme_v1_body(digest))]

    def deliver_backward(self, relay_cell: RelayCell) -> bytes:
        """Frame a backward relay cell as if sent from the last hop (for injection)."""
        return self._relay_backward(relay_cell, len(self._established) - 1)

    def _dir_data(self, cell: RelayCell) -> list[RelayCell]:
        """Serve the canned directory document for a tunneled HTTP/1.0 GET."""
        buffer = self._stream_buffers.setdefault(cell.stream_id, bytearray())
        buffer += cell.data
        if b"\r\n\r\n" not in buffer:
            return []  # request headers not complete yet
        request_line = bytes(buffer).split(b"\r\n", 1)[0].decode("latin-1")
        fields = request_line.split(" ")
        self.dir_requests.append(fields[1] if len(fields) >= 2 else "")
        document = self._dir_document if self._dir_document is not None else b""
        response = (
            b"HTTP/1.0 200 OK\r\nContent-Length: "
            + str(len(document)).encode("ascii")
            + b"\r\n\r\n"
            + document
        )
        replies: list[RelayCell] = []
        for start in range(0, len(response), RELAY_PAYLOAD_LEN):
            chunk = response[start : start + RELAY_PAYLOAD_LEN]
            replies.append(RelayCell(Relay.DATA, cell.stream_id, chunk))
        replies.append(RelayCell(Relay.END, cell.stream_id, bytes([6])))  # DONE
        return replies

    def _exit_data(self, cell: RelayCell) -> list[RelayCell]:
        if self._http_response is None:
            return [RelayCell(Relay.DATA, cell.stream_id, cell.data)]  # echo
        buffer = self._stream_buffers.setdefault(cell.stream_id, bytearray())
        buffer += cell.data
        if b"\r\n\r\n" not in buffer:
            return []  # request headers not complete yet
        response = self._http_response
        stalling = self._stall_after_bytes is not None
        if stalling:
            response = response[: self._stall_after_bytes]
        replies: list[RelayCell] = []
        for start in range(0, len(response), RELAY_PAYLOAD_LEN):
            chunk = response[start : start + RELAY_PAYLOAD_LEN]
            replies.append(RelayCell(Relay.DATA, cell.stream_id, chunk))
        if not stalling:
            replies.append(RelayCell(Relay.END, cell.stream_id, bytes([6])))  # DONE
        return replies

    def _relay_backward(self, cell: RelayCell, origin_hop: int) -> bytes:
        established = self._established
        stamped = established[origin_hop].crypto.stamp_backward(cell)  # type: ignore[union-attr]
        body = stamped.pack()
        for index in range(origin_hop, -1, -1):
            body = established[index].crypto.apply_backward_cipher(body)  # type: ignore[union-attr]
        return RawCell(self.circ_id, Cell.RELAY, body).pack(self.link_version)

    def push_end(self, stream_id: int, reason: int = 6) -> RawCell:
        """Build a backward RELAY_END for a stream (for teardown tests)."""
        cell = RelayCell(Relay.END, stream_id, bytes([reason]))
        raw = self._relay_backward(cell, len(self._established) - 1)
        return read_cell(_make_recv(raw), self.link_version)


class FakeRelayTransport:
    """An in-memory transport that runs a :class:`FakeRelay` on the far end."""

    def __init__(self, relay: FakeRelay | None = None) -> None:
        self.relay = relay or FakeRelay()
        self._outbuf = bytearray()
        self._cond = threading.Condition()
        self._closed = False

    def connect(self) -> None:
        pass

    @property
    def certificate_digest(self) -> bytes:
        return self.relay.tls_digest

    def send(self, data: bytes) -> None:
        response = self.relay.process(data)
        if response:
            with self._cond:
                self._outbuf += response
                self._cond.notify_all()

    def inject(self, cell: RawCell) -> None:
        with self._cond:
            self._outbuf += cell.pack(self.relay.link_version)
            self._cond.notify_all()

    def inject_relay(self, relay_cell: RelayCell) -> None:
        """Inject a backward relay cell (stamped/encrypted through the path)."""
        data = self.relay.deliver_backward(relay_cell)
        with self._cond:
            self._outbuf += data
            self._cond.notify_all()

    def recv_exact(self, n: int) -> bytes:
        with self._cond:
            while len(self._outbuf) < n:
                if self._closed:
                    raise ChannelError("fake transport closed")
                self._cond.wait(timeout=5.0)
            chunk = bytes(self._outbuf[:n])
            del self._outbuf[:n]
            return chunk

    def set_read_timeout(self, timeout: float | None) -> None:
        pass

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()
