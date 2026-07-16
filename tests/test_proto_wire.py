"""Tests for the wire-format layer: cells, link specifiers, relay bodies, certs."""

from __future__ import annotations

from collections.abc import Callable

from hypothesis import given
from hypothesis import strategies as st

from torquests._proto import cells, relay
from torquests._proto.certs import Ed25519Certificate
from torquests._proto.constants import (
    CELL_PAYLOAD_LEN,
    RELAY_PAYLOAD_LEN,
    Cell,
    HandshakeType,
    Relay,
)
from torquests._proto.linkspec import (
    LinkSpecifier,
    LinkSpecType,
    pack_block,
    parse_block,
)

from .crypto_helpers import ed25519_public_from_seed, ed25519_sign


def make_recv(data: bytes) -> Callable[[int], bytes]:
    buf = bytearray(data)

    def recv_exact(n: int) -> bytes:
        chunk = bytes(buf[:n])
        del buf[:n]
        return chunk

    return recv_exact


# --- Cell framing ---------------------------------------------------------- #


def test_versions_cell_uses_two_byte_circid_and_roundtrips() -> None:
    raw = cells.VersionsCell((4, 5)).to_raw()
    packed = raw.pack(link_version=2)
    assert packed[:2] == b"\x00\x00"  # 2-byte CircID
    assert packed[2] == Cell.VERSIONS
    parsed = cells.VersionsCell.from_raw(cells.read_cell(make_recv(packed), link_version=2))
    assert parsed.versions == (4, 5)


def test_read_cell_frames_fixed_then_variable() -> None:
    create2 = cells.Create2Cell(HandshakeType.NTOR, b"handshake").to_raw(circ_id=0x80000001)
    certs = cells.CertsCell(((4, b"cert-bytes"),)).to_raw()
    stream = create2.pack(4) + certs.pack(4)
    recv = make_recv(stream)
    first = cells.read_cell(recv, 4)
    second = cells.read_cell(recv, 4)
    assert first.circ_id == 0x80000001
    assert cells.Create2Cell.from_raw(first).handshake_data == b"handshake"
    assert cells.CertsCell.from_raw(second).by_type(4) == b"cert-bytes"


def test_fixed_cell_pads_to_509_and_rejects_oversize() -> None:
    packed = cells.RawCell(1, Cell.NETINFO, b"abc").pack(4)
    assert len(packed) == 4 + 1 + CELL_PAYLOAD_LEN
    import pytest

    with pytest.raises(ValueError):
        cells.RawCell(1, Cell.NETINFO, b"x" * 600).pack(4)


def test_create2_created2_destroy_roundtrip() -> None:
    c2 = cells.Create2Cell(HandshakeType.NTOR, b"\x01\x02\x03")
    assert cells.Create2Cell.from_raw(c2.to_raw(5)) == c2
    cd = cells.Created2Cell(b"\x04\x05")
    assert cells.Created2Cell.from_raw(cd.to_raw(5)) == cd
    d = cells.DestroyCell(reason=3)
    assert cells.DestroyCell.from_raw(d.to_raw(5)) == d


def test_netinfo_roundtrip() -> None:
    cell = cells.NetInfoCell(timestamp=0, other_address="38.229.33.10", my_addresses=())
    parsed = cells.NetInfoCell.from_raw(cell.to_raw())
    assert parsed.timestamp == 0
    assert parsed.other_address == "38.229.33.10"
    assert parsed.my_addresses == ()


def test_certs_cell_by_type() -> None:
    cell = cells.CertsCell(((4, b"identity"), (5, b"tls")))
    parsed = cells.CertsCell.from_raw(cell.to_raw())
    assert parsed.by_type(4) == b"identity"
    assert parsed.by_type(5) == b"tls"
    assert parsed.by_type(99) is None


# --- Link specifiers ------------------------------------------------------- #


def test_linkspec_ipv4_roundtrip() -> None:
    spec = LinkSpecifier.ipv4("38.229.33.10", 9001)
    assert spec.type == LinkSpecType.IPV4
    assert spec.endpoint == ("38.229.33.10", 9001)
    assert parse_block(pack_block([spec]))[0] == spec


def test_linkspec_ipv6_and_ids_roundtrip() -> None:
    specs = [
        LinkSpecifier.ipv6("2001:db8::1", 443),
        LinkSpecifier.legacy_id(b"\x11" * 20),
        LinkSpecifier.ed25519_id(b"\x22" * 32),
    ]
    parsed = parse_block(pack_block(specs))
    assert parsed == specs
    assert parsed[0].endpoint == ("2001:db8::1", 443)


def test_linkspec_rejects_bad_lengths() -> None:
    import pytest

    with pytest.raises(ValueError):
        LinkSpecifier.legacy_id(b"short")
    with pytest.raises(ValueError):
        LinkSpecifier.ed25519_id(b"short")


# --- Relay cells and bodies ------------------------------------------------ #


def test_relaycell_roundtrip_preserves_fields() -> None:
    cell = relay.RelayCell(command=Relay.DATA, stream_id=42, data=b"payload")
    parsed = relay.RelayCell.parse(cell.pack())
    assert parsed.command == Relay.DATA
    assert parsed.stream_id == 42
    assert parsed.data == b"payload"
    assert parsed.recognized == 0


def test_digest_input_zeros_the_digest_field() -> None:
    cell = relay.RelayCell(Relay.DATA, 1, b"x").with_digest(b"\xaa\xbb\xcc\xdd")
    assert cell.pack()[5:9] == b"\xaa\xbb\xcc\xdd"
    assert cell.digest_input()[5:9] == b"\x00\x00\x00\x00"


def test_relaycell_padding_is_zeros_then_random_entropy() -> None:
    # tor-spec (relay-cells): padding SHOULD be four zero bytes then random bytes,
    # so a relay cell is not a fixed all-zero fingerprint to the terminating hop.
    cell = relay.RelayCell(Relay.DATA, 7, b"payload")
    packed = cell.pack()
    assert len(packed) == CELL_PAYLOAD_LEN
    tail = packed[11 + len(b"payload") :]
    assert tail[:4] == b"\x00\x00\x00\x00"
    assert tail[4:] != b"\x00" * len(tail[4:])  # the remainder carries entropy


def test_relaycell_padding_is_stable_across_derived_forms() -> None:
    # digest_input() (digest zeroed) and with_digest() (digest set) must carry the
    # same random tail, or the running digest would not match the wire bytes.
    cell = relay.RelayCell(Relay.DATA, 1, b"abc")
    di = cell.digest_input()
    wire = cell.with_digest(b"\x01\x02\x03\x04").pack()
    assert di[11 + 3 :] == wire[11 + 3 :]


def test_begin_body_format() -> None:
    assert relay.begin_body("example.com", 443) == b"example.com:443\x00\x00\x00\x00\x00"
    # An onion service uses an empty address.
    assert relay.begin_body("", 80) == b":80\x00\x00\x00\x00\x00"


def test_extend2_extended2_roundtrip() -> None:
    specs = [LinkSpecifier.ipv4("1.2.3.4", 9001), LinkSpecifier.ed25519_id(b"\x33" * 32)]
    body = relay.extend2_body(specs, HandshakeType.NTOR, b"onionskin")
    parsed_specs = parse_block(body)
    assert parsed_specs == specs
    extended = relay.Extended2.parse(cells.Created2Cell(b"replydata").to_raw(1).payload)
    assert extended.handshake_data == b"replydata"


def test_sendme_v1_body_and_end_reason() -> None:
    import pytest

    digest = b"\x07" * 20
    assert relay.sendme_v1_body(digest) == b"\x01\x00\x14" + digest
    with pytest.raises(ValueError):
        relay.sendme_v1_body(b"short")
    assert relay.parse_end_reason(relay.end_body()) == relay.EndReason.DONE
    assert relay.parse_end_reason(b"") == relay.EndReason.MISC


# --- Certificates ---------------------------------------------------------- #


def _build_self_signed_cert(cert_type: int = 4) -> tuple[bytes, bytes]:
    """Return (cert_bytes, identity_pubkey) for a self-signed ed25519 cert."""
    import struct

    identity_seed = bytes([9]) * 32
    identity_pub = ed25519_public_from_seed(identity_seed)
    signing_key = ed25519_public_from_seed(bytes([3]) * 32)  # the certified key
    ext = struct.pack(">H", 32) + bytes([0x04, 0x00]) + identity_pub
    body = (
        bytes([1, cert_type])
        + struct.pack(">I", 500000)  # expiration hours
        + bytes([1])
        + signing_key
        + bytes([1])  # one extension
        + ext
    )
    signature = ed25519_sign(identity_seed, body)
    return body + signature, identity_pub


def test_certificate_parse_and_verify() -> None:
    cert_bytes, identity_pub = _build_self_signed_cert()
    cert = Ed25519Certificate.parse(cert_bytes)
    assert cert.version == 1
    assert cert.cert_type == 4
    assert cert.signing_key == identity_pub
    assert cert.verify(identity_pub)
    assert cert.verify_self_signed()


def test_certificate_rejects_tampered_signature() -> None:
    cert_bytes, identity_pub = _build_self_signed_cert()
    tampered = bytearray(cert_bytes)
    tampered[-1] ^= 0xFF
    cert = Ed25519Certificate.parse(bytes(tampered))
    assert not cert.verify(identity_pub)
    assert not cert.verify_self_signed()


def test_certificate_expiry() -> None:
    cert_bytes, _ = _build_self_signed_cert()
    cert = Ed25519Certificate.parse(cert_bytes)
    assert cert.is_expired(500000 * 3600)
    assert not cert.is_expired(499999 * 3600)


# --- Property-based round trips -------------------------------------------- #


@given(
    circ_id=st.integers(min_value=0, max_value=0xFFFFFFFF),
    payload=st.binary(max_size=CELL_PAYLOAD_LEN),
)
def test_fixed_cell_framing_property(circ_id: int, payload: bytes) -> None:
    raw = cells.RawCell(circ_id, Cell.NETINFO, payload)
    reread = cells.read_cell(make_recv(raw.pack(4)), 4)
    assert reread.circ_id == circ_id
    assert reread.command == Cell.NETINFO
    assert reread.payload == payload.ljust(CELL_PAYLOAD_LEN, b"\x00")


@given(
    command=st.integers(min_value=0, max_value=255),
    stream_id=st.integers(min_value=0, max_value=0xFFFF),
    data=st.binary(max_size=498),
)
def test_relaycell_roundtrip_property(command: int, stream_id: int, data: bytes) -> None:
    parsed = relay.RelayCell.parse(relay.RelayCell(command, stream_id, data).pack())
    assert (parsed.command, parsed.stream_id, parsed.data) == (command, stream_id, data)


# --- Remaining paths ------------------------------------------------------- #


def test_relay_data_oversize_raises() -> None:
    import pytest

    with pytest.raises(ValueError):
        relay.RelayCell(Relay.DATA, 1, b"x" * 499).pack()


def test_relaycell_parse_rejects_oversize_length() -> None:
    import struct

    import pytest

    from torquests.exceptions import CircuitError

    # A length field claiming more than the payload can hold must fail loudly with
    # the typed circuit error the receiver path already handles, not a bare
    # ValueError/struct.error that would escape untyped through circuit teardown.
    body = bytearray(relay.RelayCell(Relay.DATA, 1, b"x").pack())
    body[9:11] = struct.pack(">H", RELAY_PAYLOAD_LEN + 1)
    with pytest.raises(CircuitError) as excinfo:
        relay.RelayCell.parse(bytes(body))
    assert not isinstance(excinfo.value, (ValueError, struct.error))


def test_extended2_parse_rejects_truncation() -> None:
    import struct

    import pytest

    from torquests.exceptions import CircuitError

    # EXTENDED2 is parsed on the universal circuit-extend path. A body too short for
    # its length field, or one whose declared handshake overruns the body, must fail
    # with the typed CircuitError the build-retry loop catches, not a bare
    # struct.error that would escape untyped past circuit teardown.
    with pytest.raises(CircuitError) as too_short:
        relay.Extended2.parse(b"\x00")  # one byte: no room for the 2-byte length
    assert not isinstance(too_short.value, (ValueError, struct.error))

    overrun = struct.pack(">H", 64) + b"\x11" * 10  # claims 64 handshake bytes, carries 10
    with pytest.raises(CircuitError) as truncated:
        relay.Extended2.parse(overrun)
    assert not isinstance(truncated.value, (ValueError, struct.error))


def test_endpoint_rejects_wrong_length_specifier() -> None:
    import pytest

    from torquests._proto.constants import LinkSpecType

    # A malformed IPv4 specifier (not 6 bytes) reaches .endpoint on the onion
    # connect path. It must fail loud with ValueError, not a bare struct.error, so
    # the caller (intro_point_relay_info) can convert it to a typed onion error.
    bad_ipv4 = LinkSpecifier(LinkSpecType.IPV4, b"\x0a\x00\x00")  # three bytes
    with pytest.raises(ValueError):
        _ = bad_ipv4.endpoint
    bad_ipv6 = LinkSpecifier(LinkSpecType.IPV6, b"\x00" * 10)  # too short for 16 + 2
    with pytest.raises(ValueError):
        _ = bad_ipv6.endpoint


def test_certificate_parse_rejects_short() -> None:
    import pytest

    with pytest.raises(ValueError):
        Ed25519Certificate.parse(b"\x00" * 10)


def test_linkspec_block_rejects_truncation() -> None:
    import pytest

    # Claims one specifier but the body is truncated.
    with pytest.raises(ValueError):
        parse_block(bytes([1, LinkSpecType.IPV4, 6, 1, 2]))
    with pytest.raises(ValueError):
        parse_block(b"")
