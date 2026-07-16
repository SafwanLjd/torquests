"""Tests for the v3 onion rendezvous orchestration."""

from __future__ import annotations

import struct

import pytest

from torquests._net.channel import Channel
from torquests._net.circuit import Circuit, build_circuit
from torquests._net.hop import RelayInfo
from torquests._onion.descriptor import HsDescriptor, IntroPoint
from torquests._onion.rendezvous import (
    _introduce1_header,
    _introduce1_plaintext,
    connect_to_service,
    intro_point_relay_info,
)
from torquests._proto.constants import LinkSpecType, Relay
from torquests._proto.linkspec import LinkSpecifier
from torquests._proto.relay import RelayCell
from torquests.exceptions import CircuitError, IntroductionError

from .fakes import FakeRelay, FakeRelayTransport
from .onion_service_fake import FakeOnionService


def test_introduce1_header_format() -> None:
    auth_key = bytes(range(32))
    header = _introduce1_header(auth_key)
    assert len(header) == 56
    assert header[:20] == bytes(20)  # legacy key id
    assert header[20] == 0x02  # auth key type ed25519
    assert struct.unpack(">H", header[21:23])[0] == 32
    assert header[23:55] == auth_key
    assert header[55] == 0  # zero extensions


def test_introduce1_plaintext_carries_cookie_and_rendezvous_point() -> None:
    cookie = bytes(range(20))
    rp = RelayInfo(("1.2.3.4", 9001), bytes([7]) * 32, bytes([1]) * 20, bytes([2]) * 32)
    plaintext = _introduce1_plaintext(cookie, rp)
    assert plaintext[:20] == cookie
    assert plaintext[20] == 0  # extensions
    assert plaintext[21] == 0x01  # ntor onion key type
    assert plaintext[24:56] == rp.ntor_onion_key


def test_intro_point_relay_info_extracts_link_specifiers() -> None:
    intro = IntroPoint(
        link_specifiers=[
            LinkSpecifier.ipv4("38.229.33.10", 9001),
            LinkSpecifier.legacy_id(bytes([9]) * 20),
            LinkSpecifier.ed25519_id(bytes([8]) * 32),
        ],
        onion_key=bytes([5]) * 32,
        auth_key=bytes([6]) * 32,
        enc_key=bytes([7]) * 32,
    )
    info = intro_point_relay_info(intro)
    assert info.address == ("38.229.33.10", 9001)
    assert info.identity_digest == bytes([9]) * 20
    assert info.ed_identity == bytes([8]) * 32
    assert info.ntor_onion_key == bytes([5]) * 32


def test_intro_point_relay_info_rejects_a_malformed_address() -> None:
    # A malformed IPv4 link specifier in an (authenticated) descriptor must surface
    # as a typed IntroductionError -- which connect_to_service's failover loop
    # catches -- rather than a bare struct.error/ValueError that would abort it.
    intro = IntroPoint(
        link_specifiers=[
            LinkSpecifier(LinkSpecType.IPV4, b"\x0a\x00\x00"),  # three bytes, not six
            LinkSpecifier.legacy_id(bytes(20)),
            LinkSpecifier.ed25519_id(bytes(32)),
        ],
        onion_key=bytes(32),
        auth_key=bytes(32),
        enc_key=bytes(32),
    )
    with pytest.raises(IntroductionError):
        intro_point_relay_info(intro)


def test_full_rendezvous_flow_installs_matching_service_hop() -> None:
    service = FakeOnionService()

    intro_relay = FakeRelay(3, onion_service=service)
    service.intro_relay = intro_relay.hops[-1]
    intro_transport = FakeRelayTransport(intro_relay)

    rend_relay = FakeRelay(3)
    rend_transport = FakeRelayTransport(rend_relay)
    service.rend_transport = rend_transport

    rend_channel = Channel.open(rend_transport, "203.0.113.1")
    intro_channel = Channel.open(intro_transport, "203.0.113.2")
    try:
        rend_circuit = build_circuit(rend_channel, rend_relay.path())
        rendezvous_point = rend_relay.path()[-1]

        def build_intro_circuit(_: RelayInfo) -> Circuit:
            return build_circuit(intro_channel, intro_relay.path())

        result = connect_to_service(
            service.descriptor(),
            service.subcredential,
            rend_circuit,
            rendezvous_point,
            build_intro_circuit,
        )

        assert result is rend_circuit
        assert len(rend_circuit.hops) == 4  # three real hops plus the virtual service hop

        # The client's virtual hop and the service's crypto must be mirror images:
        # a cell the client stamps and encrypts must decrypt and be recognized.
        client_hop = rend_circuit.hops[-1].crypto
        service_hop = service.service_crypto
        assert service_hop is not None
        stamped = client_hop.stamp_forward(RelayCell(Relay.DATA, 1, b"hello service"))
        on_wire = client_hop.apply_forward_cipher(stamped.pack())
        recovered = service_hop.recognize_forward(service_hop.apply_forward_cipher(on_wire))
        assert recovered is not None
        assert recovered.data == b"hello service"
    finally:
        rend_channel.close()
        intro_channel.close()


def test_rendezvous_fails_over_to_the_next_intro_point() -> None:
    # A descriptor lists a dead introduction point before the live one. The first
    # attempt's circuit will not build, and the rendezvous must fall through to the
    # second intro point rather than aborting the whole connection.
    service = FakeOnionService()

    intro_relay = FakeRelay(3, onion_service=service)
    service.intro_relay = intro_relay.hops[-1]
    intro_transport = FakeRelayTransport(intro_relay)

    rend_relay = FakeRelay(3)
    rend_transport = FakeRelayTransport(rend_relay)
    service.rend_transport = rend_transport

    rend_channel = Channel.open(rend_transport, "203.0.113.1")
    intro_channel = Channel.open(intro_transport, "203.0.113.2")
    try:
        rend_circuit = build_circuit(rend_channel, rend_relay.path())
        rendezvous_point = rend_relay.path()[-1]

        live_intro = service.descriptor().intro_points[0]
        dead_intro = IntroPoint(
            link_specifiers=[
                LinkSpecifier.ipv4("10.0.0.9", 9001),
                LinkSpecifier.legacy_id(bytes([1]) * 20),
                LinkSpecifier.ed25519_id(bytes([2]) * 32),
            ],
            onion_key=bytes([3]) * 32,
            auth_key=bytes([4]) * 32,
            enc_key=bytes([5]) * 32,
        )
        descriptor = HsDescriptor(
            lifetime=180, revision_counter=1, intro_points=[dead_intro, live_intro]
        )

        tried: list[bytes] = []

        def build_intro_circuit(info: RelayInfo) -> Circuit:
            tried.append(info.ed_identity)
            if info.ed_identity == dead_intro.link_specifiers[2].data:
                raise CircuitError("introduction circuit is dead")
            return build_circuit(intro_channel, intro_relay.path())

        result = connect_to_service(
            descriptor,
            service.subcredential,
            rend_circuit,
            rendezvous_point,
            build_intro_circuit,
        )

        assert result is rend_circuit
        assert len(rend_circuit.hops) == 4  # the live intro point completed the rendezvous
        # The dead intro was tried first, then failover reached the live one.
        assert tried == [dead_intro.link_specifiers[2].data, live_intro.link_specifiers[2].data]
    finally:
        rend_channel.close()
        intro_channel.close()
