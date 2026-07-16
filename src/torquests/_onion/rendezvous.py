"""The client side of the v3 onion introduction and rendezvous.

Given a parsed descriptor and a rendezvous circuit, this establishes a rendezvous
point, introduces the client to the service through an introduction point, and,
once the service answers, installs the service as a virtual innermost hop on the
rendezvous circuit. After that the caller opens a stream on the circuit to reach
the service.

Reference: rend-spec, "The introduction protocol" and "The rendezvous protocol".
"""

from __future__ import annotations

import os
import struct
from collections.abc import Callable

from .._net.circuit import Circuit
from .._net.hop import RelayInfo
from .._proto.constants import LinkSpecType, Relay
from .._proto.handshake import HsNtorHandshake
from .._proto.linkspec import pack_block
from .._proto.relay import RelayCell
from .._proto.relay_crypto import RelayCrypto
from ..exceptions import ChannelError, CircuitError, IntroductionError, RendezvousError
from .descriptor import HsDescriptor, IntroPoint

# The virtual service hop is spliced onto the circuit, never extended to, so its
# relay fields are placeholders.
_VIRTUAL_SERVICE = RelayInfo(("onion-service", 0), bytes(32), bytes(20), bytes(32))

_NTOR_ONION_KEY_TYPE = 0x01
_AUTH_KEY_TYPE_ED25519 = 0x02

IntroCircuitBuilder = Callable[[RelayInfo], Circuit]


def intro_point_relay_info(intro: IntroPoint) -> RelayInfo:
    """Build the relay reference for an introduction point from its link specifiers."""
    address: tuple[str, int] | None = None
    legacy_id: bytes | None = None
    ed_identity: bytes | None = None
    for spec in intro.link_specifiers:
        if spec.type == LinkSpecType.IPV4:
            try:
                address = spec.endpoint
            except ValueError as exc:
                raise IntroductionError(
                    f"introduction point has a malformed address specifier: {exc}"
                ) from exc
        elif spec.type == LinkSpecType.LEGACY_ID:
            legacy_id = spec.data
        elif spec.type == LinkSpecType.ED25519_ID:
            ed_identity = spec.data
    if address is None or legacy_id is None or ed_identity is None:
        raise IntroductionError("introduction point is missing a required link specifier")
    return RelayInfo(address, intro.onion_key, legacy_id, ed_identity)


def _introduce1_header(auth_key: bytes) -> bytes:
    # LEGACY_KEY_ID(20 zeros) | AUTH_KEY_TYPE | AUTH_KEY_LEN | AUTH_KEY | N_EXTENSIONS(0)
    return (
        bytes(20)
        + bytes([_AUTH_KEY_TYPE_ED25519])
        + struct.pack(">H", len(auth_key))
        + auth_key
        + bytes([0])
    )


def _introduce1_plaintext(cookie: bytes, rendezvous_point: RelayInfo) -> bytes:
    # RENDEZVOUS_COOKIE | N_EXTENSIONS(0) | ONION_KEY (rendezvous point ntor key) | link specs
    return (
        cookie
        + bytes([0])
        + bytes([_NTOR_ONION_KEY_TYPE])
        + struct.pack(">H", len(rendezvous_point.ntor_onion_key))
        + rendezvous_point.ntor_onion_key
        + pack_block(rendezvous_point.link_specifiers())
    )


def _introduce(
    intro: IntroPoint,
    subcredential: bytes,
    cookie: bytes,
    rendezvous_point: RelayInfo,
    rendezvous_circuit: Circuit,
    build_intro_circuit: IntroCircuitBuilder,
    timeout: float,
) -> RelayCrypto:
    handshake = HsNtorHandshake(intro.auth_key, intro.enc_key, subcredential)
    header = _introduce1_header(intro.auth_key)
    body = header + handshake.encrypt_introduce(
        header, _introduce1_plaintext(cookie, rendezvous_point)
    )

    # Arm the RENDEZVOUS2 waiter on the rendezvous circuit before introducing, so a
    # fast reply is not missed.
    rendezvous_reply = rendezvous_circuit.arm_relay(Relay.RENDEZVOUS2)
    intro_circuit = build_intro_circuit(intro_point_relay_info(intro))
    try:
        ack = intro_circuit.arm_relay(Relay.INTRODUCE_ACK)
        intro_circuit.send_relay(RelayCell(Relay.INTRODUCE1, 0, body))
        ack_data = ack.result(timeout).data
        if len(ack_data) < 2:
            raise IntroductionError("INTRODUCE_ACK reply is too short for its status")
        (status,) = struct.unpack(">H", ack_data[:2])
        if status != 0:
            raise IntroductionError(f"introduction refused with status {status:#06x}")
    finally:
        intro_circuit.close()

    reply = rendezvous_reply.result(timeout).data
    if len(reply) < 64:
        raise RendezvousError("RENDEZVOUS2 reply is too short")
    keys = handshake.complete_rendezvous(reply[:32], reply[32:64])
    return RelayCrypto.hs_v3(keys.key_material)


def connect_to_service(
    descriptor: HsDescriptor,
    subcredential: bytes,
    rendezvous_circuit: Circuit,
    rendezvous_point: RelayInfo,
    build_intro_circuit: IntroCircuitBuilder,
    *,
    timeout: float = 60.0,
) -> Circuit:
    """Establish rendezvous, introduce, and splice the service onto the circuit.

    Returns ``rendezvous_circuit`` with the service installed as its innermost
    hop, ready for a stream to be opened to the service.
    """
    cookie = os.urandom(20)
    established = rendezvous_circuit.arm_relay(Relay.RENDEZVOUS_ESTABLISHED)
    rendezvous_circuit.send_relay(RelayCell(Relay.ESTABLISH_RENDEZVOUS, 0, cookie))
    established.result(timeout)

    if not descriptor.intro_points:
        raise IntroductionError("descriptor lists no introduction points")

    failures: list[str] = []
    for intro in descriptor.intro_points:
        try:
            service_crypto = _introduce(
                intro,
                subcredential,
                cookie,
                rendezvous_point,
                rendezvous_circuit,
                build_intro_circuit,
                timeout,
            )
        except (IntroductionError, RendezvousError, CircuitError, ChannelError) as exc:
            # A dead introduction point (its circuit will not build, or the ACK or
            # RENDEZVOUS2 never arrives) must not abort the whole introduction: try
            # the next one. CircuitError covers CircuitBuildTimeout.
            failures.append(str(exc))
            continue
        rendezvous_circuit.add_virtual_hop(service_crypto, _VIRTUAL_SERVICE)
        return rendezvous_circuit

    raise IntroductionError(f"all introduction points failed: {'; '.join(failures)}")
