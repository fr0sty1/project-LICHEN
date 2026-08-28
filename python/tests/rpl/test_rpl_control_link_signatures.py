# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""DIO, DAO, and DIS must ride signed link frames (spec 8.10 / link-01:4.2).

Independent oracles:
- RFC 6550 base-object layouts for DIS/DIO/DAO bodies
- ICMPv6 type 155 and codes 0/1/2
- draft-lichen-link-01 LLSec bits (S=bit5, SI=bit7, E=bit6)
- test/vectors/reference_schnorr48.py (PyNaCl; does not import lichen)
"""

from __future__ import annotations

import sys
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.ipv6.addr import ALL_RPL_NODES_MULTICAST
from lichen.ipv6.icmpv6 import Icmpv6Message
from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header, NextHeader
from lichen.l2_payload import wrap_schc_payload
from lichen.link.frame import LichenFrame
from lichen.link.link_layer import LinkLayer, ReceiveError, RxFrame
from lichen.rpl.dao import DaoError, DaoManager
from lichen.rpl.dodag import INFINITE_RANK, DodagRole, DodagState
from lichen.rpl.messages import DAO, DIO, DIS, RPL_ICMPV6_TYPE, RplCode
from lichen.rpl.trickle import TrickleTimer
from lichen.schc.headers import encode_rule255

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from reference_schnorr48 import (  # type: ignore[import-not-found]  # noqa: E402
    ReferenceIdentity,
    signature_transcript,
    verify,
)

# RFC 6550 6.1: RPL is ICMPv6 type 155; codes DIS=0, DIO=1, DAO=2.
_RPL_ICMPV6_TYPE = 155
_DIS_CODE = 0
_DIO_CODE = 1
_DAO_CODE = 2
_SCHC_DISPATCH = 0x14
_RULE_255 = 0xFF
_LLSEC_S = 1 << 5
_LLSEC_E = 1 << 6
_LLSEC_SI = 1 << 7
_SIGNATURE_LEN = 48
_SENDER_SEED = bytes((0x11,)) + bytes(31)
_RECEIVER_SEED = bytes((0x22,)) + bytes(31)
_DODAG_ID = IPv6Address("200::1")
_DODAG_PACKED = bytes.fromhex("02000000000000000000000000000001")

# RFC 6550 6.2 DIS base object: Flags, Reserved.
DIS_BODY = bytes((0x00, 0x00))

# RFC 6550 6.3 DIO base object plus the mandatory LICHEN Rule-Version option.
# G=1, MOP=1 (non-storing), Prf=0 => 0x88. Rank 256. Option 0x13 length 1 value 3.
DIO_BODY = (
    bytes((0x00, 0x01, 0x01, 0x00, 0x88, 0x00, 0x00, 0x00))
    + _DODAG_PACKED
    + bytes((0x13, 0x01, 0x03))
)

# RFC 6550 6.4 DAO base object with D=1 (DODAGID present), K=0, sequence 5.
DAO_BODY = bytes((0x00, 0x40, 0x00, 0x05)) + _DODAG_PACKED

CASES = (
    ("dis", _DIS_CODE, DIS_BODY, DIS()),
    (
        "dio",
        _DIO_CODE,
        DIO_BODY,
        DIO(
            rpl_instance_id=0,
            version=1,
            rank=256,
            dtsn=0,
            dodag_id=_DODAG_ID,
            grounded=True,
            mode_of_operation=1,
        ),
    ),
    (
        "dao",
        _DAO_CODE,
        DAO_BODY,
        DAO(rpl_instance_id=0, dao_sequence=5, dodag_id=_DODAG_ID),
    ),
)


class _MemoryRadio:
    def __init__(self) -> None:
        self.tx_history: list[bytes] = []
        self.rx_queue: list[tuple[bytes, int, int]] = []

    async def transmit(self, payload: bytes, channel: int = 0) -> bool:
        del channel
        self.tx_history.append(payload)
        return True

    async def receive(self, timeout_ms: int, channel: int = 0) -> tuple[bytes, int, int] | None:
        del timeout_ms, channel
        if self.rx_queue:
            return self.rx_queue.pop(0)
        return None

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        del freq_hz, tx_power_dbm

    async def cad(self, timeout_ms: int, channel: int = 0) -> bool:
        del timeout_ms, channel
        return False


def _link(identity: Identity, radio: _MemoryRadio, *peers: PeerIdentity) -> LinkLayer:
    by_iid = {peer.iid: peer for peer in peers}

    def lookup(hint: bytes) -> PeerIdentity | None:
        return by_iid.get(hint)

    link = LinkLayer(
        radio=radio,
        identity=identity,
        peer_lookup=lookup,
        peer_lookup_all=lambda: list(by_iid.values()),
        cad_enabled=False,
    )
    link.set_sequence(0, 0)
    return link


def _rpl_payload(identity: Identity, code: int, body: bytes) -> bytes:
    src = IPv6Address(IPv6Address("fe80::").packed[:8] + identity.iid)
    dst = ALL_RPL_NODES_MULTICAST
    icmp = Icmpv6Message(_RPL_ICMPV6_TYPE, code, body).to_bytes(src, dst)
    ipv6 = (
        IPv6Header(
            src_addr=src,
            dst_addr=dst,
            next_header=NextHeader.ICMPV6,
            payload_length=len(icmp),
            hop_limit=1,
        ).to_bytes()
        + icmp
    )
    return wrap_schc_payload(encode_rule255(ipv6))


def _parse_signed_wire(wire: bytes) -> tuple[int, int, bytes, bytes, bytes]:
    """Split a signed broadcast frame using only the link-01 4.1 layout."""
    if len(wire) < 1 + 4 + 8 + _SIGNATURE_LEN:
        raise AssertionError("wire shorter than signed broadcast minimum")
    length = wire[0]
    if length != len(wire) - 1:
        raise AssertionError("LENGTH does not match received size minus one")
    llsec = wire[1]
    dst_len = {0: 0, 1: 2, 2: 8, 3: 0}[llsec & 0x03]
    prefix_end = 1 + 4 + dst_len + 8
    payload = wire[prefix_end:-_SIGNATURE_LEN]
    signature = wire[-_SIGNATURE_LEN:]
    signer_eui64 = wire[1 + 4 + dst_len : prefix_end]
    return llsec, dst_len, signer_eui64, payload, signature


def _rpl_body_from_schc_payload(payload: bytes, expected_code: int) -> bytes:
    assert payload[0] == _SCHC_DISPATCH
    assert payload[1] == _RULE_255
    ipv6 = payload[2:]
    assert ipv6[0] >> 4 == 6
    assert ipv6[6] == int(NextHeader.ICMPV6)
    icmp = ipv6[HEADER_LENGTH:]
    assert icmp[0] == _RPL_ICMPV6_TYPE
    assert icmp[1] == expected_code
    return icmp[4:]


@pytest.mark.parametrize(("name", "code", "oracle_body", "message"), CASES)
def test_rpl_control_codec_matches_rfc6550_oracle(
    name: str,
    code: int,
    oracle_body: bytes,
    message: DIS | DIO | DAO,
) -> None:
    del name
    assert message.to_bytes() == oracle_body
    assert code in (_DIS_CODE, _DIO_CODE, _DAO_CODE)
    assert RPL_ICMPV6_TYPE == _RPL_ICMPV6_TYPE
    assert int(RplCode.DIS) == _DIS_CODE
    assert int(RplCode.DIO) == _DIO_CODE
    assert int(RplCode.DAO) == _DAO_CODE
    assert _DODAG_ID.packed == _DODAG_PACKED


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "code", "oracle_body", "message"), CASES)
async def test_rpl_control_tx_carries_valid_link_signature(
    name: str,
    code: int,
    oracle_body: bytes,
    message: DIS | DIO | DAO,
) -> None:
    del message
    sender_identity = Identity.from_seed(_SENDER_SEED)
    reference = ReferenceIdentity.from_seed(_SENDER_SEED)
    assert sender_identity.pubkey == reference.pubkey
    radio = _MemoryRadio()
    sender = _link(sender_identity, radio)

    payload = _rpl_payload(sender_identity, code, oracle_body)
    assert await sender.send(payload) is True
    assert len(radio.tx_history) == 1

    wire = radio.tx_history[0]
    llsec, dst_len, signer_eui64, inner, signature = _parse_signed_wire(wire)
    assert llsec & _LLSEC_S
    assert llsec & _LLSEC_SI
    assert not llsec & _LLSEC_E
    assert signer_eui64 == reference.eui64
    assert len(signature) == _SIGNATURE_LEN
    assert _rpl_body_from_schc_payload(inner, code) == oracle_body

    parsed = LichenFrame.from_bytes(wire)
    assert parsed.signature_present is True
    assert parsed.encrypted is False
    assert parsed.signer_eui64 == reference.eui64
    assert parsed.mic == signature
    assert parsed.payload == inner == payload

    transcript = signature_transcript(wire[:-_SIGNATURE_LEN], dst_len)
    assert verify(reference.pubkey, transcript, signature)

    flipped_payload = bytearray(transcript)
    flipped_payload[-1] ^= 0x01
    assert not verify(reference.pubkey, bytes(flipped_payload), signature)

    flipped_sig = bytes((signature[0] ^ 0x01,)) + signature[1:]
    assert not verify(reference.pubkey, transcript, flipped_sig), f"{name}: sig flip"


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "code", "oracle_body", "message"), CASES)
async def test_unsigned_rpl_control_is_rejected_before_routing_mutation(
    name: str,
    code: int,
    oracle_body: bytes,
    message: DIS | DIO | DAO,
) -> None:
    del message
    sender_identity = Identity.from_seed(_SENDER_SEED)
    receiver_identity = Identity.from_seed(_RECEIVER_SEED)
    sender_peer = PeerIdentity.from_pubkey(sender_identity.pubkey)
    rx_radio = _MemoryRadio()
    receiver = _link(receiver_identity, rx_radio, sender_peer)

    payload = _rpl_payload(sender_identity, code, oracle_body)
    unsigned = LichenFrame(
        epoch=0,
        seqnum=0,
        dst_addr=b"",
        payload=payload,
        mic=b"",
        signature_present=False,
    ).to_bytes()
    rx_radio.rx_queue.append((unsigned, -80, 4))

    dodag = DodagState(rpl_instance_id=0, dodag_id=_DODAG_ID, version=1)
    trickle = TrickleTimer(4_000, 8, 10, rng=lambda: 0.0)
    trickle.start(0)
    trickle.expire(4_000)
    trickle.heard_consistent()
    dao_manager = DaoManager(
        rpl_instance_id=0,
        dodag_id=_DODAG_ID,
        node_address=IPv6Address("200::2"),
        is_root=True,
    )

    result = await receiver.receive(timeout_ms=100)
    assert result is ReceiveError.UNSIGNED, f"{name}: unsigned RPL control admitted"

    with pytest.raises(TypeError, match="issued only by LinkLayer.receive"):
        RxFrame()

    assert dodag.role is DodagRole.UNJOINED
    assert dodag.rank == INFINITE_RANK
    assert dodag.preferred_parent is None
    assert trickle.interval == 8_000
    assert trickle.counter == 1
    with pytest.raises(DaoError, match="unauthenticated DAO receive is test-only"):
        dao_manager.process_dao(DAO.from_bytes(oracle_body) if name == "dao" else DAO(0, 1))


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "code", "oracle_body", "message"), CASES)
async def test_signed_rpl_control_round_trip_delivers_authenticated_payload(
    name: str,
    code: int,
    oracle_body: bytes,
    message: DIS | DIO | DAO,
) -> None:
    del message
    sender_identity = Identity.from_seed(_SENDER_SEED)
    receiver_identity = Identity.from_seed(_RECEIVER_SEED)
    sender_peer = PeerIdentity.from_pubkey(sender_identity.pubkey)
    tx_radio = _MemoryRadio()
    rx_radio = _MemoryRadio()
    sender = _link(sender_identity, tx_radio)
    receiver = _link(receiver_identity, rx_radio, sender_peer)

    payload = _rpl_payload(sender_identity, code, oracle_body)
    assert await sender.send(payload) is True
    rx_radio.rx_queue.append((tx_radio.tx_history[0], -70, 5))

    received = await receiver.receive(timeout_ms=100)
    assert isinstance(received, RxFrame), f"{name}: signed RPL control was not admitted"
    assert received.payload == payload
    assert _rpl_body_from_schc_payload(received.payload, code) == oracle_body
    assert received.frame.signature_present is True
    assert received.sender.pubkey == sender_identity.pubkey
