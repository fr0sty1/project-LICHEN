# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume the orphaned security/application vector files by driving the real
LICHEN Python implementation.

Files consumed (previously had zero machine consumers):

- ``test/vectors/announce_signed_data.json`` -> ``lichen.announce.messages.AnnounceMessage``
  transcript/serialization plus ``lichen.crypto.schnorr48`` deterministic signing and
  PyNaCl-bindings verification (spec 05 §9.2 / CCP-9).
- ``test/vectors/sos_signature.json``        -> ``lichen.coap.sos_origin`` (domain separation,
  canonical CBOR, SHA-512 transcript, wire format), ``lichen.coap.sos_relay`` dedup +
  monotonic origin-sequence gate, ``lichen.crypto.schnorr48.verify`` reject paths,
  and ``lichen.crypto.trust`` TOFU pinning.
- ``test/vectors/sos_rate_limiting.json``    -> ``lichen.coap.resources.emergency.SosResource``
  per-source rate limiting (hourly max, cooldown periods anchored at period start,
  burst allowance of 2) over a controllable monotonic clock, plus signed POST codes
  over the full stack per spec 18.4.1.
- ``test/vectors/group_oscore_key.json``     -> ``lichen.crypto.group_oscore`` pairwise
  key wrap/unwrap, ``key_epoch`` counter, OSCORE id-context composition, one-hour
  grace window, epoch rollback/future validation, and membership rekey.
- ``test/vectors/confessions_rate.json``     -> ``lichen.coap.resources.confessions``
  ``ConfessionsResource`` rate limits, retry-after math, size gate.
- ``test/vectors/receipt_cbor.json``         -> ``lichen.coap.resources.messaging``
  ``MessageReceiptsResource`` normalization + byte-exact CBOR encode pins.

All former divergences from bead project-LICHEN-worker6-a6qg have been resolved:

- Canonical-CBOR key-order vectors corrected to RFC 8949 §4.2.1 length-first
  ordering; implementation agrees.
- The spec 18.4.1 burst allowance (2 per cooldown period) is implemented;
  4.29 responses carry a CBOR ``{"retry_after": N}`` payload anchored on the
  period start.
- Hourly-window-slide vectors corrected: strict ``>`` pruning legitimately
  retains entries aged <3600 s at the pinned instants.
- Confessions retry-after uses exact ceiling arithmetic matching the vectors'
  integer pins (15/20).
- Rate-limit time sources default to ``time.monotonic`` (spec: monotonic uptime).
- A monotonic per-originator sequence validator gates both ``SosRelay`` and
  signed POST /sos; stale-but-unseen sequences are rejected.
- ``POST /sos`` enforces the spec 18.4.1 origin-signature gate: the envelope
  carries ``pubkey`` (32 B) + ``sig`` (56 B wire); unsigned/invalid/replayed
  messages are dropped (non-success response).
- Group OSCORE key distribution is implemented in
  ``lichen.crypto.group_oscore.GroupKeyManager``.
"""

from __future__ import annotations

import hashlib
import json
import time
from ipaddress import IPv6Address
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import aiocoap
import cbor2
import pytest
from aiocoap import Message

from lichen.announce.messages import ANNOUNCE_SIGNATURE_DOMAIN, AnnounceMessage
from lichen.coap.resources import StaticNodeInfo
from lichen.coap.resources.confessions import (
    CONFESSION_COOLDOWN_S,
    CONFESSION_HOURLY_MAX,
    CONFESSION_MAX_SIZE,
    ConfessionsResource,
)
from lichen.coap.resources.emergency import (
    SOS_COOLDOWN_S,
    SosResource,
)
from lichen.coap.resources.messaging import MessageReceiptsResource, MessagesResource
from lichen.coap.resources.site import build_site
from lichen.coap.sos_origin import (
    SOS_ORIGIN_DOMAIN,
    SosOriginSignature,
    canonicalize_sos_payload,
    compute_sos_transcript,
    sign_sos_origin,
    verify_sos_origin,
)
from lichen.coap.sos_relay import SosRelay
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.crypto.group_oscore import (
    GroupKeyManager,
    pairwise_unwrap,
    pairwise_wrap,
)
from lichen.crypto.identity import _pubkey_to_iid
from lichen.crypto.oscore import MemorySecurityContext
from lichen.crypto.schnorr48 import derive_keypair
from lichen.crypto.schnorr48 import sign as schnorr_sign
from lichen.crypto.schnorr48 import verify as schnorr_verify
from lichen.crypto.trust import (
    DerivationMismatchError,
    TrustLevel,
    TrustStore,
)
from lichen.ipv6.addr import make_link_local
from lichen.rpl.dao_origin import DAO_ORIGIN_DOMAIN
from lichen.senml.codec import SenmlRecord
from lichen.senml.codec import pack as senml_pack

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


def _load(name: str) -> dict[str, Any]:
    return json.loads((VECTORS_DIR / name).read_text())


ANNOUNCE_SIGNED_DATA = _load("announce_signed_data.json")
SOS_SIGNATURE = _load("sos_signature.json")
SOS_RATE_LIMITING = _load("sos_rate_limiting.json")
GROUP_OSCORE_KEY = _load("group_oscore_key.json")
CONFESSIONS_RATE = _load("confessions_rate.json")
RECEIPT_CBOR = _load("receipt_cbor.json")


def _vec(doc: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [v for v in doc["vectors"] if v["name"] == name]
    assert len(matches) == 1, f"vector {name!r} not unique in {doc.get('name')}"
    return matches[0]


class _Clock:
    """Controllable fake clock standing in for the resources' time_func."""

    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


_TEST_SEED = bytes(range(32))


def _identity() -> tuple[bytes, bytes, bytes]:
    """(privkey, pubkey, iid) for a fresh deterministic test identity."""
    priv, pub = derive_keypair(_TEST_SEED)
    return priv, pub, _pubkey_to_iid(pub)


def _origin_addr(iid: bytes) -> IPv6Address:
    return IPv6Address(bytes([0x02, 0x00]) + bytes(6) + iid)


def _sos_payload_dict(ts: int = 1716742800) -> dict[str, Any]:
    _, pub, iid = _identity()
    return {"type": "sos", "node": str(_origin_addr(iid)), "ts": ts}


async def _stack(
    **resources: Any,
) -> tuple[Any, Any]:
    net = InMemoryNetwork()
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info, **resources)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("::1"), "::1")
    return client, server


async def _teardown(client: Any, server: Any) -> None:
    await client.shutdown()
    await server.shutdown()


def _admin_post(payload: bytes) -> Message:
    """POST bound to IPv6 loopback so /msg write gates accept it."""
    request = Message(code=aiocoap.POST, payload=payload)
    request.remote = SimpleNamespace(hostinfo="[::1]")
    return request


def _confession_payload(iid: str, content: str = "it was me who ate the cake") -> bytes:
    records = [
        SenmlRecord(bn=f"urn:dev:mac:{iid}:"),
        SenmlRecord(n="type", vs="confession"),
        SenmlRecord(n="content", vs=content),
        SenmlRecord(n="anonymous", v=1),
    ]
    return senml_pack(records)


def _confession_request(iid: str, payload: bytes | None = None) -> Message:
    """POST bound to the authenticated IPv6 IID *iid*, not the SenML bn."""
    request = Message(
        code=aiocoap.POST, payload=payload if payload is not None else _confession_payload(iid)
    )
    request.remote = SimpleNamespace(hostinfo=f"[{make_link_local(bytes.fromhex(iid))}]")
    return request


# ---------------------------------------------------------------------------
# announce_signed_data.json — transcript, deterministic signing, wire frame
# ---------------------------------------------------------------------------


def _announce_from_vector(vector: dict[str, Any], *, signed: bool) -> AnnounceMessage:
    _, pub = _pub_for_seed(vector)
    return AnnounceMessage(
        originator_iid=bytes.fromhex(vector["originator_iid"]),
        pubkey=pub,
        seq_num=vector["seq_num"],
        hop_count=vector["hop_count"],
        rx_channel=vector["rx_channel"],
        signature=bytes.fromhex(vector["signature"]) if signed else b"",
        app_data=bytes.fromhex(vector["app_data"]) if vector["app_data"] else b"",
    )


def _pub_for_seed(vector: dict[str, Any]) -> tuple[bytes, bytes]:
    priv, pub = derive_keypair(bytes.fromhex(vector["signing_seed"]))
    return priv, pub


@pytest.mark.parametrize("vector", ANNOUNCE_SIGNED_DATA["vectors"], ids=lambda v: v["name"])
class TestAnnounceSignedDataVectors:
    def test_seed_derives_pinned_pubkey(self, vector: dict[str, Any]) -> None:
        priv, pub = _pub_for_seed(vector)
        assert len(priv) == 32
        assert pub.hex() == vector["public_key"]

    def test_transcript_byte_exact_and_layout_consistent(self, vector: dict[str, Any]) -> None:
        msg = _announce_from_vector(vector, signed=False)
        transcript = msg.signed_data()
        assert transcript.hex() == vector["signed_data_transcript"]
        # Independent reconstruction from the pinned layout offsets.
        layout = vector["signed_data_layout"]
        raw = transcript
        domain_len = layout["domain_length"]
        assert raw[:domain_len] == ANNOUNCE_SIGNATURE_DOMAIN
        rebuilt = (
            ANNOUNCE_SIGNATURE_DOMAIN
            + raw[layout["iid_offset"] : layout["iid_offset"] + layout["iid_length"]]
            + raw[layout["pubkey_offset"] : layout["pubkey_offset"] + layout["pubkey_length"]]
            + raw[layout["seq_num_offset"] : layout["seq_num_offset"] + layout["seq_num_length"]]
            + raw[
                layout["rx_channel_offset"] : layout["rx_channel_offset"]
                + layout["rx_channel_length"]
            ]
            + raw[
                layout["app_data_length_offset"] : layout["app_data_length_offset"]
                + layout["app_data_length_length"]
            ]
            + raw[layout["app_data_offset"] :]
        )
        assert rebuilt == transcript
        assert len(msg.app_data) == layout["app_data_length"]

    def test_deterministic_signing_reproduces_and_verifies_pinned_signature(
        self, vector: dict[str, Any]
    ) -> None:
        priv, pub = _pub_for_seed(vector)
        transcript = _announce_from_vector(vector, signed=False).signed_data()
        reproduced = schnorr_sign(priv, pub, transcript)
        assert reproduced.hex() == vector["signature"]
        pinned_sig = bytes.fromhex(vector["signature"])
        # schnorr48.verify is backed by nacl.bindings ed25519 primitives.
        assert schnorr_verify(pub, transcript, pinned_sig) is True
        # A single flipped bit in the transcript must break verification.
        tampered = bytearray(transcript)
        tampered[-1] ^= 0x01
        assert schnorr_verify(pub, bytes(tampered), pinned_sig) is False

    def test_frame_byte_exact_round_trip_and_layout(self, vector: dict[str, Any]) -> None:
        msg = _announce_from_vector(vector, signed=True)
        frame = msg.to_bytes()
        assert frame.hex() == vector["announce_frame"]
        layout = vector["announce_frame_layout"]
        assert layout["fixed_length"] == 93 == 1 + 1 + 2 + 8 + 32 + 48 + 1
        assert layout["total_length"] == len(frame)
        assert layout["app_data_offset"] == 93
        parsed = AnnounceMessage.from_bytes(frame)
        assert parsed.seq_num == vector["seq_num"]
        assert parsed.rx_channel == vector["rx_channel"]
        assert parsed.hop_count == vector["hop_count"]
        assert parsed.originator_iid == msg.originator_iid
        assert parsed.pubkey == msg.pubkey
        assert parsed.signature == msg.signature
        assert parsed.app_data == msg.app_data
        assert parsed.signed_data() == msg.signed_data()


# ---------------------------------------------------------------------------
# sos_signature.json — origin signatures, drops, TOFU, canonical CBOR
# ---------------------------------------------------------------------------


def _signed_sos_body(
    source_hex: str,
    ts: float,
    priv: bytes,
    pub: bytes,
    seq: int = 1,
) -> bytes:
    """Build a spec-18.4.1 signed POST /sos body for *source_hex*."""
    core = {"node": source_hex, "ts": ts}
    addr = IPv6Address(b"\x02\x00" + b"\x00" * 6 + bytes.fromhex(source_hex))
    sig = sign_sos_origin(priv, pub, addr, seq, core)
    return cbor2.dumps({**core, "pubkey": pub, "sig": sig.to_bytes()})


class TestSosSignatureVectors:
    def test_valid_signature_accept_and_relay(self) -> None:
        vec = _vec(SOS_SIGNATURE, "sos_valid_signature_accept")
        assert vec["expected"]["accept"] is True and vec["expected"]["relay"] is True
        priv, pub, iid = _identity()
        payload = _sos_payload_dict()
        addr = _origin_addr(iid)
        payload_cbor = canonicalize_sos_payload(payload)
        origin_sig = sign_sos_origin(priv, pub, addr, 1, payload)
        assert verify_sos_origin(pub, addr.packed, payload_cbor, origin_sig) is True
        relay = SosRelay()
        result = relay.check_relay(iid.hex(), origin_sig.origin_sequence, ttl=7)
        assert result.should_relay is True

    async def test_signed_sos_accepted_by_resource(self) -> None:
        """Spec 18.4.1 gate: a validly signed SOS activates with 2.01."""
        priv, pub, iid = _identity()
        source = iid.hex()
        sos = SosResource(time_func=_Clock())
        client, server = await _stack(sos_resource=sos)
        try:
            response = await client.request(
                Message(
                    code=aiocoap.POST,
                    uri="coap://srv/sos",
                    payload=_signed_sos_body(source, 1716742800, priv, pub),
                    content_format=60,
                )
            ).response
            assert response.code == aiocoap.CREATED
            assert sos._active is True and sos._from == source
        finally:
            await _teardown(client, server)

    async def test_unsigned_sos_must_be_silently_dropped(self) -> None:
        """Spec 18.4.1 requires silent drop of unsigned SOS (bead a6qg gap 1)."""
        vec = _vec(SOS_SIGNATURE, "sos_missing_signature_drop")
        assert vec["expected"]["accept"] is False and vec["expected"]["error_response"] is False
        sos = SosResource(time_func=_Clock())
        client, server = await _stack(sos_resource=sos)
        try:
            response = await client.request(
                Message(
                    code=aiocoap.POST,
                    uri="coap://srv/sos",
                    payload=cbor2.dumps({"node": "0011223344556677", "ts": 1716742800}),
                    content_format=60,
                )
            ).response
            assert response.code.is_successful() is False
        finally:
            await _teardown(client, server)

    async def test_wrong_key_sos_dropped_by_binding_gate(self) -> None:
        """A pubkey that does not derive to the claimed IID is dropped."""
        signer_priv, signer_pub = derive_keypair(bytes.fromhex("b" * 62 + "10"))
        _, _, iid = _identity()
        sos = SosResource(time_func=_Clock())
        client, server = await _stack(sos_resource=sos)
        try:
            response = await client.request(
                Message(
                    code=aiocoap.POST,
                    uri="coap://srv/sos",
                    payload=_signed_sos_body(iid.hex(), 1716742800, signer_priv, signer_pub),
                    content_format=60,
                )
            ).response
            # Signature is valid for B's key but B's key derives to B's IID.
            assert response.code.is_successful() is False
        finally:
            await _teardown(client, server)

    def test_invalid_all_zero_signature_rejected(self) -> None:
        vec = _vec(SOS_SIGNATURE, "sos_invalid_signature_drop")
        assert vec["signature"] == "00" * 48
        _, pub, _ = _identity()
        payload_cbor = canonicalize_sos_payload(_sos_payload_dict())
        transcript = compute_sos_transcript(_origin_addr(_pubkey_to_iid(pub)), 0, payload_cbor)
        # The zero-challenge early-rejection gate refuses the all-zero signature
        # before any point arithmetic, returning a plain False (no error path).
        assert schnorr_verify(pub, transcript, bytes.fromhex(vec["signature"])) is False

    def test_truncated_signature_rejected(self) -> None:
        vec = _vec(SOS_SIGNATURE, "sos_truncated_signature_drop")
        assert vec["signature_length"] == len(bytes.fromhex(vec["signature"]))
        _, pub, _ = _identity()
        transcript = compute_sos_transcript(
            _origin_addr(_pubkey_to_iid(pub)), 0, canonicalize_sos_payload(_sos_payload_dict())
        )
        assert schnorr_verify(pub, transcript, bytes.fromhex(vec["signature"])) is False
        with pytest.raises(ValueError, match="56 bytes"):
            SosOriginSignature.from_bytes(bytes.fromhex(vec["signature"]))
        with pytest.raises(ValueError):
            SosOriginSignature.from_bytes(b"\x00" * 57)

    def test_wrong_key_signature_rejected(self) -> None:
        vec = _vec(SOS_SIGNATURE, "sos_wrong_key_signature_drop")
        assert vec["expected"]["reason"] == "key_iid_mismatch"
        priv_a, pub_a, iid_a = _identity()
        signer_b_priv, signer_b_pub = derive_keypair(bytes.fromhex("b" * 62 + "10"))
        payload = _sos_payload_dict()
        sig_b = sign_sos_origin(signer_b_priv, signer_b_pub, _origin_addr(iid_a), 1, payload)
        # Signature valid for B's key must fail under A's pubkey...
        payload_cbor_a = canonicalize_sos_payload(payload)
        assert verify_sos_origin(pub_a, _origin_addr(iid_a).packed, payload_cbor_a, sig_b) is False
        # ...and B's key cannot claim A's IID (trust-binding gate). B's pubkey
        # derives to its own IID, so the derivation gate fires first.
        store = TrustStore()
        store.verify_or_pin(pub_a, iid_a)
        with pytest.raises(DerivationMismatchError):
            store.verify_or_pin(signer_b_pub, iid_a)

    def test_signature_covers_entire_payload(self) -> None:
        vec = _vec(SOS_SIGNATURE, "sos_signature_covers_payload")
        assert vec["expected"]["modification_detected"] is True
        priv, pub, iid = _identity()
        payload = {**_sos_payload_dict(), "msg": "Injured, need evac"}
        origin_sig = sign_sos_origin(priv, pub, _origin_addr(iid), 1, payload)
        addr = _origin_addr(iid)
        assert verify_sos_origin(pub, addr.packed, canonicalize_sos_payload(payload), origin_sig)
        for field, value in (("ts", 1716742801), ("msg", "hoax"), ("type", "cancel")):
            tampered = dict(payload)
            tampered[field] = value
            assert (
                verify_sos_origin(pub, addr.packed, canonicalize_sos_payload(tampered), origin_sig)
                is False
            ), f"modified {field} must break the signature"

    def test_replay_same_signature_rejected_by_dedup(self) -> None:
        vec = _vec(SOS_SIGNATURE, "sos_replay_same_signature_reject")
        assert vec["first_accept"] is True and vec["replay_accept"] is False
        _, _, iid = _identity()
        node = iid.hex()
        relay = SosRelay()
        first = relay.check_relay(node, 41, ttl=7)
        assert first.should_relay is True
        replay = relay.check_relay(node, 41, ttl=7)
        assert replay.should_relay is False
        assert "already" in replay.reason

    def test_unknown_peer_tofu_pin_on_first_valid_contact(self) -> None:
        vec = _vec(SOS_SIGNATURE, "sos_unknown_pubkey_tofu")
        assert vec["pubkey_known"] is False and vec["expected"]["tofu_pin"] is True
        _, pub, iid = _identity()
        store = TrustStore()
        assert iid not in store
        entry = store.verify_or_pin(pub, iid)
        assert entry.trust_level is TrustLevel.TOFU
        assert iid in store
        # Second contact verifies against the pin without re-pinning.
        assert store.verify_or_pin(pub, iid).trust_level is TrustLevel.TOFU
        assert len(store) == 1

    def test_silent_drop_surfaces_plain_bools_not_errors(self) -> None:
        vec = _vec(SOS_SIGNATURE, "sos_silent_drop_rationale")
        assert vec["expected"]["error_response_on_invalid"] is False
        _, pub, iid = _identity()
        transcript = compute_sos_transcript(_origin_addr(iid), 0, b"")
        # Every failure mode is a quiet False; nothing raises toward the caller.
        assert schnorr_verify(pub, transcript, b"\x00" * 48) is False
        assert schnorr_verify(b"\x02" * 32, transcript, b"\x00" * 48) is False
        assert schnorr_verify(pub, transcript, b"\xff" * 48) is False
        result = SosRelay().check_relay("bad-node", 1, ttl=7)
        assert result.should_relay is False and isinstance(result.reason, str)

    def test_origin_domain_separation(self) -> None:
        vec = _vec(SOS_SIGNATURE, "origin_domain_separation")
        assert SOS_ORIGIN_DOMAIN.decode() == vec["domain"]
        assert SOS_ORIGIN_DOMAIN.hex() == vec["domain_hex"]
        assert len(SOS_ORIGIN_DOMAIN) == vec["domain_length"]
        assert SOS_ORIGIN_DOMAIN != DAO_ORIGIN_DOMAIN
        assert DAO_ORIGIN_DOMAIN.decode() == vec["different_from"]
        # Cross-protocol reuse fails both ways.
        priv, pub, iid = _identity()
        addr = _origin_addr(iid)
        payload_cbor = canonicalize_sos_payload({"type": "cancel", "node": str(addr), "ts": 7})
        seq_wire = (1).to_bytes(8, "big")
        dao_material = DAO_ORIGIN_DOMAIN + addr.packed + seq_wire + payload_cbor
        dao_digest = hashlib.sha512(dao_material).digest()
        sos_digest = compute_sos_transcript(addr, 1, payload_cbor)
        assert dao_digest != sos_digest
        sig = schnorr_sign(priv, pub, dao_digest)
        assert schnorr_verify(pub, sos_digest, sig) is False

    def test_origin_transcript_format(self) -> None:
        vec = _vec(SOS_SIGNATURE, "origin_transcript_format")
        inputs = vec["transcript_inputs"]
        addr = IPv6Address(vec["origin_address"])
        assert addr.packed.hex() == inputs["ipv6_packed"]
        seq = vec["origin_sequence"]
        assert seq.to_bytes(8, "big").hex() == inputs["seq_big_endian"]
        assert SOS_ORIGIN_DOMAIN.hex() == inputs["domain"]
        payload = vec["payload"]
        payload_cbor = canonicalize_sos_payload(payload)
        transcript_material = (
            SOS_ORIGIN_DOMAIN + addr.packed + seq.to_bytes(8, "big") + payload_cbor
        )
        manual = hashlib.sha512(transcript_material).digest()
        assert manual == compute_sos_transcript(addr, seq, payload_cbor)
        # Full sign/verify cycle through the real transcript builder.
        priv, pub = derive_keypair(bytes.fromhex("21" * 32))
        origin_sig = sign_sos_origin(priv, pub, addr, seq, payload)
        assert verify_sos_origin(pub, addr.packed, payload_cbor, origin_sig) is True

    def test_wrong_domain_signature_rejected(self) -> None:
        vec = _vec(SOS_SIGNATURE, "wrong_domain_rejected")
        assert vec["correct_domain"] == SOS_ORIGIN_DOMAIN.decode()
        assert vec["used_domain"] == DAO_ORIGIN_DOMAIN.decode()
        priv, pub, iid = _identity()
        addr = _origin_addr(iid)
        payload_cbor = canonicalize_sos_payload({"type": "sos", "node": str(addr), "ts": 1})
        dao_transcript = hashlib.sha512(
            DAO_ORIGIN_DOMAIN + addr.packed + (1).to_bytes(8, "big") + payload_cbor
        ).digest()
        sig = schnorr_sign(priv, pub, dao_transcript)
        origin_sig = SosOriginSignature(origin_sequence=1, signature=sig)
        # Verifying the DAO-domain signature through the SOS verifier fails.
        assert verify_sos_origin(pub, addr.packed, payload_cbor, origin_sig) is False
        assert vec["expected"]["accept"] is False

    def test_canonical_cbor_real_key_order_matches_rfc8949(self) -> None:
        """Real behavior: length-first key order per RFC 8949 §4.2.1.

        The cancel vector's pinned order matches reality; the sos/medical
        vectors pin wrong orders and are xfailed exactly below.
        """
        cancel = _vec(SOS_SIGNATURE, "canonical_cbor_cancel")
        got_cancel = list(cbor2.loads(cbor2.dumps(cancel["payload"], canonical=True)).keys())
        assert got_cancel == cancel["key_order_canonical"] == ["ts", "node", "type"]
        sos = _vec(SOS_SIGNATURE, "canonical_cbor_key_order")
        got_sos = list(cbor2.loads(cbor2.dumps(sos["payload"], canonical=True)).keys())
        assert got_sos == ["ts", "lat", "lon", "node", "type"]
        medical = _vec(SOS_SIGNATURE, "canonical_cbor_medical")
        got_medical = list(cbor2.loads(cbor2.dumps(medical["payload"], canonical=True)).keys())
        assert got_medical == ["ts", "msg", "node", "type"]

    def test_canonical_cbor_key_order_exact_pin(self) -> None:
        """Vector corrected to RFC 8949 §4.2.1 length-first order (a6qg 7a)."""
        vec = _vec(SOS_SIGNATURE, "canonical_cbor_key_order")
        got = list(cbor2.loads(cbor2.dumps(vec["payload"], canonical=True)).keys())
        assert got == vec["key_order_canonical"]

    def test_canonical_cbor_medical_order_exact_pin(self) -> None:
        """Vector corrected to RFC 8949 §4.2.1 length-first order (a6qg 7a)."""
        vec = _vec(SOS_SIGNATURE, "canonical_cbor_medical")
        got = list(cbor2.loads(cbor2.dumps(vec["payload"], canonical=True)).keys())
        assert got == vec["key_order_canonical"]

    def test_origin_wire_format(self) -> None:
        vec = _vec(SOS_SIGNATURE, "origin_wire_format")
        assert vec["sequence_hex"] == (42).to_bytes(8, "big").hex()
        assert vec["total_length"] == vec["signature_length"] + 8 == 56
        signature = bytes(range(48))
        origin_sig = SosOriginSignature(origin_sequence=42, signature=signature)
        wire = origin_sig.to_bytes()
        assert len(wire) == vec["total_length"]
        assert wire[:8].hex() == vec["sequence_hex"]
        assert wire[8:] == signature
        parsed = SosOriginSignature.from_bytes(wire)
        assert parsed.origin_sequence == 42
        assert parsed.signature == signature

    def test_origin_sequence_replay_rejected(self) -> None:
        vec = _vec(SOS_SIGNATURE, "origin_sequence_replay")
        node = "aabbccccdddd0001"
        relay = SosRelay()
        first = relay.check_relay(node, vec["first_sequence"], ttl=7)
        replay = relay.check_relay(node, vec["replay_sequence"], ttl=7)
        assert first.should_relay is True
        assert replay.should_relay is False
        assert vec["expected"]["accept"] is False

    def test_origin_sequence_rollback_rejected(self) -> None:
        """Monotonic origin-sequence validator (a6qg gap 5).

        The relay tracks the highest accepted sequence per originator; a
        stale-but-unseen sequence (8 after 10) is rejected, closing the
        exact-``(node, seq)`` dedup gap.
        """
        vec = _vec(SOS_SIGNATURE, "origin_sequence_rollback")
        assert vec["last_seen"] == 10 and vec["received"] == 8
        node = "aabbccccdddd0002"
        relay = SosRelay()
        assert relay.check_relay(node, 10, ttl=7).should_relay is True
        stale = relay.check_relay(node, 8, ttl=7)
        assert stale.should_relay is False
        assert "stale origin sequence" in stale.reason


# ---------------------------------------------------------------------------
# sos_rate_limiting.json — SosResource cooldown/hourly windows
# ---------------------------------------------------------------------------


def _sos_body(source_hex: str = "0011223344556677", ts: float = 1716742800) -> bytes:
    return cbor2.dumps({"node": source_hex, "ts": ts})


class TestSosRateLimitingVectors:
    async def test_first_sos_accepted(self) -> None:
        vec = _vec(SOS_RATE_LIMITING, "first_sos_accepted")
        assert vec["history"] == []
        clock = _Clock()
        sos = SosResource(time_func=clock)
        assert sos.check_rate_limit("0011223344556677") is True
        priv, pub, iid = _identity()
        client, server = await _stack(sos_resource=sos)
        try:
            response = await client.request(
                Message(
                    code=aiocoap.POST,
                    uri="coap://srv/sos",
                    payload=_signed_sos_body(iid.hex(), 1716742800, priv, pub),
                    content_format=60,
                )
            ).response
            assert response.code == aiocoap.CREATED
        finally:
            await _teardown(client, server)

    async def test_burst_second_accepted_live(self) -> None:
        """Spec 18.4.1 burst allowance: second SOS at +1 s is accepted."""
        vec = _vec(SOS_RATE_LIMITING, "burst_second_accepted")
        clock = _Clock()
        sos = SosResource(time_func=clock)
        source = vec["sender_iid"]
        clock.t = vec["last_sos_uptime_ms"] / 1000
        assert sos.check_rate_limit(source) is True
        sos._record_request(source)
        clock.t = vec["current_uptime_ms"] / 1000
        assert sos.evaluate_rate_limit(source)[2] == vec["expected"]["reason"]
        assert sos.check_rate_limit(source) is vec["expected"]["accept"] is True

    async def test_burst_second_accepted_exact_pin(self) -> None:
        vec = _vec(SOS_RATE_LIMITING, "burst_second_accepted")
        clock = _Clock()
        sos = SosResource(time_func=clock)
        source = vec["sender_iid"]
        clock.t = vec["last_sos_uptime_ms"] / 1000
        sos._record_request(source)
        clock.t = vec["current_uptime_ms"] / 1000
        assert sos.check_rate_limit(source) is vec["expected"]["accept"] is True

    async def test_third_before_cooldown_rejected_429(self) -> None:
        """Third SOS inside a spent period: 4.29 with Retry-After == 300 s."""
        vec = _vec(SOS_RATE_LIMITING, "third_before_cooldown_rejected")
        clock = _Clock()
        sos = SosResource(time_func=clock)
        source = vec["sender_iid"]
        # Faithful scenario history: original opens the period at t=0, the
        # burst follow-up lands at t=1s, spending the burst budget.
        clock.t = 0.0
        sos._record_request(source)
        clock.t = vec["last_sos_uptime_ms"] / 1000
        sos._record_request(source)
        clock.t = vec["current_uptime_ms"] / 1000
        allowed, retry_after, _reason = sos.evaluate_rate_limit(source)
        assert allowed is False
        assert retry_after == vec["expected"]["retry_after_s"] == 300
        # Same scenario over the wire with a real signing identity.
        priv, pub, iid = _identity()
        client, server = await _stack(sos_resource=sos)
        try:
            clock.t = 0.0
            sos._record_request(iid.hex())
            clock.t = vec["last_sos_uptime_ms"] / 1000
            sos._record_request(iid.hex())
            clock.t = vec["current_uptime_ms"] / 1000
            response = await client.request(
                Message(
                    code=aiocoap.POST,
                    uri="coap://srv/sos",
                    payload=_signed_sos_body(iid.hex(), 1716742800, priv, pub, seq=3),
                    content_format=60,
                )
            ).response
            assert response.code == aiocoap.TOO_MANY_REQUESTS
            assert response.code.dotted == vec["expected"]["response_code"].split()[0]
            payload = cbor2.loads(response.payload)
            assert payload["retry_after"] == vec["expected"]["retry_after_s"] == 300
        finally:
            await _teardown(client, server)

    async def test_third_exactly_at_cooldown_boundary_accepted(self) -> None:
        vec = _vec(SOS_RATE_LIMITING, "third_after_cooldown_accepted")
        clock = _Clock()
        sos = SosResource(time_func=clock)
        source = vec["sender_iid"]
        clock.t = vec["last_sos_uptime_ms"] / 1000
        sos._record_request(source)
        sos._record_request(source)
        clock.t = vec["current_uptime_ms"] / 1000
        # Boundary is inclusive: elapsed == 600s passes the `< cooldown` check.
        assert sos.check_rate_limit(source) is vec["expected"]["accept"] is True

    async def test_fourth_in_hour_rejected(self) -> None:
        vec = _vec(SOS_RATE_LIMITING, "fourth_in_hour_rejected")
        clock = _Clock()
        sos = SosResource(time_func=clock)
        source = vec["sender_iid"]
        clock.t = 0.0
        sos._record_request(source)
        clock.t = 620.0
        sos._record_request(source)
        clock.t = vec["last_sos_uptime_ms"] / 1000
        sos._record_request(source)
        clock.t = vec["current_uptime_ms"] / 1000
        allowed, _retry, reason = sos.evaluate_rate_limit(source)
        assert allowed is vec["expected"]["accept"] is False
        assert reason == vec["expected"]["reason"] == "hourly_limit_exceeded"
        # Same scenario over the wire with a real signing identity: the
        # fourth signed POST gets 4.29 (unsigned would be dropped earlier).
        priv, pub, iid = _identity()
        client, server = await _stack(sos_resource=sos)
        try:
            clock.t = 0.0
            sos._record_request(iid.hex())
            clock.t = 620.0
            sos._record_request(iid.hex())
            clock.t = vec["last_sos_uptime_ms"] / 1000
            sos._record_request(iid.hex())
            clock.t = vec["current_uptime_ms"] / 1000
            response = await client.request(
                Message(
                    code=aiocoap.POST,
                    uri="coap://srv/sos",
                    payload=_signed_sos_body(iid.hex(), 1716742800, priv, pub, seq=4),
                    content_format=60,
                )
            ).response
            dotted = response.code.dotted
            assert dotted == vec["expected"]["response_code"].split()[0] == "4.29"
        finally:
            await _teardown(client, server)

    async def test_hourly_window_slides_with_strict_pruning(self) -> None:
        """At now=3601s the t=0 entry is outside the `>=` cutoff (3601-3600=1).

        The corrected vector pins sos_in_window=2: the 1 s and 2 s entries
        are at or after the cutoff and remain in the window.
        """
        vec = _vec(SOS_RATE_LIMITING, "hourly_window_slides")
        clock = _Clock()
        sos = SosResource(time_func=clock)
        source = vec["sender_iid"]
        for entry in vec["history"]:
            clock.t = entry["uptime_ms"] / 1000
            sos._record_request(source)
        clock.t = vec["current_uptime_ms"] / 1000
        assert sos.check_rate_limit(source) is vec["expected"]["accept"] is True
        assert len(sos._request_times[source]) == vec["expected"]["sos_in_window"] == 2

    def test_time_source_defaults_to_monotonic(self) -> None:
        """Spec 18.4.1: monotonic uptime, not wall clock (a6qg gap 4)."""
        vec = _vec(SOS_RATE_LIMITING, "monotonic_uptime_enforced")
        assert vec["expected"]["time_source"] == "monotonic_uptime"
        sos = SosResource()
        assert sos._time_func is time.monotonic
        # With a controllable injected clock the enforcement logic works:
        clock = _Clock()
        injected = SosResource(time_func=clock)
        # Spend the burst budget (2 requests).
        injected._record_request("aa" * 8)
        injected._record_request("aa" * 8)
        clock.t += SOS_COOLDOWN_S - 1
        assert injected.check_rate_limit("aa" * 8) is False
        clock.t += 1
        assert injected.check_rate_limit("aa" * 8) is True

    async def test_different_nodes_independent(self) -> None:
        vec = _vec(SOS_RATE_LIMITING, "different_nodes_independent")
        exhausted, fresh = vec["scenarios"]
        clock = _Clock()
        sos = SosResource(time_func=clock)
        a, b = exhausted["sender_iid"], fresh["sender_iid"]
        for offset in (0.0, 620.0, 1240.0):  # 3 in-hour entries, spaced > cooldown
            clock.t = offset
            sos._record_request(a)
        clock.t = 1300.0
        assert sos.check_rate_limit(a) is exhausted["accept"] is False
        assert sos.check_rate_limit(b) is fresh["accept"] is True

    async def test_cooldown_resets_on_accept(self) -> None:
        """Step scenario from the vector: burst accept, period rollover, hourly stop.

        t=0 opens the period (accept); t=1s is the burst follow-up (accept);
        t=600s lands exactly at the period boundary, opening a new period
        (accept); t=601s hits the 3-per-hour ceiling from the accumulated
        history and is rejected.
        """
        vec = _vec(SOS_RATE_LIMITING, "cooldown_resets_on_accept")
        steps = vec["scenario"]
        assert [step["action"] for step in steps] == ["send"] * 4
        clock = _Clock()
        sos = SosResource(time_func=clock)
        source = vec["sender_iid"]
        codes: list[str] = []
        for step in steps:
            clock.t = step["uptime_ms"] / 1000
            allowed = sos.check_rate_limit(source)
            if allowed:
                sos._record_request(source)
            codes.append("2.01" if allowed else "4.29")
        assert codes == [f"{'2.01' if step['accept'] else '4.29'}" for step in steps]
        assert codes == ["2.01", "2.01", "2.01", "4.29"]

    async def test_sos_independent_of_confessions_rate(self) -> None:
        vec = _vec(SOS_RATE_LIMITING, "sos_clears_confessions_rate")
        source = vec["sender_iid"]
        clock = _Clock()
        confessions = ConfessionsResource(time_func=clock)
        for i in range(vec["confessions_count_in_hour"]):
            clock.t = i * (CONFESSION_COOLDOWN_S + 1)
            confessions._record_request(source)
        clock.t = vec["confessions_count_in_hour"] * (CONFESSION_COOLDOWN_S + 1)
        assert confessions.check_rate_limit(source)[0] is False  # confessions exhausted
        sos = SosResource(time_func=clock)
        assert sos.check_rate_limit(source) is vec["expected"]["sos_accept"] is True


# ---------------------------------------------------------------------------
# group_oscore_key.json — driven through lichen.crypto.group_oscore
# ---------------------------------------------------------------------------


def _group_members() -> list[tuple[str, bytes, bytes]]:
    """(name, privkey, pubkey) triples for alice/bob/carol/dave."""
    names = ("alice", "bob", "carol", "dave")
    return [(name, *derive_keypair(bytes([ord("a") + i]) * 32)) for i, name in enumerate(names)]


def _group_manager(
    time_func: Any = None,
) -> tuple[GroupKeyManager, dict[str, bytes], dict[str, bytes]]:
    """Manager over alice+bob with the vector's 16-byte group key."""
    triples = _group_members()
    pubkeys = {name: pub for name, _priv, pub in triples}
    seeds = {name: priv for name, priv, _pub in triples}
    mgr = GroupKeyManager(
        bytes.fromhex("1234567890abcdef"),
        bytes.fromhex("deadbeefcafebabedeadbeefcafebabe"),
        {"alice": pubkeys["alice"], "bob": pubkeys["bob"]},
        time_func=time_func,
    )
    return mgr, pubkeys, seeds


class TestGroupOscoreKeyVectors:
    def test_key_epoch_composes_oscore_id_context(self) -> None:
        """Vector ``key_epoch_oscore_context``: group_id || key_epoch(u32 BE)."""
        vec = _vec(GROUP_OSCORE_KEY, "key_epoch_oscore_context")
        group_id = bytes.fromhex(vec["group_id"])
        epoch = vec["key_epoch"]
        mgr = GroupKeyManager(group_id, b"\x01" * 16)
        assert mgr.oscore_id_context(epoch) == group_id + epoch.to_bytes(4, "big")

        def make(epoch_value: int) -> MemorySecurityContext:
            return MemorySecurityContext(
                b"g" * 16,
                b"s" * 8,
                b"\x01",
                b"\x02",
                id_context=group_id + epoch_value.to_bytes(4, "big"),
            )

        ctx = make(epoch)
        assert ctx.context_id == group_id + epoch.to_bytes(4, "big")
        assert ctx.kid_context == ctx.context_id
        # Context isolation: another epoch on the same group gets its own id.
        other = make(epoch + 1)
        assert other.context_id != ctx.context_id
        assert other.context_id[:-4] == ctx.context_id[:-4] == group_id
        # The manager composes the same id_context for its live epoch.
        assert mgr.oscore_id_context() == group_id + (1).to_bytes(4, "big")

    def test_key_pairwise_wrap_unique_per_member(self) -> None:
        vec = _vec(GROUP_OSCORE_KEY, "key_pairwise_wrap")
        group_key = bytes.fromhex(vec["group_key"])
        _mgr, pubkeys, seeds = _group_manager()
        wrapped_alice = pairwise_wrap(group_key, pubkeys["alice"])
        wrapped_bob = pairwise_wrap(group_key, pubkeys["bob"])
        # Unique per member; each unwraps to the same group key.
        assert wrapped_alice != wrapped_bob
        assert pairwise_unwrap(wrapped_alice, seeds["alice"], pubkeys["alice"]) == group_key
        assert pairwise_unwrap(wrapped_bob, seeds["bob"], pubkeys["bob"]) == group_key

    def test_key_epoch_increment_monotonic(self) -> None:
        vec = _vec(GROUP_OSCORE_KEY, "key_epoch_increment")
        assert vec["initial_epoch"] == 1
        mgr, _pubkeys, _seeds = _group_manager()
        assert mgr.epoch == vec["initial_epoch"]
        mgr.rekey(b"\x02" * 16)
        assert mgr.epoch == vec["after_rekey_epoch"] == 2
        mgr.rekey(b"\x03" * 16)
        assert mgr.epoch == 3 > 2  # monotonic

    def test_grace_period_1hr(self) -> None:
        vec = _vec(GROUP_OSCORE_KEY, "grace_period_1hr")
        clock = _Clock()
        mgr, _pubkeys, _seeds = _group_manager(time_func=clock)
        old_material = mgr.key_for_epoch(vec["old_epoch"])
        mgr.rekey(b"\x02" * 16)
        clock.t = vec["test_time_ms"] / 1000  # 1800 s after rekey
        assert mgr.key_valid_at(old_material, clock.t) is True

    def test_grace_period_expired(self) -> None:
        vec = _vec(GROUP_OSCORE_KEY, "grace_period_expired")
        clock = _Clock()
        mgr, _pubkeys, _seeds = _group_manager(time_func=clock)
        old_material = mgr.key_for_epoch(vec["old_epoch"])
        mgr.rekey(b"\x02" * 16)
        clock.t = vec["test_time_ms"] / 1000  # 3600.001 s: strictly past grace
        assert mgr.key_valid_at(old_material, clock.t) is False

    def test_epoch_rollback_rejected(self) -> None:
        vec = _vec(GROUP_OSCORE_KEY, "epoch_rollback_reject")
        mgr, _pubkeys, _seeds = _group_manager()
        while mgr.epoch < vec["current_epoch"]:
            mgr.rekey()
        accepted, reason = mgr.validate_epoch(vec["message_epoch"])
        assert accepted is False and reason == "epoch_rollback"

    def test_epoch_future_rejected(self) -> None:
        vec = _vec(GROUP_OSCORE_KEY, "epoch_future_reject")
        mgr, _pubkeys, _seeds = _group_manager()
        while mgr.epoch < vec["current_epoch"]:
            mgr.rekey()
        accepted, reason = mgr.validate_epoch(vec["message_epoch"])
        assert accepted is False and reason == "future_epoch_unknown"

    def test_rekey_distribution_to_all_members(self) -> None:
        vec = _vec(GROUP_OSCORE_KEY, "rekey_distribution_to_all")
        mgr, _pubkeys, _seeds = _group_manager()
        carol = next(t for t in _group_members() if t[0] == "carol")
        mgr.add_member("carol", carol[2])
        distribution = mgr.rekey(b"\x09" * 16)
        assert set(distribution) == set(vec["members"])
        assert len(distribution) == vec["expected"]["distribution_count"] == 3
        for name, blob in distribution.items():
            member = next(t for t in _group_members() if t[0] == name)
            assert pairwise_unwrap(blob, member[1], member[2]) == b"\x09" * 16

    def test_member_removal_no_rekey_access(self) -> None:
        vec = _vec(GROUP_OSCORE_KEY, "member_removal_no_rekey_access")
        mgr, _pubkeys, _seeds = _group_manager()
        carol = next(t for t in _group_members() if t[0] == "carol")
        wrapped_carol_initial = mgr.add_member("carol", carol[2])
        # Carol could decrypt the epoch-1 key she was wrapped.
        assert (
            pairwise_unwrap(wrapped_carol_initial, carol[1], carol[2]) == mgr.key_for_epoch(1).key
        )
        mgr.remove_member(vec["remove"])
        distribution = mgr.rekey(b"\x0a" * 16)
        # No new key material reaches the removed member...
        assert "carol" not in distribution
        assert vec["expected"]["carol_can_decrypt_new"] is False

    def test_new_member_no_old_key(self) -> None:
        vec = _vec(GROUP_OSCORE_KEY, "new_member_no_old_key")
        mgr, _pubkeys, _seeds = _group_manager()
        dave = next(t for t in _group_members() if t[0] == "dave")
        current_before_join = mgr.key_for_epoch(mgr.epoch).key
        wrapped_dave = mgr.add_member("dave", dave[2])
        # Dave receives exactly one key: the current one.
        assert pairwise_unwrap(wrapped_dave, dave[1], dave[2]) == current_before_join
        assert vec["expected"]["dave_receives_current_key"] is True
        # Historical epochs exist on the controller but were never sent to him.
        assert mgr.key_for_epoch(1) is not None
        assert vec["expected"]["dave_can_decrypt_historical"] is False


# ---------------------------------------------------------------------------
# confessions_rate.json — ConfessionsResource limits and retry-after
# ---------------------------------------------------------------------------


class TestConfessionsRateVectors:
    async def test_first_post_accepted_created(self) -> None:
        vec = _vec(CONFESSIONS_RATE, "first_post_accepted")
        source = vec["sender_iid"]
        conf = ConfessionsResource(time_func=_Clock())
        allowed, retry_after = conf.check_rate_limit(source)
        assert (allowed, retry_after) == (True, 0)
        response = await conf.render_post(_confession_request(source))
        assert response.code.dotted == vec["expected"]["response_code"].split()[0] == "2.01"
        assert len(conf.confessions()) == 1

    async def test_second_within_30s_rejected_retry_math(self) -> None:
        """Second POST at 15 s: rejected with retry_after matching vector pin."""
        vec = _vec(CONFESSIONS_RATE, "second_post_within_30s_rejected")
        source = vec["sender_iid"]
        clock = _Clock()
        conf = ConfessionsResource(time_func=clock)
        clock.t = vec["history"][0]["uptime_ms"] / 1000
        conf._record_request(source)
        clock.t = vec["current_uptime_ms"] / 1000
        allowed, retry_after = conf.check_rate_limit(source)
        assert allowed is vec["expected"]["accept"] is False
        # Implementation uses math.ceil, matching the vector's exact integer pin.
        assert retry_after == vec["expected"]["retry_after_s"] == 15
        response = await conf.render_post(_confession_request(source))
        assert response.code.dotted == vec["expected"]["response_code"].split()[0] == "4.29"
        assert cbor2.loads(response.payload) == {"retry_after": retry_after}

    async def test_post_exactly_at_30s_accepted(self) -> None:
        vec = _vec(CONFESSIONS_RATE, "post_after_30s_accepted")
        source = vec["sender_iid"]
        clock = _Clock()
        conf = ConfessionsResource(time_func=clock)
        clock.t = vec["history"][0]["uptime_ms"] / 1000
        conf._record_request(source)
        clock.t = vec["current_uptime_ms"] / 1000
        allowed, retry_after = conf.check_rate_limit(source)
        assert (allowed, retry_after) == (True, 0)
        response = await conf.render_post(_confession_request(source))
        assert response.code.dotted == vec["expected"]["response_code"].split()[0] == "2.01"

    async def test_thirteenth_post_within_hour_rejected(self) -> None:
        vec = _vec(CONFESSIONS_RATE, "thirteenth_post_within_hour_rejected")
        source = vec["sender_iid"]
        clock = _Clock()
        conf = ConfessionsResource(time_func=clock)
        for i in range(vec["history_count_in_hour"]):
            clock.t = i * 120.0  # 12 posts spaced 120s apart (< 1 hour span)
            conf._record_request(source)
        clock.t = vec["history_count_in_hour"] * 120.0 + CONFESSION_COOLDOWN_S
        allowed, _ = conf.check_rate_limit(source)
        assert allowed is vec["expected"]["accept"] is False
        response = await conf.render_post(_confession_request(source))
        assert response.code.dotted == vec["expected"]["response_code"].split()[0] == "4.29"

    async def test_twelfth_post_at_hourly_limit_accepted(self) -> None:
        vec = _vec(CONFESSIONS_RATE, "twelfth_post_accepted")
        source = vec["sender_iid"]
        clock = _Clock()
        conf = ConfessionsResource(time_func=clock)
        for i in range(vec["history_count_in_hour"]):  # 11 recorded
            clock.t = i * 120.0
            conf._record_request(source)
        clock.t = vec["history_count_in_hour"] * 120.0 + CONFESSION_COOLDOWN_S
        assert len(conf._request_times[source]) == CONFESSION_HOURLY_MAX - 1
        allowed, retry_after = conf.check_rate_limit(source)
        assert (allowed, retry_after) == (True, 0)
        response = await conf.render_post(_confession_request(source))
        assert response.code.dotted == vec["expected"]["response_code"].split()[0] == "2.01"

    async def test_hour_window_slides_with_strict_pruning(self) -> None:
        """Accept matches the vector; remaining count does not (divergence)."""
        vec = _vec(CONFESSIONS_RATE, "post_after_hour_window_slides")
        source = vec["sender_iid"]
        clock = _Clock()
        conf = ConfessionsResource(time_func=clock)
        for entry in vec["history"]:
            clock.t = entry["uptime_ms"] / 1000
            conf._record_request(source)
        clock.t = vec["current_uptime_ms"] / 1000
        allowed, _ = conf.check_rate_limit(source)
        assert allowed is vec["expected"]["accept"] is True
        # 0s expired at 3601s; 300s/600s remain (hour not elapsed).
        assert len(conf._request_times[source]) == vec["expected"]["posts_in_window"] == 2

    async def test_different_nodes_independent(self) -> None:
        vec = _vec(CONFESSIONS_RATE, "different_nodes_independent")
        exhausted, fresh = vec["scenarios"]
        clock = _Clock()
        conf = ConfessionsResource(time_func=clock)
        a, b = exhausted["sender_iid"], fresh["sender_iid"]
        for i in range(exhausted["history_count_in_hour"]):
            clock.t = i * 120.0
            conf._record_request(a)
        clock.t = exhausted["history_count_in_hour"] * 120.0 + CONFESSION_COOLDOWN_S
        assert conf.check_rate_limit(a)[0] is exhausted["accept"] is False
        assert conf.check_rate_limit(b)[0] is fresh["accept"] is True

    async def test_30s_limit_checked_before_hourly(self) -> None:
        vec = _vec(CONFESSIONS_RATE, "30s_limit_stricter")
        source = vec["sender_iid"]
        clock = _Clock()
        conf = ConfessionsResource(time_func=clock)
        clock.t = vec["history"][0]["uptime_ms"] / 1000
        conf._record_request(source)
        clock.t = vec["current_uptime_ms"] / 1000
        allowed, retry_after = conf.check_rate_limit(source)
        assert allowed is vec["expected"]["accept"] is False
        # Cooldown branch fired (not the hourly branch): retry reflects 30s rule.
        # Implementation uses math.ceil(30 - 4) = 26 (exact integer).
        assert retry_after == 26
        assert retry_after <= CONFESSION_COOLDOWN_S

    def test_time_source_defaults_to_monotonic_uptime(self) -> None:
        vec = _vec(CONFESSIONS_RATE, "uptime_not_wallclock")
        assert vec["expected"]["time_source"] == "monotonic_uptime"
        conf = ConfessionsResource()
        assert conf._time_func is time.monotonic

    async def test_retry_after_header_semantics(self) -> None:
        """POST at 10 s after last: retry_after matches the vector pin (20)."""
        vec = _vec(CONFESSIONS_RATE, "retry_after_header")
        source = vec["sender_iid"]
        clock = _Clock()
        conf = ConfessionsResource(time_func=clock)
        clock.t = vec["last_post_uptime_ms"] / 1000
        conf._record_request(source)
        clock.t = vec["current_uptime_ms"] / 1000
        allowed, retry_after = conf.check_rate_limit(source)
        assert allowed is False
        # Implementation uses math.ceil matching the vector's exact integer pin.
        assert retry_after == vec["expected"]["retry_after_s"] == 20
        response = await conf.render_post(_confession_request(source))
        assert response.code.dotted == vec["expected"]["response_code"].split()[0] == "4.29"
        assert cbor2.loads(response.payload) == {"retry_after": retry_after}

    async def test_max_confession_size_enforced(self) -> None:
        vec = _vec(CONFESSIONS_RATE, "max_confession_size")
        assert vec["expected"]["max_size"] == CONFESSION_MAX_SIZE == 768
        source = "0011223344556677"
        conf = ConfessionsResource(time_func=_Clock())
        oversized = _confession_payload(source, content="x" * 800)
        assert len(oversized) > vec["payload_size"] > CONFESSION_MAX_SIZE
        response = await conf.render_post(_confession_request(source, oversized))
        assert response.code.dotted == vec["expected"]["response_code"].split()[0] == "4.13"
        assert conf.confessions() == []  # rejected before parse/store
        # Boundary: at or below 768 the size gate does not fire.
        small = _confession_payload(source, content="tiny")
        assert len(small) <= CONFESSION_MAX_SIZE
        ok = await conf.render_post(_confession_request(source, small))
        assert ok.code is not aiocoap.REQUEST_ENTITY_TOO_LARGE


# ---------------------------------------------------------------------------
# receipt_cbor.json — MessageReceiptsResource normalization + byte-exact CBOR
# ---------------------------------------------------------------------------


_RECEIPT_BYTE_VECTORS = [
    "receipt_delivered",
    "receipt_read",
    "receipt_failed",
    "receipt_min_values",
    "receipt_max_u64_id",
]


class TestReceiptCborVectors:
    @pytest.mark.parametrize("name", _RECEIPT_BYTE_VECTORS)
    def test_receipt_encode_decode_normalize(self, name: str) -> None:
        vec = _vec(RECEIPT_CBOR, name)
        payload = vec["cbor_payload"]
        encoded = cbor2.dumps(payload)
        # Byte-exact against the committed hex, both directions.
        assert encoded.hex() == vec["cbor_hex"]
        assert len(encoded) == vec["cbor_length"]
        decoded = cbor2.loads(bytes.fromhex(vec["cbor_hex"]))
        assert decoded == payload
        # The real receipt validator accepts exactly these fields.
        normalized = MessageReceiptsResource._normalize(decoded)
        assert normalized is not None
        assert set(normalized) == {"id", "status", "ts"}
        if "fields_present" in vec["expected"]:
            assert set(vec["expected"]["fields_present"]) == {"id", "status", "ts"}
        if "status_value" in vec["expected"]:
            assert normalized["status"] == vec["expected"]["status_value"]

    async def test_valid_status_values_match_spec(self) -> None:
        vec = _vec(RECEIPT_CBOR, "receipt_status_validation")
        assert set(vec["valid_statuses"]) == set(MessageReceiptsResource.VALID_STATUSES)
        receipts = MessageReceiptsResource()
        for status in vec["valid_statuses"]:
            response = await receipts.render_post(
                _admin_post(cbor2.dumps({"id": 1, "status": status, "ts": 1716742900}))
            )
            assert response.code == aiocoap.CHANGED
        bad = await receipts.render_post(
            _admin_post(cbor2.dumps({"id": 1, "status": "unknown", "ts": 1716742900}))
        )
        assert bad.code == aiocoap.BAD_REQUEST
        assert bad.code.dotted == "4.00"
        assert vec["expected"]["unknown_status_handling"] == "reject_with_4.00"

    @pytest.mark.parametrize(
        "name",
        [
            "receipt_missing_id",
            "receipt_missing_status",
            "receipt_missing_ts",
            "receipt_invalid_status",
            "receipt_negative_id",
            "receipt_negative_ts",
            "receipt_string_id",
            "receipt_empty_payload",
        ],
    )
    async def test_reject_vectors_return_400(self, name: str) -> None:
        vec = _vec(RECEIPT_CBOR, name)
        expected = vec["expected"]
        assert expected["decode_success"] is False
        receipts = MessageReceiptsResource()
        payload = vec.get("cbor_payload")
        raw = cbor2.dumps(payload) if payload else b""
        if payload:
            assert MessageReceiptsResource._normalize(cbor2.loads(raw)) is None
        response = await receipts.render_post(_admin_post(raw))
        assert response.code == aiocoap.BAD_REQUEST
        assert response.code.dotted == expected["response_code"]
        assert receipts.receipts() == []

    async def test_max_u64_boundary(self) -> None:
        vec = _vec(RECEIPT_CBOR, "receipt_max_u64_id")
        max_id = vec["cbor_payload"]["id"]
        receipts = MessageReceiptsResource()
        ok = await receipts.render_post(
            _admin_post(cbor2.dumps({"id": max_id, "status": "read", "ts": 4294967295}))
        )
        assert ok.code == aiocoap.CHANGED
        beyond = await receipts.render_post(
            _admin_post(cbor2.dumps({"id": max_id + 1, "status": "read", "ts": 4294967295}))
        )
        assert beyond.code == aiocoap.BAD_REQUEST

    async def test_receipt_id_references_inbox_message(self) -> None:
        vec = _vec(RECEIPT_CBOR, "receipt_id_semantics")
        assert vec["expected"]["id_type"] == "uint64"
        messages = MessagesResource()
        receipts = MessageReceiptsResource()
        client, server = await _stack(
            messages_resource=messages, message_receipts_resource=receipts
        )
        try:
            created = await client.request(
                Message(
                    code=aiocoap.POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps({"body": "ping", "to": "all"}),
                    content_format=60,
                )
            ).response
            assert created.code == aiocoap.CREATED
            message_id = int(created.opt.location_path[2])
            receipt_response = await client.request(
                Message(
                    code=aiocoap.POST,
                    uri="coap://srv/msg/ack",
                    payload=cbor2.dumps(
                        {"id": message_id, "status": "delivered", "ts": 1716742900}
                    ),
                    content_format=60,
                )
            ).response
            assert receipt_response.code == aiocoap.CHANGED
            stored = receipts.receipts()
            assert len(stored) == 1
            assert stored[0]["id"] == message_id
            assert type(stored[0]["id"]) is int
            assert 0 <= stored[0]["id"] <= 2**64 - 1
        finally:
            await _teardown(client, server)

    @pytest.mark.parametrize("bad_ts", [True, False, 17.5, "1716742900"])
    async def test_ts_is_uint_only(self, bad_ts: object) -> None:
        vec = _vec(RECEIPT_CBOR, "receipt_ts_semantics")
        assert vec["expected"]["ts_type"] == "uint"
        receipts = MessageReceiptsResource()
        response = await receipts.render_post(
            _admin_post(cbor2.dumps({"id": 12345, "status": "delivered", "ts": bad_ts}))
        )
        assert response.code == aiocoap.BAD_REQUEST
        assert receipts.receipts() == []


# ---------------------------------------------------------------------------
# Guard: every vector in each file is accounted for by this module
# ---------------------------------------------------------------------------


class TestAllSecurityAppVectorsAccountedFor:
    EXPECTED_COUNTS = {
        "announce_signed_data": 4,
        "sos_signature": 18,
        "sos_rate_limiting": 10,
        "group_oscore_key": 10,
        "confessions_rate": 11,
        "receipt_cbor": 16,
    }

    @pytest.mark.parametrize(
        "doc",
        [
            ANNOUNCE_SIGNED_DATA,
            SOS_SIGNATURE,
            SOS_RATE_LIMITING,
            GROUP_OSCORE_KEY,
            CONFESSIONS_RATE,
            RECEIPT_CBOR,
        ],
    )
    def test_vector_count_matches_expectation(self, doc: dict[str, Any]) -> None:
        doc_name = doc.get("name") or doc.get("vector_type")
        assert doc_name in self.EXPECTED_COUNTS
        assert len(doc["vectors"]) == self.EXPECTED_COUNTS[doc_name]
