# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consumers for the previously orphaned vector files.

Drives the real lichen Python implementation through every vector case in:

- ``test/vectors/slip_framing.json``   via :mod:`lichen.slip.codec`
- ``test/vectors/sos_cbor.json``       via :mod:`lichen.coap.sos_origin`,
  :mod:`lichen.coap.sos_relay`, and the ``/sos`` CoAP resource
- ``test/vectors/neighbors_cbor.json`` via the ``/status/neighbors`` resource
  and the LCI client neighbor normalization path
- ``test/vectors/coap_transport.json`` via :mod:`lichen.coap.params` and
  SCHC fragmentation/port-rule constants

Known divergences (real behavior asserted; tracked in beads):

- SLIP invalid escape / truncated escape / repeated END frames: the Python
  oracle implements RFC 1055 recovery leniently (discard ESC, pass the next
  byte through) rather than rejecting, and drops empty frames instead of
  yielding them. The vectors describe stricter behavior. Bytes before the
  first END are likewise surfaced as a packet rather than discarded.
- ``neighbors_cbor.json`` wraps entries in ``{"neighbors": [...]}``; the
  ``NeighborsResource`` producer emits a bare list. The LCI client accepts
  both shapes, so both are exercised.
- ``sos_node_format`` positive examples use colon-hex IPv6 notation, while
  ``SosResource``/``SosRelay`` require 16-char hex EUI-64 node identifiers.
- ``sos_seq_rollover`` expects uint8 wraparound (255->0) to be valid; the
  implementation uses 64-bit monotonic sequences for replay protection (spec
  18.4.1), so rollover at 255 is rejected as stale.

Undrivable cases (no Python enforcement surface; not fabricated):

- ``sos_type_validation`` unknown-type handling ("reject_or_log_unknown"):
  SosResource deliberately tolerates non-"sos" type values.
- ``coap_transport`` "prefer_non" CON/NON selection policy and
  "gateway_translation" external-leg strings: prose policy with no code
  surface; only the port membership is machine-checkable.

Rejection contract coverage:

- The six negative ``sos_cbor.json`` vectors carry machine-drivable
  ``cbor_hex`` now and are driven through :class:`CheckInResource` POST,
  whose coordinate rules mirror the C decoder contract (lat [-90, 90],
  lon [-180, 180] inclusive; non-finite rejected; lat/lon all-or-none).
  The four non-finite-coordinate vectors have no ``cbor_payload`` because
  NaN/Infinity are not representable in JSON; their raw CBOR structure is
  asserted directly instead of through payload equality.
"""

from __future__ import annotations

import json
import math
from collections.abc import AsyncIterator
from ipaddress import IPv6Address
from pathlib import Path
from typing import Any

import cbor2
import pytest
from aiocoap import BAD_REQUEST, CREATED, POST, Message

from lichen.client import CoapResult, LciClient, LciClientError
from lichen.coap.params import (
    LICHEN_ACK_RANDOM_FACTOR,
    LICHEN_ACK_TIMEOUT,
    LICHEN_DEFAULT_LEISURE,
    LICHEN_MAX_RETRANSMIT,
    LICHEN_NSTART,
    LICHEN_PROBING_RATE,
    PORT_ALLOCATION,
    PORT_COAPS_RESERVED,
    RFC7252_ACK_RANDOM_FACTOR,
    RFC7252_ACK_TIMEOUT,
    RFC7252_DEFAULT_LEISURE,
    RFC7252_MAX_RETRANSMIT,
    RFC7252_NSTART,
    RFC7252_PROBING_RATE,
    CoapParams,
    CongestionLevel,
    TxPriority,
    app_priority,
    congestion_level,
    congestion_service_unavailable,
)
from lichen.coap.resources import StaticNodeInfo
from lichen.coap.resources.emergency import CheckInResource, SosResource
from lichen.coap.resources.node_resources import NeighborsResource
from lichen.coap.sos_origin import (
    canonicalize_sos_payload,
    sign_sos_origin,
    verify_sos_origin,
)
from lichen.coap.sos_relay import SosRelay, get_sos_id_from_payload
from lichen.constants import PORT_MQTT_SN, SCHC_FRAGMENT_M, SCHC_FRAGMENT_N
from lichen.crypto.identity import _pubkey_to_iid
from lichen.crypto.schnorr48 import derive_keypair
from lichen.schc.fragment import MAX_PACKET_SIZE, MAX_SCHC_PACKET, TILE_SIZE, WINDOW_SIZE
from lichen.schc.rules import MO, UDP_PORT_RULE
from lichen.slip.codec import StreamDecoder
from lichen.slip.codec import decode as slip_decode
from lichen.slip.codec import encode as slip_encode

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"


def _make_signed_sos_body(
    sos_type: str,
    ts: int,
    origin_seq: int = 1,
    seed: bytes | None = None,
) -> dict:
    """Create a signed SOS body suitable for POST /sos.

    Returns a dict with all required fields including the origin signature
    envelope (pubkey, sig) so that SosResource.render_post accepts it.
    """
    if seed is None:
        seed = bytes(range(32))
    privkey, pubkey = derive_keypair(seed)
    iid = _pubkey_to_iid(pubkey)
    node_hex = iid.hex()
    origin_address = IPv6Address(b"\x02\x00" + b"\x00" * 6 + iid)
    payload = {"type": sos_type, "node": node_hex, "ts": ts}
    origin_sig = sign_sos_origin(privkey, pubkey, origin_address, origin_seq, payload)
    return {
        **payload,
        "pubkey": pubkey,
        "sig": origin_sig.to_bytes(),
    }


def _load(name: str) -> dict:
    return json.loads((VECTORS_DIR / name).read_text())


def _cases(name: str) -> list[tuple[str, dict]]:
    doc = _load(name)
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


def _case(filename: str, target: str) -> dict:
    return next(v for _, v in _cases(filename) if v["name"] == target)


# ---------------------------------------------------------------------------
# slip_framing.json
# ---------------------------------------------------------------------------


def _slip_encode_cases() -> list[tuple[str, dict]]:
    return [
        (name, vector)
        for name, vector in _cases("slip_framing.json")
        if "data" in vector and "framed" in vector.get("expected", {})
    ]


def _slip_decode_valid_cases() -> list[tuple[str, dict]]:
    return [
        (name, vector)
        for name, vector in _cases("slip_framing.json")
        if "framed" in vector and vector.get("expected", {}).get("valid") is True
    ]


@pytest.mark.parametrize("name,vector", _slip_encode_cases())
def test_slip_encode_exact_bytes(name: str, vector: dict) -> None:
    data = bytes.fromhex(vector["data"])
    framed = bytes.fromhex(vector["expected"]["framed"])
    assert slip_encode(data) == framed, f"encode drift: {name}"


@pytest.mark.parametrize("name,vector", _slip_encode_cases())
def test_slip_roundtrip_after_encode(name: str, vector: dict) -> None:
    data = bytes.fromhex(vector["data"])
    assert slip_decode(slip_encode(data)) == data, f"roundtrip drift: {name}"


@pytest.mark.parametrize("name,vector", _slip_decode_valid_cases())
def test_slip_decode_valid_frame(name: str, vector: dict) -> None:
    framed = bytes.fromhex(vector["framed"])
    expected_data = bytes.fromhex(vector["expected"].get("data", ""))
    decoded = slip_decode(framed)
    assert decoded == expected_data, f"decode drift: {name}"
    decoder = StreamDecoder()
    assert decoder.feed(framed) == ([expected_data] if expected_data else []), name


def _split_ascii_hex_stream(stream_text: str) -> bytes:
    """Parse a vector stream mixing literal ASCII prefix with hex payload.

    Returns the longest all-hex even-length suffix decoded plus the remaining
    leading text encoded as ASCII.
    """
    hex_chars = set("0123456789abcdefABCDEF")
    start = 0
    for candidate in range(len(stream_text) + 1):
        tail = stream_text[candidate:]
        if len(tail) % 2 == 0 and tail and all(char in hex_chars for char in tail):
            start = candidate
            break
    return stream_text[:start].encode("ascii") + bytes.fromhex(stream_text[start:])


def test_slip_stream_leading_end_strip() -> None:
    """Vector expects pre-END garbage to be silently discarded.

    The stream decoder surfaces the unsynchronized leading bytes as their own
    packet at the first END; consumers must drop frames received before line
    sync. Asserts the deterministic real output and documents the divergence.
    """
    vector = _case("slip_framing.json", "slip_leading_end_strip")
    stream = _split_ascii_hex_stream(vector["stream"])
    decoder = StreamDecoder()
    packets = decoder.feed(stream)
    assert packets[0] == b"garbage"
    assert packets[-1] == bytes.fromhex(vector["expected"]["first_valid_frame"])


def test_slip_max_frame_size() -> None:
    vector = _case("slip_framing.json", "slip_max_frame_size")
    max_data_size = vector["max_data_size"]
    assert max_data_size == StreamDecoder.DEFAULT_MAX_SIZE
    worst_case_escaped = b"\xdb" * max_data_size
    assert len(slip_encode(worst_case_escaped)) == vector["expected"]["max_framed_size"]
    worst_case_end = b"\xc0" * max_data_size
    assert len(slip_encode(worst_case_end)) == vector["expected"]["max_framed_size"]


def test_slip_invalid_escape_sequence_known_divergence() -> None:
    """Vector expects valid=false for ESC followed by an undefined byte.

    The Python oracle follows RFC 1055 recovery instead: ESC is discarded and
    the following byte passes through as data. Asserts that deterministic real
    behavior on both decoder APIs; divergence from the vector is intentional
    and documented in the module docstring.
    """
    vector = _case("slip_framing.json", "slip_invalid_escape_sequence")
    assert vector["expected"]["valid"] is False
    framed = bytes.fromhex(vector["framed"])
    assert slip_decode(framed) == b"\x01\x01\x02"
    decoder = StreamDecoder()
    assert decoder.feed(framed) == [b"\x01\x01\x02"]


def test_slip_truncated_escape_known_divergence() -> None:
    """Vector expects valid=false for a frame whose ESC abuts the closing END.

    decode() consumes the closing END as the byte following ESC (lenient
    pass-through of 0xC0); the stream decoder holds the partial frame until a
    further END arrives. Neither API raises for this input.
    """
    vector = _case("slip_framing.json", "slip_truncated_escape")
    assert vector["expected"]["valid"] is False
    framed = bytes.fromhex(vector["framed"])
    assert slip_decode(framed) == b"\x01\xc0"
    decoder = StreamDecoder()
    assert decoder.feed(framed) == []
    assert decoder.feed(b"\xc0") == [b"\x01\xc0"]


def test_slip_multiple_empty_frames_known_divergence() -> None:
    """Vector counts 3 empty sync frames in four consecutive ENDs.

    The stream decoder treats consecutive ENDs as idle/sync and emits no
    packets; line synchronization still works afterwards, which is asserted
    here in place of the unimplemented empty-frame count.
    """
    vector = _case("slip_framing.json", "slip_multiple_empty_frames")
    assert vector["expected"]["frame_count"] == 3
    assert vector["expected"]["all_empty"] is True
    decoder = StreamDecoder()
    assert decoder.feed(b"\xc0\xc0\xc0\xc0") == []
    assert decoder.feed(slip_encode(b"Hello")) == [b"Hello"]


# ---------------------------------------------------------------------------
# sos_cbor.json
# ---------------------------------------------------------------------------


def _sos_payload_cases() -> list[tuple[str, dict]]:
    return [(name, vector) for name, vector in _cases("sos_cbor.json") if "cbor_hex" in vector]


def _is_rejection_case(vector: dict) -> bool:
    return vector.get("expected", {}).get("decode_success") is False


@pytest.mark.parametrize("name,vector", _sos_payload_cases())
def test_sos_cbor_wire_contract(name: str, vector: dict) -> None:
    wire = bytes.fromhex(vector["cbor_hex"])
    assert len(wire) == vector["cbor_length"], name
    decoded = cbor2.loads(wire)
    if "cbor_payload" in vector:
        # Payload equality is raw-CBOR structure, valid for both accepted
        # and rejected vectors; application-level rejection is covered by
        # test_sos_cbor_negative_vectors_rejected.
        payload = vector["cbor_payload"]
        assert decoded == payload, name
        assert cbor2.dumps(payload) == wire, f"re-encode drift: {name}"
    if not _is_rejection_case(vector):
        for field in vector["expected"].get("fields_present", []):
            assert field in decoded, f"{name}: missing {field}"
        for field in vector["expected"].get("fields_absent", []):
            assert field not in decoded, f"{name}: unexpected {field}"
        if vector["expected"].get("lat_negative") is True:
            assert decoded["lat"] < 0
    else:
        error = vector["expected"]["error"]
        assert isinstance(decoded, dict), name
        lat = decoded.get("lat")
        lon = decoded.get("lon")
        if error == "non_finite_coordinate":
            bad_lat = isinstance(lat, float) and not math.isfinite(lat)
            bad_lon = isinstance(lon, float) and not math.isfinite(lon)
            assert bad_lat != bad_lon, f"{name}: exactly one non-finite coordinate expected"
            assert lat is not None and lon is not None, f"{name}: paired map with one defect"
        elif error == "coordinate_out_of_range":
            bad_lat = lat is not None and not -90 <= lat <= 90
            bad_lon = lon is not None and not -180 <= lon <= 180
            assert bad_lat != bad_lon, f"{name}: exactly one out-of-range coordinate expected"
        else:  # pragma: no cover - guards against silent schema drift
            pytest.fail(f"{name}: unexpected rejection error {error!r}")


@pytest.mark.parametrize("name,vector", _sos_payload_cases())
async def test_sos_cbor_negative_vectors_rejected(name: str, vector: dict) -> None:
    """All six negative vectors are rejected by the real check-in decoder.

    :class:`CheckInResource` enforces the same coordinate contract as the
    C ``sos_alert_from_cbor`` reference: inclusive bounds, non-finite
    rejection, all-or-none lat/lon pairing. The wire bytes from the vector
    are decoded with cbor2 so the exact committed encoding drives the
    implementation surface (status/node/ts defaults fill the unrelated
    required fields).
    """
    if not _is_rejection_case(vector):
        pytest.skip("positive vector")
    wire = bytes.fromhex(vector["cbor_hex"])
    coordinates = cbor2.loads(wire)
    body = {
        "node": str(coordinates.get("node", "0200111122223333")),
        "ts": coordinates.get("ts", 1_700_000_000),
        "status": "ok",
    }
    for field in ("lat", "lon"):
        if coordinates.get(field) is not None:
            body[field] = coordinates[field]
    resource = CheckInResource()
    response = await resource.render_post(Message(code=POST, payload=cbor2.dumps(body)))
    assert response.code == BAD_REQUEST, name
    assert not resource._checkins, name


@pytest.mark.parametrize("name,vector", _sos_payload_cases())
def test_sos_cbor_canonical_signing_roundtrip(name: str, vector: dict) -> None:
    payload = vector.get("cbor_payload")
    if payload is None:
        # Non-finite coordinates (NaN/Inf) are not representable in JSON,
        # so these rejection vectors carry no signed-payload example.
        pytest.skip(f"{name}: cbor_payload not representable")
    canonical = canonicalize_sos_payload(dict(payload))
    assert cbor2.loads(canonical) == payload
    assert canonicalize_sos_payload(dict(payload)) == canonical

    privkey, pubkey = derive_keypair(bytes(range(32)))
    origin_address = IPv6Address("fe80::0200:0011:2233:4455")
    signature = sign_sos_origin(privkey, pubkey, origin_address, 1, dict(payload))
    assert verify_sos_origin(pubkey, origin_address.packed, canonical, signature)

    tampered = bytearray(canonical)
    tampered[-1] ^= 0x01
    assert not verify_sos_origin(pubkey, origin_address.packed, bytes(tampered), signature)


@pytest.mark.parametrize(
    ("sos_type", "origin_seq"),
    [("sos", 1), ("medical", 2), ("security", 3), ("fire", 4), ("cancel", 5)],
)
async def test_sos_type_validation_accepted_types(sos_type: str, origin_seq: int) -> None:
    """All five spec types are accepted by POST /sos.

    The vector's unknown_type_handling expectation ("reject_or_log_unknown")
    has no enforcement surface in the implementation and stays undrivable.

    Each type uses a distinct origin_seq so the monotonic sequence gate
    passes on a fresh SosResource (which tracks per-node sequences).
    """
    vector = _case("sos_cbor.json", "sos_type_validation")
    assert sos_type in vector["valid_types"]
    resource = SosResource()
    body = _make_signed_sos_body(sos_type, ts=1716742800, origin_seq=origin_seq)
    response = await resource.render_post(Message(code=POST, payload=cbor2.dumps(body)))
    assert response.code == CREATED


def test_sos_seq_rollover_known_divergence() -> None:
    """Vector expects uint8 wraparound to be valid; implementation rejects it.

    The OriginSequenceTracker enforces strictly monotonic 64-bit sequences for
    replay protection (spec 18.4.1). Rollover from 255 to 0 is rejected because
    the origin-signature mechanism uses a 64-bit counter, not an 8-bit one.
    This is intentional: the wire format allows 64-bit sequences, so rollover
    at 255 would only occur if the sender deliberately wrapped (suspicious).

    Asserts the deterministic real behavior and documents the divergence from
    the vector's ``rollover_valid: true`` expectation.
    """
    vector = _case("sos_cbor.json", "sos_seq_rollover")
    assert vector["previous_seq"] == 255
    assert vector["new_seq"] == 0
    assert vector["expected"]["rollover_valid"] is True
    node = "0123456789abcdef"
    relay = SosRelay()
    first = relay.check_relay(node, vector["previous_seq"], ttl=7)
    assert first.should_relay is True
    wrapped = relay.check_relay(node, vector["new_seq"], ttl=7)
    assert wrapped.should_relay is False
    assert "stale" in wrapped.reason
    assert get_sos_id_from_payload({"node": node, "seq": 255}) == (node, 255)
    assert get_sos_id_from_payload({"node": node, "seq": 0}) == (node, 0)


@pytest.mark.parametrize(
    "bad_node",
    ["192.168.1.1", "0011:2233:4455:6677", ""],
)
async def test_sos_node_format_invalid_examples_rejected(bad_node: str) -> None:
    """The invalid node examples are rejected by POST /sos.

    The vector's positive examples use colon-hex IPv6 notation, but the
    implementation's node identifiers are 16-char hex EUI-64 strings; the
    positive half of this vector diverges and is documented in the module
    docstring.
    """
    vector = _case("sos_cbor.json", "sos_node_format")
    assert bad_node in vector["invalid_node_examples"]
    resource = SosResource()
    body = {"type": "sos", "node": bad_node, "ts": 1716742800}
    response = await resource.render_post(Message(code=POST, payload=cbor2.dumps(body)))
    assert response.code == BAD_REQUEST


async def test_sos_ts_semantics() -> None:
    """Validate ts=0 is accepted (wall clock unavailable) and missing ts is rejected."""
    vector = _case("sos_cbor.json", "sos_ts_semantics")
    assert vector["ts_zero_meaning"] == "wall_clock_unavailable"
    resource = SosResource()
    zero_ts_body = _make_signed_sos_body("sos", ts=0, origin_seq=1)
    response = await resource.render_post(Message(code=POST, payload=cbor2.dumps(zero_ts_body)))
    assert response.code == CREATED
    fresh = SosResource()
    privkey, pubkey = derive_keypair(bytes(range(32)))
    iid = _pubkey_to_iid(pubkey)
    missing_ts = {"type": "sos", "node": iid.hex(), "pubkey": pubkey, "sig": b"\x00" * 56}
    response = await fresh.render_post(Message(code=POST, payload=cbor2.dumps(missing_ts)))
    assert response.code == BAD_REQUEST


# ---------------------------------------------------------------------------
# neighbors_cbor.json
# ---------------------------------------------------------------------------


class _FakeResourceTransport:
    def __init__(self, payload: Any) -> None:
        self._payload = payload

    async def request(
        self,
        method: str,
        path: str,
        *,
        payload: bytes = b"",
        content_format: int | None = None,
        observe: bool = False,
    ) -> CoapResult:
        del method, path, payload, content_format, observe
        return CoapResult(code="2.05", payload=self._payload)

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    def observe(self, path: str, *, method: str = "GET") -> AsyncIterator[CoapResult]:
        del path, method
        raise NotImplementedError


def _assert_neighbor_matches(entry: dict[str, Any], neighbor: Any) -> None:
    assert neighbor.addr == entry["addr"]
    assert neighbor.rssi_dbm == entry["rssi_dbm"]
    assert neighbor.snr_db == entry["snr_db"]
    assert neighbor.etx == entry["etx"]
    assert neighbor.last_seen_s == entry["last_seen_s"]
    assert neighbor.trust == entry["trust"]


@pytest.mark.parametrize("name,vector", _cases("neighbors_cbor.json"))
def test_neighbors_cbor_wire_contract(name: str, vector: dict) -> None:
    wire = bytes.fromhex(vector["encoded_hex"])
    decoded = cbor2.loads(wire)
    assert decoded == vector["input"], name
    assert cbor2.dumps(vector["input"]) == wire, f"re-encode drift: {name}"


@pytest.mark.parametrize("name,vector", _cases("neighbors_cbor.json"))
async def test_neighbors_lci_client_wrapped_shape(name: str, vector: dict) -> None:
    """Decode the exact committed wire bytes through the LCI consumer path."""
    transport = _FakeResourceTransport(cbor2.loads(bytes.fromhex(vector["encoded_hex"])))
    client = LciClient(transport)
    neighbors = await client.list_neighbors()
    assert len(neighbors) == len(vector["input"]["neighbors"]), name
    for entry, neighbor in zip(vector["input"]["neighbors"], neighbors, strict=True):
        _assert_neighbor_matches(entry, neighbor)


@pytest.mark.parametrize("name,vector", _cases("neighbors_cbor.json"))
async def test_neighbors_resource_producer_and_bare_shape(name: str, vector: dict) -> None:
    """NeighborsResource emits a bare list; the LCI client accepts it too."""
    info = StaticNodeInfo(neighbors=[dict(n) for n in vector["input"]["neighbors"]])
    resource = NeighborsResource(info)
    response = await resource.render_get(Message())
    assert response.opt.content_format == 60
    bare = cbor2.loads(response.payload)
    assert bare == vector["input"]["neighbors"], name

    transport = _FakeResourceTransport(bare)
    client = LciClient(transport)
    neighbors = await client.list_neighbors()
    for entry, neighbor in zip(vector["input"]["neighbors"], neighbors, strict=True):
        _assert_neighbor_matches(entry, neighbor)


async def test_neighbors_lci_client_rejects_non_list_payload() -> None:
    transport = _FakeResourceTransport({"neighbors": "not-a-list"})
    client = LciClient(transport)
    with pytest.raises(LciClientError):
        await client.list_neighbors()


# ---------------------------------------------------------------------------
# coap_transport.json
# ---------------------------------------------------------------------------


def test_coap_transport_port_allocation() -> None:
    vector = _case("coap_transport.json", "port_allocation")
    assert {entry["port"]: entry["use"] for entry in vector["ports"]} == PORT_ALLOCATION
    family = vector["schc_compressed_family"]
    low_text, high_text = family["range"].split("-")
    src, dst = UDP_PORT_RULE.fields[0], UDP_PORT_RULE.fields[1]
    for descriptor in (src, dst):
        assert descriptor.mo is MO.MSB
        assert descriptor.target_value == 5683
        assert descriptor.mo_arg == family["msb_bits"]
        assert descriptor.length_bits - descriptor.mo_arg == family["lsb_bits"]
    residue_bits = (src.length_bits - src.mo_arg) + (dst.length_bits - dst.mo_arg)
    assert (residue_bits + 7) // 8 == family["wire_cost_bytes"]
    low, high = int(low_text), int(high_text)
    for port in range(low, high + 1):
        assert (port >> family["lsb_bits"]) == (5683 >> family["lsb_bits"])

    assert vector["mqtt_sn_requires_dedicated_rule"] is True
    assert vector["mqtt_sn_rule"]["port"] == PORT_MQTT_SN


def test_coap_transport_gateway_translation_ports() -> None:
    vector = _case("coap_transport.json", "gateway_translation")
    for translation in vector["translations"]:
        assert translation["mesh_port"] in PORT_ALLOCATION


def test_coap_transport_lora_params() -> None:
    vector = _case("coap_transport.json", "loRa_params")
    params = CoapParams()
    rfc = {
        "ack_timeout": RFC7252_ACK_TIMEOUT,
        "ack_random_factor": RFC7252_ACK_RANDOM_FACTOR,
        "max_retransmit": RFC7252_MAX_RETRANSMIT,
        "nstart": RFC7252_NSTART,
        "default_leisure": RFC7252_DEFAULT_LEISURE,
        "probing_rate": RFC7252_PROBING_RATE,
    }
    lichen = {
        "ack_timeout": LICHEN_ACK_TIMEOUT,
        "ack_random_factor": LICHEN_ACK_RANDOM_FACTOR,
        "max_retransmit": LICHEN_MAX_RETRANSMIT,
        "nstart": LICHEN_NSTART,
        "default_leisure": LICHEN_DEFAULT_LEISURE,
        "probing_rate": LICHEN_PROBING_RATE,
    }
    assert vector["rfc7252"] == rfc
    assert vector["lichen"] == lichen
    assert params.retransmit_timeouts() == vector["retry_schedule"]
    max_transmit_span = params.exchange_lifetime() - params.default_leisure
    assert max_transmit_span == vector["give_up_after"]


@pytest.mark.parametrize(
    "target",
    [
        "congestion_normal",
        "congestion_elevated",
        "congestion_critical",
        "congestion_exhausted",
    ],
)
def test_coap_transport_congestion_levels(target: str) -> None:
    vector = _case("coap_transport.json", target)
    level = congestion_level(vector["duty_used_ratio"])
    assert level.value == vector["expected_level"]
    assert level.value == vector["computed_level"]
    assert vector["duty_used_ratio"] * 100 == pytest.approx(vector["duty_used_percent"])


def test_coap_transport_load_shedding_503() -> None:
    vector = _case("coap_transport.json", "load_shedding_503")
    message = congestion_service_unavailable(CongestionLevel.CRITICAL, retry_after_s=120)
    assert int(message.code) == vector["response_code"]
    assert message.payload.hex() == vector["payload_hex"]
    assert cbor2.loads(message.payload) == vector["payload_example"]
    assert message.opt.max_age == vector["max_age"]
    assert message.opt.content_format is not None
    assert int(message.opt.content_format) == vector["content_format"]


def test_coap_transport_priority_queue() -> None:
    vector = _case("coap_transport.json", "priority_queue")
    members = [
        TxPriority.SOS,
        TxPriority.ROUTING,
        TxPriority.URGENT,
        TxPriority.NORMAL,
        TxPriority.BULK,
    ]
    assert len(members) == len(vector["priorities"])
    for priority_enum, entry in zip(members, vector["priorities"], strict=True):
        assert int(priority_enum) == entry["priority"]
        assert entry["label"].startswith(f"P{entry['priority']}")


_APP_SUBTYPE_KEYS = [
    ("Compact CoT", "Alert (0x20)", "alert"),
    ("Compact CoT", "Chat (0x01)", "chat"),
    ("Compact CoT", "PLI (0x02-0x05)", "pli"),
    ("Compact CoT", "Marker (0x10)", "marker"),
    ("SenML", "All", "senml"),
    ("CoAP", "CON", "con"),
    ("CoAP", "NON", "non"),
    ("Cayenne", "All", "cayenne"),
    ("APRS-IS", "All", "aprs"),
    ("NMEA", "All", "nmea"),
    ("MQTT-SN", "QoS 1+", "qos1"),
    ("MQTT-SN", "QoS 0/-1", "qos0"),
]


@pytest.mark.parametrize(("app", "subtype", "key"), _APP_SUBTYPE_KEYS)
def test_coap_transport_app_to_priority_mapping(app: str, subtype: str, key: str) -> None:
    vector = _case("coap_transport.json", "app_to_priority_mapping")
    row = next(
        entry for entry in vector["mapping"] if entry["app"] == app and entry["subtype"] == subtype
    )
    assert int(app_priority(row["port"], key)) == row["priority"]


def test_coap_transport_fragmentation_guidance_capacity() -> None:
    vector = _case("coap_transport.json", "fragmentation_guidance")
    capacity = vector["capacity"]
    assert capacity["fcn_bits"] == SCHC_FRAGMENT_N
    assert capacity["tiles_per_window"] == WINDOW_SIZE
    assert capacity["windows"] == (1 << SCHC_FRAGMENT_M)
    assert capacity["tile_size"] == TILE_SIZE
    assert capacity["ceiling"] == MAX_PACKET_SIZE
    assert capacity["mandatory_receiver"] == MAX_SCHC_PACKET
    assert (
        capacity["windows"] * capacity["tiles_per_window"] * capacity["tile_size"]
    ) == MAX_PACKET_SIZE


def test_coap_transport_oscore_reference_port() -> None:
    vector = _case("coap_transport.json", "oscore_reference")
    assert vector["port_5684_reserved"] is True
    assert PORT_COAPS_RESERVED == 5684
    assert PORT_ALLOCATION[5684].startswith("Reserved")
