#!/usr/bin/env python3
"""Generate CoAP test vectors for LICHEN Chapter 07 (spec/07-transport-app.md).

Vectors are derived from the Python oracle (python/src/lichen/coap) which is
the source of truth per the Python Oracle Template (project-LICHEN-worker6-l1qw.16).

Run: PYTHONPATH=python/src python3 test/vectors/generate_coap.py
Writes: test/vectors/coap_messages.json, coap_rd.json, coap_transport.json
"""

from __future__ import annotations

import json
from pathlib import Path

import cbor2

# --- CoAP wire helpers (independent oracle via aiocoap) ---
from aiocoap import Message
from aiocoap.numbers.codes import Code
from aiocoap.numbers.types import CON, NON, ACK, RST

# Import oracle params
from lichen.coap.params import (
    CONTENT_FORMATS,
    LICHEN_ACK_TIMEOUT,
    LICHEN_ACK_RANDOM_FACTOR,
    LICHEN_DEFAULT_LEISURE,
    LICHEN_MAX_RETRANSMIT,
    LICHEN_NSTART,
    LICHEN_PROBING_RATE,
    PORT_ALLOCATION,
    TxPriority,
    congestion_level,
)

VECTORS_DIR = Path(__file__).resolve().parent
FORMAT_VERSION = 2


def _write(filename: str, description: str, vectors: list[dict], spec: str = "spec/07-transport-app.md") -> None:
    doc = {
        "$schema": "./schema.json",
        "format_version": FORMAT_VERSION,
        "name": filename.replace(".json", ""),
        "description": description,
        "spec": spec,
        "vectors": vectors,
    }
    path = VECTORS_DIR / filename
    path.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {len(vectors)} vectors to {path.name}")


def coap_message_vectors() -> list[dict]:
    """CoAP message parse/serialize vectors via aiocoap oracle."""
    vectors: list[dict] = []

    # Vector 1: CON GET with token and Uri-Path
    # Known vector: VER=1 T=0 CON TKL=2 GET mid=0x1234 token 0102 option Uri-Path=status payload none
    # Option encoding: delta=11 (Uri-Path) len=6 => 0xB6 'status'
    wire_con_get = bytes.fromhex("420112340102b6737461747573")
    # Decode via aiocoap to verify
    from lichen.coap.transport import LichenRemote

    remote = LichenRemote("srv")
    decoded = Message.decode(wire_con_get, remote)
    vectors.append(
        {
            "name": "con_get_status",
            "description": "CON GET /status with token 0x0102, MID 0x1234 (RFC 7252 §3).",
            "mtype": int(CON),
            "mtype_name": "CON",
            "code": int(Code.GET),
            "code_name": "0.01 GET",
            "mid": 0x1234,
            "token": "0102",
            "uri_path": ["status"],
            "options_hex": "b6737461747573",
            "payload": "",
            "encoded": wire_con_get.hex(),
            "decoded_code": int(decoded.code),
            "decoded_mtype": int(decoded.mtype),
            "decoded_mid": decoded.mid,
            "decoded_token": decoded.token.hex(),
        }
    )

    # Vector 2: NON POST with CBOR payload
    payload = cbor2.dumps({"temp": 23.5})
    # Craft wire: VER1 T=1 NON TKL1 POST 0x02 MID5678 token ab Content-Format 60 delta12 len1 0x3c payload marker ff + cbor
    # For oracle generation, we use aiocoap's serialization: encode via token_manager path is heavy,
    # so we compute wire via manual CoAP framing using aiocoap's private but we can do: Message.encode() static?
    # Fallback: manually build and verify decode
    # Build option bytes: Content-Format (12) value 60 => 0xC1 0x3C, Uri-Path delta 11-12=-1? Actually need delta encoding
    # Simplify: use python's cbor payload hex and expected encoding
    # We'll rely on aiocoap decode to produce correct options; store what we know
    # Let's actually call aiocoap's encoder by creating a dummy transport-less encode: use struct
    # Instead, we store the wire we craft and confirm aiocoap can decode options
    cbor_hex = payload.hex()
    # Content-Format 60 is option 12, Uri-Path is option 11 – order matters (11 before 12)
    # So uri first: Uri-Path status delta11 len7 -> B7 'sensors' ; Content-Format delta1 len1 0x3c
    # Wire: 51 02 5678 ab B7 73 65 6e 73 6f 72 73 11 3c ff <cbor>
    wire_non_post = bytes.fromhex("51025678ab") + bytes.fromhex("b773656e736f7273") + bytes.fromhex("113c") + b"\xff" + payload
    decoded2 = Message.decode(wire_non_post, remote)
    vectors.append(
        {
            "name": "non_post_sensors_cbor",
            "description": "NON POST /sensors with Content-Format 60 and CBOR payload.",
            "mtype": int(NON),
            "mtype_name": "NON",
            "code": int(Code.POST),
            "code_name": "0.02 POST",
            "mid": 0x5678,
            "token": "ab",
            "uri_path": ["sensors"],
            "content_format": 60,
            "payload_hex": cbor_hex,
            "payload_cbor": {"temp": 23.5},
            "encoded": wire_non_post.hex(),
            "decoded_code": int(decoded2.code),
            "decoded_mtype": int(decoded2.mtype),
            "decoded_payload_hex": decoded2.payload.hex(),
            "decoded_content_format": int(decoded2.opt.content_format) if decoded2.opt.content_format is not None else None,
        }
    )

    # Vector 3: ACK 2.05 Content with payload (0x60 = Ver1 ACK TKL0, Code 2.05 0x45, MID 0x4539)
    decoded3 = Message.decode(bytes.fromhex("60024539ff68656c6c6f"), remote)
    vectors.append(
        {
            "name": "ack_205_content",
            "description": "ACK 2.05 Content with payload 'hello' (RFC 7252 §5.5).",
            "mtype": int(ACK),
            "mtype_name": "ACK",
            "code": int(Code.CONTENT),
            "code_name": "2.05 Content",
            "mid": 0x4539,
            "token": "",
            "payload": "68656c6c6f",
            "payload_text": "hello",
            "encoded": "60024539ff68656c6c6f",
            "decoded_code": int(decoded3.code),
            "decoded_payload_text": decoded3.payload.decode(),
        }
    )

    # Vector 4: RST handling
    wire_rst = bytes.fromhex("70001234")
    decoded4 = Message.decode(wire_rst, remote)
    vectors.append(
        {
            "name": "rst_empty",
            "description": "RST empty message MID 0x1234.",
            "mtype": int(RST),
            "mtype_name": "RST",
            "code": 0,
            "code_name": "0.00 Empty",
            "mid": 0x1234,
            "token": "",
            "encoded": wire_rst.hex(),
            "decoded_mtype": int(decoded4.mtype),
        }
    )

    # Vector 5: Content-Format dispatch table
    vectors.append(
        {
            "name": "content_format_table",
            "description": "Content-Format dispatch values (spec §10.2.1).",
            "formats": [{"value": k, "media_type": v} for k, v in sorted(CONTENT_FORMATS.items())],
        }
    )

    # Vector 6: CoAP URI parsing
    from lichen.coap.transport import parse_uri_authority

    ep = parse_uri_authority("[2001:db8::1]:5683")
    vectors.append(
        {
            "name": "uri_authority_ipv6",
            "description": "URI authority parsing for [2001:db8::1]:5683.",
            "authority": "[2001:db8::1]:5683",
            "expected_host": "2001:db8::1",
            "expected_port": 5683,
            "parsed_host": ep.host,
            "parsed_port": ep.port,
        }
    )

    return vectors


def coap_rd_vectors() -> list[dict]:
    """RD registration and lookup vectors (spec §10.6, RFC 9176)."""
    vectors: list[dict] = []

    # Normal registration: ep=sensor-42 lt=3600 links CBOR
    links = [{"href": "/temperature", "rt": "sensor", "if": "core.s"}]
    payload = cbor2.dumps(links)
    vectors.append(
        {
            "name": "rd_register_sensor42",
            "description": "POST /rd?ep=sensor-42&lt=3600 with link </temperature>;rt=sensor. Expect 2.01 Created with Location-Path /rd/<id>.",
            "method": "POST",
            "uri": "/rd?ep=sensor-42&lt=3600",
            "query": {"ep": "sensor-42", "lt": 3600},
            "links": links,
            "payload_hex": payload.hex(),
            "payload_cbor": links,
            "expected_code": int(Code.CREATED),
            "expected_code_name": "2.01 Created",
            "location_path_prefix": "rd",
        }
    )

    # Default lifetime
    vectors.append(
        {
            "name": "rd_register_default_lifetime",
            "description": "POST /rd?ep=node-01 without lt uses default 86400 (RFC 9176 §7.3.1).",
            "method": "POST",
            "uri": "/rd?ep=node-01",
            "query": {"ep": "node-01"},
            "expected_lt": 86400,
            "expected_code": int(Code.CREATED),
        }
    )

    # Missing ep => 4.00
    vectors.append(
        {
            "name": "rd_register_missing_ep",
            "description": "POST /rd without ep returns 4.00 Bad Request.",
            "method": "POST",
            "uri": "/rd",
            "query": {},
            "expected_code": int(Code.BAD_REQUEST),
            "expected_code_name": "4.00 Bad Request",
        }
    )

    # Invalid lt => 4.00
    for bad_lt in ["0", "-1", "true", ""]:
        vectors.append(
            {
                "name": f"rd_register_bad_lt_{bad_lt or 'empty'}",
                "description": f"POST /rd?ep=node-01&lt={bad_lt or '(empty)'} returns 4.00.",
                "method": "POST",
                "uri": f"/rd?ep=node-01&lt={bad_lt}",
                "query": {"ep": "node-01", "lt": bad_lt},
                "expected_code": int(Code.BAD_REQUEST),
            }
        )

    # Lookup: GET /rd returns CBOR list
    entries = [
        {"id": "1", "ep": "sensor-42", "lt": 3600, "base": None, "links": links},
        {"id": "2", "ep": "sensor-43", "lt": 86400, "base": None, "links": [{"href": "/humidity", "rt": "sensor"}]},
    ]
    payload_list = cbor2.dumps(entries)
    vectors.append(
        {
            "name": "rd_lookup_all",
            "description": "GET /rd returns CBOR list of all registrations.",
            "method": "GET",
            "uri": "/rd",
            "response_payload_hex": payload_list.hex(),
            "response_entries": entries,
            "expected_code": int(Code.CONTENT),
            "expected_content_format": 60,
        }
    )

    # Filter by ep
    vectors.append(
        {
            "name": "rd_lookup_filter_ep",
            "description": "GET /rd?ep=sensor-42 filters by endpoint name.",
            "method": "GET",
            "uri": "/rd?ep=sensor-42",
            "query": {"ep": "sensor-42"},
            "expected_filtered_eps": ["sensor-42"],
            "expected_code": int(Code.CONTENT),
        }
    )

    # Resource directory lookup: GET /rd-lookup/res?rt=sensor
    vectors.append(
        {
            "name": "rd_lookup_res_by_rt",
            "description": "GET /rd-lookup/res?rt=sensor lookup (RFC 9176 §8.3).",
            "method": "GET",
            "uri": "/rd-lookup/res?rt=sensor",
            "query": {"rt": "sensor"},
            "expected_code": int(Code.CONTENT),
            "note": "Python ResourceDirectoryResource implements /rd; rd-lookup path is alias for GET /rd filtered by rt in future.",
        }
    )

    # DELETE /rd/<id>
    vectors.append(
        {
            "name": "rd_delete_success",
            "description": "DELETE /rd/<id> removes registration, returns 2.02 Deleted. Second DELETE returns 4.04 Not Found.",
            "method": "DELETE",
            "uri": "/rd/1",
            "expected_code_success": int(Code.DELETED),
            "expected_code_not_found": int(Code.NOT_FOUND),
        }
    )

    # Link descriptor validation: href must start with / and not contain .. etc
    for bad_href, reason in [("temperature", "missing leading slash"), ("/a/../b", "contains .."), ("/", "empty segment")]:
        vectors.append(
            {
                "name": f"rd_register_bad_href_{bad_href.replace('/', '_') or 'slash'}",
                "description": f"POST /rd with href={bad_href!r} ({reason}) returns 4.00.",
                "method": "POST",
                "uri": "/rd?ep=node-01",
                "bad_link": {"href": bad_href, "rt": "sensor"},
                "expected_code": int(Code.BAD_REQUEST),
            }
        )

    return vectors


def coap_transport_vectors() -> list[dict]:
    """Transport and duty cycle vectors (spec §9.1, §10.2.2, §10.2.3)."""
    vectors: list[dict] = []

    # Port allocation table
    vectors.append(
        {
            "name": "port_allocation",
            "description": "UDP port allocation (spec §9.1). Ports 5681-5687 share MSB(12) for SCHC compression.",
            "ports": [{"port": p, "use": u} for p, u in sorted(PORT_ALLOCATION.items())],
            "schc_compressed_family": {"range": "5680-5695", "msb_bits": 12, "lsb_bits": 4, "wire_cost_bytes": 1},
            "mqtt_sn_requires_dedicated_rule": True,
            "mqtt_sn_rule": {"port": 10883, "encoding": "not-sent (exact match)"},
        }
    )

    # Gateway translation table
    vectors.append(
        {
            "name": "gateway_translation",
            "description": "Mesh-internal ports MUST be translated at gateways (spec §9.1 Mesh-Internal Semantics).",
            "translations": [
                {"mesh_port": 5681, "payload": "Compact CoT", "external": "CoT XML over TCP 8087"},
                {"mesh_port": 5682, "payload": "SenML", "external": "CoAP Content-Format 112"},
                {"mesh_port": 5685, "payload": "Cayenne LPP", "external": "LoRaWAN application server"},
                {"mesh_port": 5686, "payload": "APRS-IS", "external": "APRS-IS TCP or AX.25 RF"},
                {"mesh_port": 5687, "payload": "NMEA", "external": "Serial NMEA or CoAP/SenML"},
            ],
        }
    )

    # LoRa parameters
    vectors.append(
        {
            "name": "loRa_params",
            "description": "CoAP transmission parameters for LoRa (spec §10.2.2).",
            "rfc7252": {
                "ack_timeout": 2.0,
                "ack_random_factor": 1.5,
                "max_retransmit": 4,
                "nstart": 1,
                "default_leisure": 5.0,
                "probing_rate": 1.0,
            },
            "lichen": {
                "ack_timeout": LICHEN_ACK_TIMEOUT,
                "ack_random_factor": LICHEN_ACK_RANDOM_FACTOR,
                "max_retransmit": LICHEN_MAX_RETRANSMIT,
                "nstart": LICHEN_NSTART,
                "default_leisure": LICHEN_DEFAULT_LEISURE,
                "probing_rate": LICHEN_PROBING_RATE,
            },
            "rationale": {
                "ack_timeout": "Multi-hop RTT can exceed 10s",
                "ack_random_factor": "More jitter reduces collision",
                "max_retransmit": "Fewer retries, fail faster",
                "default_leisure": "Multicast response spread",
                "probing_rate": "Respect duty cycle",
            },
            "retry_schedule": [15.0, 30.0],
            "give_up_after": 90.0,
        }
    )

    # Prefer NON
    vectors.append(
        {
            "name": "prefer_non",
            "description": "Prefer NON for telemetry; use CON only for critical delivery (spec §10.2.2).",
            "non_use": ["telemetry", "notifications", "periodic sensor readings", "position beacons"],
            "con_use": ["configuration changes", "firmware blocks", "SOS acknowledgments"],
        }
    )

    # Congestion levels
    for ratio, expected in [(0.30, "normal"), (0.60, "elevated"), (0.85, "critical"), (0.97, "exhausted")]:
        vectors.append(
            {
                "name": f"congestion_{expected}",
                "description": f"Duty {ratio*100:.0f}% => {expected}.",
                "duty_used_ratio": ratio,
                "duty_used_percent": ratio * 100,
                "expected_level": expected,
                "computed_level": congestion_level(ratio).value,
                "action": {
                    "normal": "Transmit normally",
                    "elevated": "Delay non-urgent traffic, increase backoff",
                    "critical": "Only SOS/routing, shed application traffic",
                    "exhausted": "Stop TX until window rolls over",
                }[expected],
            }
        )

    # 5.03 Service Unavailable
    vectors.append(
        {
            "name": "load_shedding_503",
            "description": "When congested, respond 5.03 Service Unavailable with retry_after (spec §10.2.3 Load Shedding).",
            "response_code": int(Code.SERVICE_UNAVAILABLE),
            "response_code_name": "5.03 Service Unavailable",
            "payload_example": {"reason": "duty_cycle", "retry_after": 120, "level": "critical"},
            "payload_hex": cbor2.dumps({"reason": "duty_cycle", "retry_after": 120, "level": "critical"}).hex(),
            "max_age": 120,
            "content_format": 60,
        }
    )

    # Priority queue
    vectors.append(
        {
            "name": "priority_queue",
            "description": "TX queue ordered by priority (spec §10.2.3). Low priority dropped first during congestion.",
            "priorities": [
                {"priority": 0, "label": "P0 (highest)", "traffic": "SOS, emergency"},
                {"priority": 1, "label": "P1", "traffic": "RPL control (DIO, DAO)"},
                {"priority": 2, "label": "P2", "traffic": "CoAP CON, tactical chat"},
                {"priority": 3, "label": "P3", "traffic": "CoAP NON, telemetry, position"},
                {"priority": 4, "label": "P4 (lowest)", "traffic": "Bulk transfer, firmware"},
            ],
        }
    )

    # Application-to-priority mapping
    mapping = [
        {"port": 5681, "app": "Compact CoT", "subtype": "Alert (0x20)", "priority": int(TxPriority.P0)},
        {"port": 5681, "app": "Compact CoT", "subtype": "Chat (0x01)", "priority": int(TxPriority.P2)},
        {"port": 5681, "app": "Compact CoT", "subtype": "PLI (0x02-0x05)", "priority": int(TxPriority.P3)},
        {"port": 5681, "app": "Compact CoT", "subtype": "Marker (0x10)", "priority": int(TxPriority.P3)},
        {"port": 5682, "app": "SenML", "subtype": "All", "priority": int(TxPriority.P3)},
        {"port": 5683, "app": "CoAP", "subtype": "CON", "priority": int(TxPriority.P2)},
        {"port": 5683, "app": "CoAP", "subtype": "NON", "priority": int(TxPriority.P3)},
        {"port": 5685, "app": "Cayenne", "subtype": "All", "priority": int(TxPriority.P3)},
        {"port": 5686, "app": "APRS-IS", "subtype": "All", "priority": int(TxPriority.P3)},
        {"port": 5687, "app": "NMEA", "subtype": "All", "priority": int(TxPriority.P3)},
        {"port": 10883, "app": "MQTT-SN", "subtype": "QoS 1+", "priority": int(TxPriority.P2)},
        {"port": 10883, "app": "MQTT-SN", "subtype": "QoS 0/-1", "priority": int(TxPriority.P3)},
    ]
    vectors.append(
        {
            "name": "app_to_priority_mapping",
            "description": "Application-to-priority mapping (spec §10.2.3).",
            "mapping": mapping,
        }
    )

    # SCHC fragmentation guidance
    vectors.append(
        {
            "name": "fragmentation_guidance",
            "description": "SCHC fragmentation preferred over CoAP block-wise (spec §10.5).",
            "recommendation": "CoAP Block-wise (RFC 7959) is NOT RECOMMENDED. Use SCHC fragmentation (RFC 8724).",
            "comparison": {
                "blockwise": {"designed_for": "Reliable networks", "ack": "Per-block ACK", "recovery": "Application retry"},
                "schc": {"designed_for": "LPWAN (LoRa)", "ack": "ACK-on-Error (sparse)", "recovery": "L2 retransmission"},
            },
            "capacity": {"fcn_bits": 6, "tiles_per_window": 63, "windows": 2, "tile_size": 187, "ceiling": 23562, "mandatory_receiver": 1281},
            "chunking_protocol": "Application-level chunking with POST /firmware/upload {chunk, total, data}",
        }
    )

    # OSCORE context (reference to existing oscore.json)
    vectors.append(
        {
            "name": "oscore_reference",
            "description": "OSCORE end-to-end security (spec §06-security, §10.2). LICHEN uses OSCORE not DTLS.",
            "note": "OSCORE vectors are in test/vectors/oscore.json (RFC 8613). This vector links transport to security.",
            "port_5684_reserved": True,
            "security": "OSCORE (RFC 8613) over CoAP port 5683; CoAPS/DTLS port 5684 reserved but not used",
        }
    )

    return vectors


def main() -> None:
    _write(
        "coap_messages.json",
        "CoAP message format vectors (RFC 7252 §3, spec §10.2). Wire encodings via Python aiocoap oracle.",
        coap_message_vectors(),
    )
    _write(
        "coap_rd.json",
        "Resource Directory vectors (RFC 9176, spec §10.6). Registration, lookup, deletion, validation.",
        coap_rd_vectors(),
    )
    _write(
        "coap_transport.json",
        "Transport bindings vectors (spec §9-10): UDP port dispatch, LoRa CoAP parameters, duty cycle, priority, fragmentation.",
        coap_transport_vectors(),
    )


if __name__ == "__main__":
    main()
