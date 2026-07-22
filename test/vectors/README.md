<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# LICHEN Test Vectors

Language-neutral conformance vectors for the LICHEN protocol. The **Python
prototype is the source of truth**; the Rust and C implementations MUST validate
against these files (issue `ajr`, gate `ijj`).

## Files

| File | Covers |
|------|--------|
| `schema.json` | JSON Schema (draft-07) for the envelope and vector shapes |
| `schc_compression.json` | SCHC whole-packet compression (RFC 8724), rules 0–4 |
| `l2_payload.json` | Authenticated L2 inner-payload dispatch wrapping SCHC and routing/control bodies |
| `link_frame.json` | LICHEN link-layer frame encoding (spec section 4) |
| `announce_coords.json` | Announce app_data Type=0x01 geographic coordinate encoding |
| `meshtastic_app_compat.json` | Meshtastic BLE raw-protobuf app compatibility exchanges |
| `meshcore_app_compat.json` | MeshCore byte-command app compatibility exchanges |
| `ccp15.json` | CCP-15 coordinated capacity, adaptive SF, density, hash_32, EMA (v2) |
| `ccp16.json` | CCP-16 load balancing, TDMA slot, now()/select_channel (v2) |
| `ccp16-desync.json` | CCP-16 desynchronization/recovery vectors (v2 bare array root example). Independent oracle vs ccp15.json. Top-level comment/docs via description in vectors. |

All byte strings are lowercase hex (possibly empty).

## How to validate (any implementation)

**SCHC** (`schc_compression.json`): for each vector,
- `compress(hex_decode(packet))` MUST equal `hex_decode(compressed)`, and
- `decompress(hex_decode(compressed))` MUST equal `hex_decode(packet)`.
- The first byte of `compressed` equals `rule_id`.

**Link frames** (`link_frame.json`): for each vector,
- encoding a frame built from `fields` MUST equal `hex_decode(encoded)`, and
- decoding `hex_decode(encoded)` MUST reproduce `fields`.
- A vector with `expect.error` is negative: decoding `encoded` MUST reject it,
  and encoders MUST NOT emit it.

`addr_mode`: 0=none/broadcast, 1=16-bit short, 2=EUI-64, 3=elided.
`mic_length`: 0=32-bit, 1=64-bit.

**L2 payload dispatch** (`l2_payload.json`): for each vector,
- `wrapped` is the authenticated link inner payload.
- Byte 0 of `wrapped` MUST equal `dispatch`.
- `body` MUST equal the bytes after the dispatch byte.
- `kind=schc` uses dispatch `0x14`; `kind=routing` uses dispatch `0x15`.
  An unwrapped payload beginning with `0x01` is `unknown`, not announce.

**Announce coordinates** (`announce_coords.json`): for each vector,
- `encoded` is the complete announce `app_data` value for Type `0x01`.
- Implementations MUST decode `encoded` as `type(1) + lat_e7(4) + lon_e7(4)`,
  where `lat_e7` and `lon_e7` are signed big-endian 32-bit integers.
- Encoding `latitude_degrees` and `longitude_degrees` MUST reproduce `encoded`.

**Meshtastic app compatibility** (`meshtastic_app_compat.json`): for each vector,
- `encoded` is one raw protobuf GATT value unless `expect.reject` is true.
- BLE vectors MUST NOT include the serial/TCP `0x94 0xc3 + length` stream prefix except for rejection cases.
- `source_baseline` records the upstream Meshtastic commits used for field numbers and app behavior.
- Rich sync-stage vectors list required `FromRadio` message kinds in `expect.from_radio_sequence`; implementers MUST
  emit a `config_complete_id` matching the incoming nonce at the end of the stage.
- Implementations should decode `encoded` with their Meshtastic protobuf schema and compare the decoded structure to
  `decoded`; the Python drift test also checks wire types independently of the generator.
- `FromNum` vectors encode the 32-bit queue counter as little-endian bytes. A `FromNum` notification means the app
  should read `FromRadio` repeatedly until it receives the zero-length empty-drain vector.

**MeshCore app compatibility** (`meshcore_app_compat.json`): for each vector,
- BLE/NUS vectors encode one raw MeshCore inner frame in `encoded`: command/response/push byte followed by payload.
- Serial vectors include the outer `0x3c` app-to-device or `0x3e` device-to-app marker, a 16-bit little-endian payload
  length, then the raw inner frame.
- `source_baseline` records the upstream MeshCore firmware/client commits used for command IDs and drift notes.
- `expect.responses` lists exact response frames for deterministic adapter command vectors. Variable fields, such as
  uptime-derived device time, use `expect.response_prefix` and `expect.response_len`.
- Incoming app-event vectors include `MSG_WAITING`, `CHANNEL_MSG_RECV_V3`, and `PUSH_SEND_CONFIRMED` frames used with
  `SYNC_NEXT_MESSAGE`.

## Regenerating

```
PYTHONPATH=python/src python3 test/vectors/generate.py
```

The Python suite re-derives every vector and fails on drift:

```
cd python && PYTHONPATH=src python3 -m pytest tests/test_vectors.py
```
