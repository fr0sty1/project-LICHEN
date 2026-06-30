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
| `link_frame.json` | LICHEN link-layer frame encoding (spec section 4) |
| `meshtastic_app_compat.json` | Meshtastic BLE raw-protobuf app compatibility exchanges |

All byte strings are lowercase hex (possibly empty).

## How to validate (any implementation)

**SCHC** (`schc_compression.json`): for each vector,
- `compress(hex_decode(packet))` MUST equal `hex_decode(compressed)`, and
- `decompress(hex_decode(compressed))` MUST equal `hex_decode(packet)`.
- The first byte of `compressed` equals `rule_id`.

**Link frames** (`link_frame.json`): for each vector,
- encoding a frame built from `fields` MUST equal `hex_decode(encoded)`, and
- decoding `hex_decode(encoded)` MUST reproduce `fields`.

`addr_mode`: 0=none/broadcast, 1=16-bit short, 2=EUI-64, 3=elided.
`mic_length`: 0=32-bit, 1=64-bit.

**Meshtastic app compatibility** (`meshtastic_app_compat.json`): for each vector,
- `encoded` is one raw protobuf GATT value unless `expect.reject` is true.
- BLE vectors MUST NOT include the serial/TCP `0x94 0xc3 + length` stream prefix except for rejection cases.
- `source_baseline` records the upstream Meshtastic commits used for field numbers and app behavior.
- Rich sync-stage vectors list required `FromRadio` message kinds in `expect.from_radio_sequence`; implementers MUST
  emit a `config_complete_id` matching the incoming nonce at the end of the stage.
- Implementations should decode `encoded` with their Meshtastic protobuf schema and compare the decoded structure to
  `decoded`; the Python drift test also checks wire types independently of the generator.

## Regenerating

```
PYTHONPATH=python/src python3 test/vectors/generate.py
```

The Python suite re-derives every vector and fails on drift:

```
cd python && PYTHONPATH=src python3 -m pytest tests/test_vectors.py
```
