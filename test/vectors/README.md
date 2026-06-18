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

## Regenerating

```
PYTHONPATH=python/src python3 test/vectors/generate.py
```

The Python suite re-derives every vector and fails on drift:

```
cd python && PYTHONPATH=src python3 -m pytest tests/test_vectors.py
```
