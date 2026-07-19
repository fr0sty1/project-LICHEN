<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# LICHEN Test Vectors

Language-neutral conformance vectors for the LICHEN protocol. The committed
independently derived literals are the source of truth; Python, Rust, and C
implementations MUST validate against these files. A vector MUST NOT use the
implementation under test to generate its own expected output.

## Files

| File | Covers |
|------|--------|
| `schema.json` | JSON Schema (draft-07) for the envelope and vector shapes |
| `schc_compression.json` | SCHC whole-packet compression (RFC 8724), rules 0–4 |
| `schc_fragmentation.json` | LICHEN Rule Set Version 2 SCHC ACK-on-Error wire, recovery, capacity, and malformed cases |
| `l2_payload.json` | Authenticated L2 inner-payload dispatch wrapping SCHC and routing/control bodies |
| `link_frame.json` | LICHEN link-layer frame encoding (spec section 4) |
| `announce_coords.json` | Announce app_data Type=0x01 geographic coordinate encoding |
| `meshtastic_app_compat.json` | Meshtastic BLE raw-protobuf app compatibility exchanges |
| `meshcore_app_compat.json` | MeshCore byte-command app compatibility exchanges |

All byte strings are lowercase hex (possibly empty).

## How to validate (any implementation)

**SCHC** (`schc_compression.json`): for each vector,
- `compress(hex_decode(packet))` MUST equal `hex_decode(compressed)`, and
- `decompress(hex_decode(compressed))` MUST equal `hex_decode(packet)`.
- The first byte of `compressed` equals `rule_id`.

**SCHC fragmentation** (`schc_fragmentation.json`):
- `packet`, fragment `wire`, ACK, and control values are exact byte strings.
- A byte value is either lowercase literal hex or a `parts` list. A part is
  literal hex or `{"repeat_byte": "aa", "count": N}`; expansion only
  concatenates bytes and MUST NOT calculate protocol fields.
- RCS is CRC-32/ISO-HDLC over the SCHC Packet followed by one zero octet.
- Fragment fields are packed MSB-first and bit-contiguously per Rule Set
  Version 2; bitmap 1 means received and 0 means missing.
- `recovery` and `window_transition` are deterministic transcripts;
  `capacity` checks preflight limits; `malformed` inputs MUST be rejected.
- Expected bytes were hand-derived from RFC 8724 and independently checked
  with non-LICHEN CRC-32 and SHA-256 implementations. This file is not emitted
  by `generate.py`.

**Link frames** (`link_frame.json`): for each vector,
- encoding a frame built from `fields` MUST equal `hex_decode(encoded)`, and
- decoding `hex_decode(encoded)` MUST reproduce `fields`.
- Complete encoded frames MUST be at most 255 bytes, so the leading `LENGTH`
  MUST be at most 254. An unsigned broadcast frame can carry at most 250 payload bytes.
- A vector with `expect.error` is negative: decoding `encoded` MUST reject it,
  and encoders MUST NOT emit it.
- A vector with `crypto` is a deterministic signed-frame oracle. Implementations
  MUST reproduce its keypair, exact preimage, signature, and complete wire bytes.

`addr_mode`: 0=none/broadcast, 1=16-bit short, 2=EUI-64, 3=elided.
`mic_length`: compatibility selector 0 or 1; unsigned frames carry no MIC.

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
