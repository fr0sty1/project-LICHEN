<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# LICHEN Test Vectors

Language-neutral conformance vectors for the LICHEN protocol using **format_version=2** strict schema. The **Python prototype is the source of truth**; Rust, C, and Zephyr implementations MUST validate against these files (issue ajr, gate ijj). Schema enforces one vector family per file with dedicated ccp15/ccp_load_balancing_document defs.

## Files

| File | Covers |
|------|--------|
| `schema.json` | v2-only JSON Schema (draft-07); const format_version=2, per-family docs, no legacy envelope |
| `schc_compression.json` | SCHC whole-packet compression (RFC 8724), rules 0–4 + ICMPv6/UDP malformed (invalid source, bad type, checksum, length; RFC 4443) |
| `schc_fragment.json` | SCHC fragmentation (RFC 8724 §8): single/multi, window, ACK-on-error, MIC fail, OOO, retransmit (independent RFC oracles) |
| `l2_payload.json` | Authenticated L2 inner-payload dispatch wrapping SCHC and routing/control bodies |
| `link_frame.json` | LICHEN link-layer frame encoding (spec section 4) |
| `announce_coords.json` | Announce app_data Type=0x01 geographic coordinate encoding |
| `meshtastic_app_compat.json` | Meshtastic BLE raw-protobuf app compatibility exchanges |
| `meshcore_app_compat.json` | MeshCore byte-command app compatibility exchanges |
| `ccp_load_balancing.json` | TDMA slot assignment (static hash), guard time boundaries (50ms), drift compensation, CCP-16 load metrics/rebalancing (independent mathematical oracles from spec timing/hash formulas) |
| `ccp13.json` | CCP-13 DutyCycleTracker (prune, window eviction, partial overlap proration, remaining_ms, usage_permille, can_transmit, next_available_ms with u64::MAX for impossible). Independent math oracles matching Rust, C, Python sim. |
| `ccp15.json` | CCP-15 CCA threshold, interference score (busy_pct + PER*100), frequency agility (lowest score channel), SF adaptation (PER>0.2), TDMA CCA guard integration (independent mathematical oracles per spec 02a) |
| `ccp16-desync.json` | CCP-16 desync transitions, SFN wrap, multi-root conflict, clock drift recovery using bare array root (v2 schema). Independent oracles from spec 02a and 09-packets-timing.md. |
| `ccp9.json` | CCP-9 rendezvous mechanisms (rx_channel scheduling, CH0 control fallback for unknown peers, synchronized_hop_channel(CCP-12) override of announce rendezvous, announce channel field parse/roundtrip in L2 payload). Independent mathematical oracles from spec/02a-coordinated-capacity.md §CCP-9, da2q multi-channel context, and python/src/lichen/sim/medium.py. Matches ccp9_vectors() in generate.py. |
| `deaddrop.json` | /deaddrop DTN store-and-forward (POST/GET, OSCORE-wrapped, SenML payloads). Independent RFC 7252/8613/8428 oracles aligned with oscore.json. No code-under-test oracle.

All byte strings are lowercase hex (possibly empty). Schema validation and independent oracles used in tests.

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
- A vector with `expect.error` is negative: decoding `encoded` MUST reject it,
  and encoders MUST NOT emit it.

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

**CCP-16 Load Balancing** (`ccp16.json`): for each vector (spec/02a-coordinated-capacity.md:36, da2q context),
- TDMA slot = (crc32(EUI64) ^ epoch) % num_slots, adaptive_sf_select(density, snr_ema, load), now() for timing.
- Includes multi-RX gateway, SF thresholds, modulo/wrap (0xFFFFFFFF edge), desync. Matches generate.py + test_vectors.py.
- Python/Rust/Zephyr MUST match vectors exactly (no oracle weakening).

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

**CCP-16 vectors** (`ccp*.json`): for coordinated capacity planning, density, TDMA slot selection, load balancing, desync recovery. Uses `hash_32` (FNV-1a) primitive. ccp16-desync.json uses bare array root for v2 schema; others use object envelope. Schema updated with `type`, `expected_hash`, fixed allOf conditionals for type discriminator, ccp_load_balancing_vector fields, and Rust no_std compatible notes. Cleanup of magic numbers and features completed.

**RAK2287 vectors** (`rak2287*.json`): test fixtures for packet formats, UDP forwarder protocol, multi-channel demod. Ensures cross-impl interop with SX126x paths in mesh-gateway, Python sim, and Rust tests. Updated schema and generate.py.

## Regenerating

```
PYTHONPATH=python/src python3 test/vectors/generate.py
cd python
uv run --extra dev python ../test/vectors/generate_dao_origin_signature.py
uv run --extra dev python ../test/vectors/generate_dao_origin_signature.py --check
cd ..
python3 test/vectors/generate_rpl_route_state.py
python3 test/vectors/generate_rpl_route_state.py --check
```

The Python suite validates schema, structure, relations, hashes, and signatures:

```sh
cd python && uv run --extra dev pytest tests/test_vectors.py
```
