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
| `dao_origin_signature.json` | End-to-end DAO origin signatures, mutation rejection, and replay metadata |
| `generate_dao_origin_signature.py` | Deterministic DAO origin-vector generator using the Python Schnorr48 implementation |
| `dao_origin_signature_oracle.c` | Independent offline SHA-512/Schnorr48 checker using C/Monocypher |

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

**DAO Origin Signature** (`dao_origin_signature.json`):
- `vector_type=dao_origin_signature` selects the closed dedicated document schema; prose descriptions are not discriminants.
- The option is `type=0x12`, `length=0x38`, then an unsigned 64-bit big-endian origin sequence and a 48-byte Schnorr48 signature.
- The SHA-512 input is ASCII `LICHEN-DAO-ORIGIN-v1` with no NUL, followed by the 16-byte origin IPv6 address, effective 16-byte DODAGID, sequence, and exact unsigned DAO bytes.
- For D=0, `effective_dodag_id` is receiver context; for D=1 it matches the DODAGID carried in the DAO.
- The option occurs exactly once and is final. `option_offset` identifies its insertion point in `unsigned_dao`.
- Strict signed DAO envelopes reject unknown RPL options even when the transcript signature is valid.
- Canonical `.44.7` vectors use a key-derived ULA origin and the exact same address as one self `/128` Target. Prefix lengths below 128, Target Descriptors, canonicalization, and external `E=1` behavior belong to future `.44.9` work.
- `prior` describes the previously accepted transcript and whether volatile route state survived. RX persistence contains only the stable-key sequence/digest floor. An equal exact retransmission does not rewrite that floor and may reconcile missing route state after a crash.
- Replay state follows the pinned public key across IPv6 prefix changes, not the complete source address.
- `effective_instance_id`, `active_dodag_id`, and `effective_dodag_id` distinguish receiver context from the signed transcript. `.44.7` requires exactly one `/128` Target whose 16 octets equal the preserved source, even when another Target has a valid signature.
- `expected.signature_valid` is cryptographic validity independent of structural, trust, IID-binding, and replay checks.
- `expected.route_changed` and `expected.replay_persisted` distinguish fresh application, no-op duplicate handling, and post-crash route reconciliation.
- Decision order is structural/context, key/IID/signature, replay, semantics including exact self-Target validation, persistence, then atomic in-memory route mutation.

Signatures are generated by the PyNaCl/libsodium implementation in `python/src/lichen/crypto/schnorr48.py`. The committed C oracle independently recomputes every digest with Monocypher SHA-512, verifies every signature expectation, and reproduces each valid deterministic signature with the C Schnorr48 implementation:

```sh
cd python && uv run --extra dev python ../test/vectors/generate_dao_origin_signature.py
cd ..
cc -std=c11 -O2 -Wall -Wextra -Werror -DCONFIG_LICHEN_CRYPTO_MONOCYPHER -Ilichen/subsys/lichen/link/include -Ilichen/subsys/lichen/crypto test/vectors/dao_origin_signature_oracle.c lichen/subsys/lichen/link/schnorr48.c lichen/subsys/lichen/crypto/monocypher.c lichen/subsys/lichen/crypto/monocypher-ed25519.c -o /tmp/dao-origin-oracle
/tmp/dao-origin-oracle test/vectors/dao_origin_signature.json
cargo test --manifest-path rust/Cargo.toml -p lichen-node --features std --test dao_origin_vectors
```

`python/tests/test_vectors.py` is a secondary structural/crypto check. There is currently no production Python DAO-origin codec, so that test does not claim Python production compatibility.

## Regenerating

```
PYTHONPATH=python/src python3 test/vectors/generate.py
cd python && uv run --extra dev python ../test/vectors/generate_dao_origin_signature.py
```

The Python suite validates schema, structure, relations, hashes, and signatures:

```sh
cd python && uv run --extra dev pytest tests/test_vectors.py
```
