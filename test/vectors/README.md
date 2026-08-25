<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# LICHEN Test Vectors

Language-neutral conformance vectors for the LICHEN protocol using **format_version=2** strict schema. The **Python prototype is the source of truth**; Rust, C, and Zephyr implementations MUST validate against these files (issue ajr, gate ijj). Schema enforces one vector family per file with dedicated ccp15/ccp_load_balancing_document defs.

## File Index

Complete index of every vector file (112 files). Byte strings are lowercase hex (possibly empty).

### Schema

| File | Covers |
|------|--------|
| `schema.json` | Combined v2-only JSON Schema envelope (draft-07; const format_version=2, per-family docs, no legacy envelope) |

### Crypto & Identity

| File | Covers |
|------|--------|
| `edhoc.json` | EDHOC interop (Python initiator/responder with fixed seeds as reference) |
| `hash_32.json` | `lichen_hash_32` FNV-1a32 primitive (basis 0x811c9dc5) |
| `oscore.json` | OSCORE key derivation, request/response protection, replay detection (RFC 8613) |
| `schnorr48.json` | 48-byte Schnorr signatures per draft-lichen-schnorr-00 (Appendix A vectors) |
| `x25519.json` | X25519/Ed25519 key derivation and RFC 8032 clamping |

### Link Layer

| File | Covers |
|------|--------|
| `epoch_rollover.json` | Replay protection across link-layer epoch rollover (spec 4.4) |
| `frame_length_boundaries.json` | Frame body length boundary enforcement (spec 02 §4.1) |
| `l2_payload.json` | Authenticated L2 inner-payload dispatch (0x14=SCHC, 0x15=routing) |
| `link-addressing.json` | Link-layer addressing modes incl. elided-context derivation (spec 4.3) |
| `link-edge-fuzz.json` | Malformed LLSec / truncated-signature edge+fuzz hardening (spec 4.x) |
| `link_frame.json` | Link-layer frame encode/decode roundtrip (spec 4, draft-lichen-link-01) |
| `mic_length_selector.json` | LLSec MIC-length selector bits 2–4 semantics (spec 02 §4.2) |
| `replay_window.json` | 32-slot anti-replay window and 24-bit logical counter (spec 4.4) |
| `short_addr_dad.json` | Short-address assignment + CRC32 DAD (spec 02 §4.5, 04 §12.3) |

### SCHC

| File | Covers |
|------|--------|
| `rule_versioning.json` | SCHC Rule Version Option serialization in DIO (spec 5.7) |
| `schc_adaptation.json` | Unknown rule IDs, Rule 255 uncompressed fallback, port behavior |
| `schc_compression.json` | Whole-packet compression rules 0–4 + malformed cases (RFC 8724) |
| `schc_fragment.json` | Generic fragmentation-codec exercises per RFC 8724 §8, including deliberately non-profile toy parameters, with a zlib CRC-32 oracle |
| `schc_fragmentation.json` | Normative Rule Set Version 3 LICHEN fixed-profile ACK-on-Error bytes and state transitions, independently hand-derived |

### IPv6 / RPL / Routing

| File | Covers |
|------|--------|
| `dad_hash_clarification.json` | DAD hash algorithm disambiguation (two readings of spec 4.5) |
| `dao_origin_signature.json` | Shared DAO Origin Signature conformance (v2 schema) |
| `gradient_entry.json` | Gradient table entry ranking/comparison order (spec 11) |
| `ipv6-addresses.json` | Pubkey → IID → fe80::/10 and primary/native address derivation |
| `ipv6-icmpv6.json` | ICMPv6 Echo/errors with pseudo-header checksum (RFC 4443, spec 6.4) |
| `ipv6_malformed.json` | Malformed IPv6/ICMPv6/UDP rejection (RFC 8200/4443/768) |
| `loadng.json` | LOADng 16-bit sequence-number wrap-aware freshness (RFC 1982) |
| `loadng_discovery.json` | LOADng discovery state-machine transitions (spec 10.3–10.5, B2.6) |
| `loadng_messages.json` | LOADng RREQ/RREP/RERR message encoding (spec 10.3/10.4/10.6) |
| `root_authorization.json` | DODAGID == AddrForKey(root_pubkey) binding (spec 8.2, 8.4) |
| `root_signature.json` | Root-signature verification of RPL DIO (spec 8.2, 8.4) |
| `rpl_messages.json` | RPL DIS/DIO/DAO/DAO-ACK message encodings (RFC 6550, hardcoded independent vectors) |
| `rpl_multi_instance.json` | Multi-instance RPL coordination (GCP-5) |
| `rpl_route_state.json` | Post-provenance DAO route-state transitions from fixed option bytes |
| `source_route_hop_limit.json` | RFC 6554 source-route Segment Left/hop-limit validation |

### Coordinated Capacity (CCP / TDMA)

| File | Covers |
|------|--------|
| `ccp-interference.json` | CCP-15 interference score (busy_pct + PER·100) and backoff jitter |
| `ccp13.json` | CCP-13 DutyCycleTracker (prune, proration, usage_permille, can_transmit) |
| `ccp15.json` | CCP-15 SF EMA load_factor via hash_32/FNV-1a (spec 02a) |
| `ccp16-desync.json` | Desync transitions, u32 SFN wrap arithmetic, multi-root conflict, drift recovery |
| `ccp16-hop.json` | CCP-12 synchronized-hop SelectChannel pseudocode match (spec 02a:120) |
| `ccp16.json` | CCP-16 synchronized hopping/desync incl. now_ts and select_channel_timing |
| `ccp16_ema_loss_threshold.json` | EMA packet-loss threshold boundary (spec 02 §3.5) |
| `ccp16_utilization.json` | Channel utilization and tx_allowed decisions (spec 02 §3.5) |
| `ccp4_regional_channel_plans.json` | Regional channel-plan selection (spec 02a:167-182) |
| `ccp9-rendezvous.json` | CCP-9 rendezvous from da2q context: scheduler rx_channel, beacon/DIO assignment, CH0 fallback (**content-overlaps `ccp9_rendezvous.json`; consolidation is a human call**) |
| `ccp9.json` | CCP-9 rendezvous exact wire format via `_l2_announce_with_channel` oracle |
| `ccp9_rendezvous.json` | CCP-9 rendezvous via hash_32(FNV-1a) oracle (**content-overlaps `ccp9-rendezvous.json`**) |
| `ccp_beacon_format.json` | Exact beacon header layout and canonical SFN-rotating TDMA slots |
| `ccp_beacon_sig_gate.json` | Signature verification MUST precede DIO processing |
| `ccp_ema_update_integer.json` | Integer EMA update for adaptive SF (spec 02 §3.x) |
| `ccp_load_balancing.json` | Load balancing + TDMA slot assignment, guard-time/drift math oracles |
| `ccp_select_channel_endianness.json` | select_channel EUI64 big-endian concat + modulo checks |
| `ccp_sfn_wrap_slot_hash.json` | slot_for() across SFN wraparound (spec 14.7) |
| `ccp_slot_map_validation.json` | slot_map CBOR array validation (spec 02a:80) |
| `ccp_tdma.json` | Independent TDMA slot assignment via FNV-1a32 |
| `sf_assignment.json` | Stateless hash-based fallback SF assignment (spec 02 §3.4) |
| `sync_hop.json` | CCP-12 GNSS-synchronized frequency hopping (FNV-1a32) |

### Gateway Coordination (GCP)

| File | Covers |
|------|--------|
| `gateway_coordination.json` | GCP overall: discovery, coordination, handoff (spec 08) |
| `gateway_discovery.json` | GCP-4 backbone multicast + LoRa fallback discovery |
| `gcp_iid_comparison.json` | IID comparison/conflict-resolution algorithm (GCP-6.3) |
| `gcp_psk_oscore.json` | PSK-based OSCORE HKDF derivation intermediates (RFC 8613) |
| `gcp_slot_claim.json` | Slot-claim message Schnorr48 signing over CBOR-canonical form |
| `gcp3_trust_models.json` | GCP-3 trust models (pubkey-derived keys, PSK, hybrid) |
| `gcp6_slot_coordination.json` | Superframe slot coordination (spec 08 §6) |
| `node_handoff.json` | Node-handoff request/response (GCP-7) |

### CoAP / LCI / Applications

| File | Covers |
|------|--------|
| `coap_lci_auth.json` | LCI authorization (`is_local_admin`) for mutable resources (spec 17) |
| `coap_messages.json` | CoAP message wire formats (RFC 7252 §3, aiocoap oracle) |
| `coap_observe_sequence.json` | Observe 24-bit sequence rollover/reordering (RFC 7641 §4.4) |
| `coap_option_malformed.json` | Option delta/length overflow and reserved values (RFC 7252 §3.1) |
| `coap_rd.json` | Resource Directory register/lookup/delete (RFC 9176, spec 10.6) |
| `coap_token_validation.json` | Token TKL bounds and semantics (RFC 7252 §3) |
| `coap_transport.json` | Transport bindings: UDP dispatch, LoRa CoAP params, duty cycle (spec 9–10) |
| `compact_cot.json` | Compact CoT binary PLI encoding (spec 07 §10.1.1) |
| `confessions.json` | /confessions anonymous board resource (LCI) |
| `confessions_rate.json` | Confessions rate limits: 1/30s and 12/hr (spec 18.10.3) |
| `deaddrop.json` | /deaddrop DTN store-and-forward, OSCORE-wrapped SenML (RFC 7252/8613/8428) |
| `keystore_iid.json` | Keystore IID format/path validation (LCI 17.5.5) |
| `messaging.json` | Messaging /msg/inbox POST, /msg/sent GET, /msg/ack POST exchanges incl. rejects (LCI 17.5.7, spec 18.1) |
| `neighbors_cbor.json` | GET /status/neighbors CBOR encoding (spec 8.4) |
| `position_privacy_auth.json` | Position-sharing public/group/private auth modes (spec 18.1) |
| `presence_cbor.json` | Presence/presence-cache CBOR encoding (spec 18.5.1) |
| `rangetest.json` | Range testing: /diag/rangetest POST/GET and /diag/traceroute (spec 18.7) |
| `raw_diag_ttl.json` | Raw-diagnostic TTL arming/auto-disable (LCI 17.5.4) |
| `receipt_cbor.json` | Delivery-receipt CBOR fields id/status/ts (spec 18.1.2) |
| `ipso_smart_objects.json` | IPSO object/instance/resource SenML names and CBOR records (appendix-senml F.2.1) |
| `senml_location.json` | SenML location profile (spec appendix-senml F.3) |
| `slip_framing.json` | SLIP (RFC 1055) framing for LCI serial transport |
| `sos_cbor.json` | SOS alert full-field CBOR encoding (spec 18.4.2) |
| `sos_rate_limiting.json` | SOS limits: 10-min cooldown, 3/hr, burst 2 (spec 18.3) |
| `sos_signature.json` | SOS signature verification; unsigned/invalid silently dropped (spec 18.3) |
| `waypoint.json` | Waypoint CBOR encoding (ordered map, spec 18.3.1) incl. truncated-CBOR rejects |

### Announce

| File | Covers |
|------|--------|
| `announce_coords.json` | Announce app_data Type=0x01 lat/lon e7 big-endian encoding |
| `announce_signed_data.json` | Announce signed_data transcript format (CCP-9, spec 05 §9.2) |

### App Compatibility

| File | Covers |
|------|--------|
| `meshcore_app_compat.json` | MeshCore byte-command exchanges (BLE inner frames + serial markers) |
| `meshtastic_app_compat.json` | Meshtastic BLE raw-protobuf GATT exchanges incl. sync stages |

### Bufferbloat / Queue Management

| File | Covers |
|------|--------|
| `forwarding_buffer.json` | B.3.2 forwarding buffer per-source bounds (appendix-bufferbloat) |
| `no_silent_drops.json` | B.2.5 drops must be explicit and counted |
| `tx_queue_bounded.json` | B.2.1 bounded TX queue capacity and priority order |
| `tx_queue_expiry.json` | B.2.2 time-based packet expiry/deadline |
| `tx_queue_implementation.json` | B.3.1 TX queue implementation oracle |
| `tx_queue_priority.json` | B.2.3 priority queuing, preemption, scheduling |

### Forwarding / Multicast / Misc Policy

| File | Covers |
|------|--------|
| `br_multicast_filter.json` | BR must not forward mesh multicasts to internet (spec 6.3.4) |
| `broadcast_rate_limiting.json` | Hop-aware per-sender broadcast budgets (spec 6.3.3) |
| `forwarding.json` | Mesh↔internet forwarding decisions |
| `group_oscore_key.json` | Group OSCORE key distribution, key_epoch, 1-hr grace (spec 18.6) |

### Addressing / Node Identity

| File | Covers |
|------|--------|
| `node-addresses.json` | Human-readable node addresses, canonical set (**content-overlaps `node_address.json`**) |
| `node_address.json` | Base32-from-SHA-512(pubkey[:8]) 13-char node address (**content-overlaps `node-addresses.json`**) |
| `yggdrasil-derivation.json` | Seed→address derivation matched across Rust/C/Python |
| `yggdrasil.json` | `ygg_addr_from_pubkey` spot vectors (e.g. SHA-256(b"") key) |
| `yggdrasil_address.json` | Native Yggdrasil-range derivation corpus: verbatim upstream Go `AddrForKey` anchor (divergence pinned) + LICHEN SHA-512 profile cases incl. length-rejections |

### Simulation Models

| File | Covers |
|------|--------|
| `lr_fhss.json` | LR-FHSS airtime model (2× standard LoRa airtime) for simulator |
| `lr_fhss_capability.json` | LR_FHSS_SUPPORTED capability exchange in gateway DIO (spec 02 §3.7) |
| `packets-formats.json` | Packets/timing wire formats (spec 09 §13, Python oracle) |
| `packets-timing.json` | Trickle, DAO, duty cycle, airtime, CSMA, time sync (spec 09 §14) |
| `propagation.json` | LoRa propagation model: path loss, RX power, SNR, range, budget |

## How to validate (any implementation)

**SCHC** (`schc_compression.json`): for each vector,
- `compress(hex_decode(packet))` MUST equal `hex_decode(compressed)`, and
- `decompress(hex_decode(compressed))` MUST equal `hex_decode(packet)`.
- The first byte of `compressed` equals `rule_id`.
- This curated corpus is not emitted by `generate.py`; the small
  `schc_vectors()` helper there supplies construction inputs to other vector
  families and is not a complete builder for this file.

**SCHC fragmentation** (`schc_fragmentation.json`, `schc_fragment.json`):
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
  with non-LICHEN CRC-32 and SHA-256 implementations. Neither file is emitted
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
- TDMA slot = `(FNV1a32(EUI64) + u32(SFN)) mod num_slots`, adaptive_sf_select(density, snr_ema, load), now() for timing.
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

**CCP vectors** (`ccp*.json`): for coordinated capacity planning, density, TDMA slot selection, load balancing, desync recovery. Uses `hash_32` (FNV-1a) primitive. ccp16-desync.json uses bare array root for v2 schema; others use object envelope. Schema updated with `type`, `expected_hash`, fixed allOf conditionals for type discriminator, ccp_load_balancing_vector fields, and Rust no_std compatible notes. Cleanup of magic numbers and features completed.

## Regenerating

```
PYTHONPATH=python/src python3 test/vectors/generate.py link_frame.json
# Bulk regeneration is intentionally guarded because it overwrites local files:
PYTHONPATH=python/src python3 test/vectors/generate.py --all --yes-regenerate-all
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
