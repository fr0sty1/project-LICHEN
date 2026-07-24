<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Coordinated Capacity Protocol (CCP)

## Abstract

The Coordinated Capacity Protocol (CCP) defines mechanisms for coordinated capacity management in LICHEN LoRa meshes. This includes TDMA slot assignment, channel agility via select_channel with density-aware fallback, adaptive spreading factor selection via adaptive_sf_select (incorporating EMA-smoothed SNR and load_factor), time synchronization via now(), CH0 control channel rules, signed rx_channel for CCP-9 da2q rendezvous, density/load rules, capability signaling in DIOs, and desynchronization recovery.

All implementations MUST produce identical behavior to test vectors in `test/vectors/ccp16.json`, `ccp_tdma.json`, `link_frame.json`, and `l2_payload.json`:
- TDMA beacon byte layout, CDDL, SCHC rule 0x08, slot/hash, SFN wrap, join flows, epoch/num_slots per 2a.2
- vectors for CCP-16/14 slot, SF, channel, tx_allowed, Multi-RX, capacity metrics (independent oracle: FNV-1a + SX126x airtime + multi-channel sim).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## Table of Contents

1. Abstract
2. 2a.1. Overview
3. 2a.2. TDMA Beacon Format, Slots, Hash Selection, and Join (SCHC 0x08, CDDL, byte layout)
4. 2a.3. Channel Agility (select_channel, now())
5. 2a.4. Time Synchronization
6. 2a.5. Desync Recovery State Machine
7. 2a.6. Regional Channel Plans and CH0 Rules
8. 2a.7. Adaptive Spreading Factor Selection (adaptive_sf_select)
9. Implementation Status
10. References

## Overview

LICHEN networks operate under severe bandwidth and duty-cycle constraints. CCP coordinates access to the shared medium using hash-derived TDMA slots synchronized to a network epoch, density-aware adaptive SF selection, multi-channel operation (CH0 dedicated to control per SCHC-compressed beacons and RPL DIOs), deterministic channel agility, time synchronization, signed rx_channel announcements for rendezvous, per-neighbor EMA for RF metrics, and load/density signaling. The root advertises epoch and num_slots. Nodes suppress transmission outside assigned slots. All algorithms are deterministic.

## TDMA Frame Structure, Slot Assignment, now(), and Desync Recovery

## 2a.2. TDMA Slots and Hash Selection

The root advertises `epoch` (u32) and `num_slots` (default 8) via SCHC Rule ID 0x08 (TDMA_BEACON) on CH0 (see draft-lichen-schc-lora-00 and appendix-schc.md). 

**TDMA Beacon Format (exact, normative for interop):**

Multi-byte integers unsigned big-endian (network order). Full byte layout:

| Offset | Bytes | Field          | Description |
|--------|-------|----------------|-------------|
| 0      | 4     | epoch          | u32 BE for slot hash and SFN base |
| 4      | 1     | num_slots      | u8 (default 8); hash modulus |
| 5      | 4     | sfn            | u32 BE superframe number |
| 9      | 4     | timestamp      | u32 BE for epoch_floor validation |
| 13     | 1     | flags          | bits 0=scheduled, 1=CSMA, 2=CH0-RX, 3=GNSS-PPS, 4-7=0 |
| 14     | 1     | rx_chains      | u8 (1 for single-radio) |
| 15     | 2     | setup_window   | u16 ms (retune/CAD) |
| 17     | 2     | occupied_time  | u16 ms (data+ACK) |
| 19     | 1     | guard          | u8 ms (default 100) |
| 20     | 4     | channel_mask   | u32 (bit 0=CH0); local intersection computed |
| 24+    | var   | cbor_options   | density, slot_map, etc. |

**CDDL (RFC 8610) for CBOR options tail:**

```cddl
tdma-beacon = {
    epoch: uint .size 4,
    num_slots: uint .size 1,
    sfn: uint .size 4,
    timestamp: uint .size 4,
    flags: uint .size 1,
    rx_chains: uint .size 1,
    setup_window: uint .size 2,
    occupied_time: uint .size 2,
    guard: uint .size 1,
    channel_mask: uint .size 4,
    ? density: uint .size 1,
    * any
}
```

Slot ID = fnv1a32(EUI64 XOR epoch) % num_slots (lichen_hash_32, basis 0x811c9dc5; see lichen-core/src/lib.rs, appendix-design-rationale.md). All impls MUST match `test/vectors/ccp_tdma.json`, `ccp16.json`, `link_frame.json`, `l2_payload.json` exactly. Integrates with `lichen_rpl_dodag_init()`, `lichen_link_set_slot()`, `tdma_tx_allowed()`.

For SFN (superframe number, a u32 epoch counter) wrap-around, all nodes MUST compute using unsigned 32-bit arithmetic (modulo 0x100000000). The time-provider (see `docs/firmware-time-provider.md`) is the canonical source: SFN/epoch updates MUST pass epoch_floor validation, set `wall_clock_valid`, and respect stratum before adoption. RPL version changes or desync MUST reset SFN relative to the new root per the FSM in Section 2a.5.

Delta = (current_sfn - last_sfn) using uint32_t subtraction ensures correct wrap behavior. 

Edge case example (0xFFFFFFFF boundary):

```
last_sfn = 0xFFFFFFFFu;
current_sfn = 0x00000002u;
delta = current_sfn - last_sfn;  /* = 3 in unsigned 32-bit arithmetic */
```

This MUST be treated as advancement of 3 slots. Signed arithmetic would yield a large negative value, breaking desync detection and slot scheduling. Test vectors in ccp16.json and ccp_tdma.json MUST cover this and similar boundaries.

A node MUST only transmit in its assigned slot. Slot duration = max_airtime(current_SF) + 100 ms guard. The link layer MUST enforce via `lichen_link_set_slot()` and `tdma_tx_allowed()` (see lichen/subsys/lichen/link implementation). This integrates with TDMA and SCHC compressed control traffic on CH0.

## CCP-4. Regional Channel Plans

A regional channel plan MUST be provisioned locally. An over-the-air message MUST NOT expand the local plan, increase transmit power, or relax regulatory limits.

Each versioned plan contains:
- plan identifier and version;
- ordered channel entries, with CH0 at index zero;
- center frequency, bandwidth, spreading factors, coding rates, and maximum power allowed for each entry;
- regulatory accounting group for each channel;
- applicable duty-cycle, dwell-time, occupancy, and listen-before-talk rules;
- hardware-specific permitted channel mask.

CCP PHY profile ID `0x01` is fixed as LoRa bandwidth 125 kHz, SF10, coding rate 4/5, eight-symbol preamble, explicit header, payload CRC enabled, and low-data-rate optimization disabled. ADR MUST NOT change these parameters inside a schedule generation. See 2a.3 for normative adaptive SF outside schedules. Future profile IDs require canonical airtime vectors and a new specification revision before use.

Remote capability and schedule messages MAY reduce the locally permitted intersection. Unknown plan identifiers or versions MUST cause CH0 fallback.

## 2a.3. Channel Agility and Adaptive SF

CH0 is the control channel; all nodes MUST listen continuously on it for DIOs and beacons (see draft-lichen-schc-lora-00 and draft-lichen-rpl-lora-00). Announce messages carry rx_channel (CCP-9 per spec/05-routing.md:9.2) for rendezvous. Data channels selected via select_channel() or hash. All implementations MUST produce identical results to test vectors in ccp16.json, ccp9*.json, ccp_load_balancing.json.

### 2a.3.1. Pure Pseudocode Definitions (IETF-style, language agnostic)

Procedure Now():
   1. RETURN current SFN value.
   2. All subtractions, comparisons, and MOD operations MUST use unsigned 32-bit modular arithmetic (modulo 2^32) to handle wraparound correctly per test vectors.

Procedure SelectChannel(EUI64, Epoch, Density, NChannels):
   1. IF Density > 8 THEN RETURN 0
   2. Data = CONCAT(EUI64 as BE bytes, Epoch as LE u32 bytes)
   3. Hash = FNV1A32(Data)  // basis 0x811c9dc5; matches hash_32.json and ccp16.json vectors
   4. N = MAX(NChannels, 3)
   5. RETURN 1 + (Hash MOD N)

### 2a.7. Adaptive Spreading Factor Selection (per 8gac)

SF10 is the REQUIRED baseline for moderate density (5-20 nodes). Density-aware adaptation and per-neighbor EMA (alpha = 1/4) override only on explicit thresholds. Load_factor from gateway DIOs takes precedence. All paths MUST match ccp16.json and ccp_load_balancing.json exactly (independent oracle).

**Thresholds Table:**

| SF | Sensitivity | Upgrade Condition (SHOULD) | Downgrade Condition (MUST) |
|----|-------------|----------------------------|----------------------------|
| 7  | -123 dBm   | N/A                        | SNR < 0 OR loss > 0.25    |
| 9  | -129 dBm   | Density < 5 AND SNR_EMA > 8 | SNR < 0 OR Density > 8    |
| 10 | -132 dBm   | DEFAULT (moderate density) | SNR < 0 OR load_factor > 0.8 |
| 11 | -134 dBm   | N/A                        | Density > 8 OR SNR_EMA < 0 OR load > 0.8 |
| 12 | -137 dBm   | N/A                        | Density > 20 OR SNR_EMA < -5 |

Procedure AdaptiveSFSelect(AssignedSF, Neighbor, Density, Utilization, LoadFactor):
   1. SF = AssignedSF
   2. IF SF absent THEN SF = 10
   3. IF (Density > 10) OR (Utilization > 150) THEN SF = MIN(12, SF + 2)
   4. IF (Neighbor.EMA_SNR > 8) AND (Density < 5) THEN SF = MAX(7, SF - 1)
   5. IF (Neighbor.EMA_Loss > 0.25) OR (Utilization > 200) THEN
         SF = MIN(12, SF + 1)
         IF Utilization > 200 THEN RETURN (SF, false)  // tx not allowed
   6. RETURN (SF, true)

EMA_Update(Avg, Sample) = Avg + ((Sample - Avg) right-shift 2). Update per-neighbor state on every RX. Integrate with RPL DIO capability signaling. No dead code.

## 2a.5. Desync Recovery State Machine

The recovery mechanism is a finite state machine. All implementations MUST produce identical test vector output (see `test/vectors/ccp16.json`, `ccp_tdma.json`).

Nodes MUST follow the initialization dependency graph from AGENTS.md (normative for subsystem ordering to prevent use-before-init crashes) and the `lichen_node_init()` example (AGENTS.md). `lichen_link_init()` MUST precede `lichen_link_load_key()`, `lichen_rpl_dodag_init()`, TDMA (`lichen_tdma_init()`), `oscore_init()`, and `lichen_coap_client_init()` per the graph in AGENTS.md.

| Current State | Event/Condition | Timer/Timeout | Action | Next State | Reference |
|---|---|---|---|---|---|
| UNJOINED | Power-on / reset | - | `lichen_node_init(eui64, seed)` per AGENTS.md init graph | ACQUIRING | `AGENTS.md`, `lichen_link_init()` |
| ACQUIRING | Valid beacon (higher stratum/version) | BEACON_TIMEOUT = 3×superframe | Sync SFN, adopt time, DAO confirm, load key via `lichen_link_load_key()` | SYNCED | `lichen_rpl_dodag_init()`, `lichen_link_load_key()` |
| SYNCED | Beacon rx in assigned slot | superframe_timer | TX in slot, update RPL | SYNCED | Guard 100 ms enforced per §2a.2 |
| SYNCED | >3 missed beacons or RPL version increment | rejoin_timeout = 10×superframe_len (Kconfig `CONFIG_LICHEN_TDMA_REJOIN_TIMEOUT`, default 10 s) | Reset SFN, clear stale state | DRIFTING | Desync recovery |
| DRIFTING | Beacon rx or contention success | REJOIN_TIMEOUT | Re-init DODAG if needed, TOFU key pin | ACQUIRING | `oscore_init()` ordering |
| REJOINING | DAO-ACK + slot assign | - | Enter assigned slot, report LCI status | SYNCED | `lichen_coap_client_init()` |

MUST reset all timers on state transition. All transitions and multi-root cases produce identical test vector output. See full init graph in AGENTS.md (normative where referenced) and `spec/09-packets-timing.md` §14.8 for additional detail.

## Regional Channel Plans and CH0 Rules

- Python simulator, Rust gateway, Zephyr `lichen/subsys/lichen` validate against `test/vectors/ccp16.json`, `ccp_tdma.json`, `link_frame.json`, `l2_payload.json`.
- Kconfig options for CCP16, TDMA_SLOTS, integration with RPL/SCHC/TDMA complete. SCHC Rule 0x08 for TDMA beacon implemented.
- Adaptive SF, desync FSM, channel plans, Multi-RX gateway support implemented and tested.
- All codereview passes closed. Capacity gains verified in simulation per independent oracles.

## References

### Normative References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997, <https://www.rfc-editor.org/info/rfc2119>.

- `test/vectors/ccp16.json`, `ccp_tdma.json`, `link_frame.json`, `l2_payload.json` (authoritative for TDMA beacon format, CDDL, byte layout, slot/hash, join flows, SFN wrap; MUST match exactly)

- `spec/drafts/draft-lichen-rpl-lora-00.md`
- `spec/drafts/draft-lichen-schc-lora-00.md`
- `spec/appendix-design-rationale.md`
- `spec/appendix-schc.md` (Rule 0x08=TDMA_BEACON)
- `lichen/subsys/lichen/link*` (for `lichen_link_set_slot()`, `tdma_tx_allowed()`)
- `docs/firmware-time-provider.md`
- `spec/drafts/draft-lichen-link-01.md` (L2 0x15 join frame)
- `spec/09-packets-timing.md` (desync recovery FSM, boot storm avoidance, TDMA timing)
- `AGENTS.md` (normative for init dependency graph, `lichen_node_init()`, `lichen_link_init()`, `lichen_link_load_key()`, `oscore_init()`, `lichen_coap_client_init()` ordering)

[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](03-adaptation.md)
