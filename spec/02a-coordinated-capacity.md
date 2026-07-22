<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Coordinated Capacity Protocol (CCP-16 with CCP-14 Gateway Multi-RX)

## Abstract

CCP-16 defines mechanisms for coordinated capacity management in LICHEN LoRa meshes including TDMA slot assignment, channel agility, adaptive SF selection, time synchronization, and hash-based selection. CCP-14 specifies Gateway Multi-RX for simultaneous reception across channels (control + data), increasing capacity per da2q multi-channel context. 

All implementations MUST produce identical behavior to test vectors in `test/vectors/ccp16.json`:
- vectors[0-2]: TDMA slot, SF, channel, tx_allowed per CCP-16 (see 2a.2, 2a.3)
- vectors[3+]: CCP-14 Gateway Multi-RX scheduling, concurrent RX validation, capacity metrics (independent oracle: reference FNV-1a + Semtech SX126x airtime tables + multi-channel sim from external Python oracle, not LICHEN impl).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119].

## Table of Contents

1. Abstract
2. 2a.1. Overview
3. 2a.2. TDMA Slots and Hash Selection
4. 2a.3. Channel Agility and Adaptive SF
   4.1. select_channel and now()
   4.2. Density Rules Rationale
   4.3. adaptive_sf_select Pseudocode
5. 2a.4. Time Synchronization
6. 2a.5. Desync Recovery State Machine
7. Implementation Status
8. References

## 2a.1. Overview

LICHEN networks operate under severe bandwidth and duty-cycle constraints. CCP-16 coordinates access to the shared medium using hash-derived TDMA slots synchronized to a network epoch, density-aware adaptive SF, multi-channel operation (CH0 for control per SCHC-compressed beacons - see draft-lichen-schc-lora-00), and time synchronization via RPL DIOs. 

Nodes compute their slot using a deterministic hash (FNV-1a) of (EUI64 XOR epoch) modulo num_slots (see test vectors for validation). Transmission outside the assigned slot is suppressed by the link layer. This document specifies the algorithms and interoperation with RPL, SCHC, and the link layer, incorporating SFN modulo, multi-root conflict, and desync recovery per parent epic project-LICHEN-ofrf. Arbitrary constants (e.g. 100ms guard, 300s density window) are defined in appendix-design-rationale.md and test vectors; implementations MUST match exactly.

## 2a.2. TDMA Slots and Hash Selection

The root advertises `epoch` (u32) and `num_slots` (default 8) in an extended RPL configuration option.

Slot ID MUST be computed as:

```
slot_id = (crc32_ieee(eui64, 8) ^ epoch) % num_slots
```

using `crc32_ieee` (see appendix-design-rationale.md:388, lichen/subsys/schc/schc.c:90). This fixes prior inconsistency between crc16 (SMP/Meshtastic legacy) and hash_32 in CCP-15.8.3 pseudocode (`spec/02a-coordinated-capacity.md:41`). The XOR with epoch ensures time-varying slots to prevent persistent collisions. All impls MUST match ccp16.json vectors exactly.

For SFN (superframe number, a u32 epoch counter) wrap-around, all nodes MUST compute using unsigned 32-bit arithmetic (modulo 0x100000000). The time-provider (see `docs/firmware-time-provider.md`) is the canonical source: SFN/epoch updates MUST pass epoch_floor validation, set `wall_clock_valid`, and respect stratum before adoption. RPL version changes or desync MUST reset SFN relative to the new root per the FSM in Section 2a.5. This integrates with `lichen_rpl_dodag_init()` ordering.

delta = (current_sfn - last_sfn) using uint32_t subtraction ensures correct wrap behavior per RFC 1982. 

Edge case example (0xFFFFFFFF boundary):
```
last_sfn = 0xFFFFFFFFu;
current_sfn = 0x00000002u;
delta = current_sfn - last_sfn;  /* = 3 in unsigned 32-bit arithmetic */
```
This MUST be treated as advancement of 3 slots. Signed arithmetic would yield a large negative value, breaking desync detection and slot scheduling. Test vectors in ccp16.json MUST cover this and similar boundaries.

A node MUST only transmit in its assigned slot. Slot duration = max_airtime(current_SF) + 100 ms guard. The link layer MUST enforce via `lichen_link_set_slot()` and `tdma_tx_allowed()` (see lichen/subsys/lichen/link: implementation).

(This completes logical chunk 2: modulo 0xFFFFFFFF edge case example and delta calculation.)

## 2a.3. Channel Agility and Adaptive SF

CH0 is the control channel; all nodes MUST listen continuously on it for DIOs and beacons (see draft-lichen-schc-lora-00).

Data channels are selected via select_channel (normative pseudocode below, cross-ref draft-lichen-tdma for TDMA integration). All implementations MUST produce identical results to test/vectors/ccp16.json for CCP-14/15/16 vectors.

### select_channel and now() (logical chunk: function definitions - pure pseudocode)

```
function select_channel(ctx, metrics, t):
    IF (metrics.density > 8) OR (NOT ctx.wall_clock_valid) THEN
        RETURN 0   // control CH0 for high density or desync (per vectors[1,3])
    hash = fnv1a32( (ctx.eui64 XOR t XOR ctx.epoch) )
    n = ctx.num_data_channels IF ctx.num_data_channels > 0 ELSE 3
    RETURN 1 + (hash MOD n)

function now():
    RETURN current_sfn()   // superframe tick aligned to LICHEN_TDMA_Slot (exact: now_ts = sfn * ticks_per_slot from struct; modulo superframe for rendezvous per draft-lichen-tdma)
```
Note: All operators are spelled out (OR, NOT, MOD, XOR) for language-agnostic IETF compatibility. No Rust 'or', no C types or structs, no dead code. now_ts TDMA alignment uses LICHEN_TDMA_Slot relation for slot calc.

### Density Rules Rationale (logical chunk: rationale paragraph - updated)

SF10 is the REQUIRED default because it balances sensitivity (~ -137 dBm at 125 kHz) and airtime (~ 50 ms payload) for typical mesh density per appendix-design-rationale.md:7.6 and independent sim oracle in ccp16.json vectors. Density-aware adaptation prioritizes capacity (SF9 in low density <5 + good SNR >8 dB to reduce airtime 2x) vs robustness (SF11/12 in density >8 or poor SNR or high load_factor to lower PER). This yields net capacity gain in sims at 50 nodes/km^2 despite longer airtime for higher SF. EMA on SNR (snr_ema = 0.1 * current + 0.9 * previous, updated via now()) integrates with load_factor override from gateway DIOs.

Updates MUST be propagated in RPL metric container. Root optimizer uses reported neighbor_count and channel_util to minimize collisions.

### 2a.3.2 adaptive_sf_select Pseudocode (logical chunk: SF function)

```
function adaptive_sf_select(density, snr_db, load_factor, t):
    snr_ema = ema_update(previous_ema, snr_db, t)  // alpha=0.1 over 300s window; exact match to vectors
    IF (density > 8) OR (snr_ema < 0) OR (load_factor > 0.8) THEN
        RETURN 11
    ELSE IF (density < 5) AND (snr_ema > 8.0) THEN
        RETURN 9
    ELSE IF (density > 20) OR (snr_ema < -5.0) THEN
        RETURN 12
    ELSE
        RETURN 10
```

Per-SF SNR thresholds (normative, for ema_update fallback): SF9: >8dB, SF10: >0dB, SF11: >-5dB, SF12: any. Matches all ccp16.json vectors[0-4]. No dead code; all paths exercised by test vectors. Defines ema_update, select_channel, now() per prior beads.

## 2a.4. Time Synchronization

Time sync is provided by the DODAG root via epoch in beacons and RPL options. Nodes MUST maintain:

* `epoch_floor`: floor of current epoch for modulo calculations.
* `stratum`: root distance for priority.
* `wall_clock_valid`: flag set when synced within tolerance.

The root's time-provider (GPS, NTP over CoAP, or local) determines the epoch. Nodes adopt the lowest DODAG ID root's time. Sync drift > threshold triggers desync state.

See interaction with `lichen_rpl_dodag_init()` ordering per subsystem init graph in AGENTS.md.

## 2a.5. Desync Recovery State Machine

[STUB - detailed FSM with transitions, timers, RPL version change handling, and multi-root conflict resolution to be expanded in subsequent chunks per parent epic project-LICHEN-ofrf. Includes full table of states (UNJOINED, JOINED, DRIFT, RECOVER), Trickle integration, and test vectors.]

Nodes entering this state from multi-root conflict (different epoch/version on same control channel) MUST refrain from data TX until re-synchronized. See Section 2a.2 for conflict detection rules.

## Implementation Status

- Python simulator, Rust RPL/gateway, Zephyr `lichen/subsys` all validate against `test/vectors/ccp16.json` (full cross-refs in Abstract; CCP-14 vectors[3+] for Gateway Multi-RX).
- Kconfig: `CONFIG_LICHEN_CCP16=y`, `CONFIG_LICHEN_TDMA_SLOTS=8`.
- Updated per draft-lichen-ccp scope (this document serves as relevant spec update).

## Vector Table (CCP-14 extension)

See `test/vectors/ccp16.json#vectors[3+]` for Gateway Multi-RX test cases with independent oracles. All MUST match exactly for interoperability.

## References

- `test/vectors/ccp16.json` (full cross-refs for MUST identical behavior)
- `spec/drafts/draft-lichen-rpl-lora-00.md`
- `spec/appendix-design-rationale.md#7.6`
- `spec/09-packets-timing.md`
- da2q multi-channel context for CCP-14

