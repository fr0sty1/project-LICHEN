<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Coordinated Capacity Protocol (CCP-16)

## Abstract

CCP-16 defines mechanisms for coordinated capacity management in LICHEN LoRa meshes including TDMA slot assignment, channel agility, adaptive SF selection, time synchronization, and hash-based selection. It ensures deterministic transmission windows, reduces collisions in dense deployments, and maintains bit-exact interoperability with test vectors in `test/vectors/ccp16.json`.

All implementations MUST produce identical `slot_id`, `sf`, `channel`, and `tx_allowed` outputs for the defined test vectors.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119].

## Table of Contents

1. Abstract
2. 2a.1. Overview
3. 2a.2. TDMA Slots and Hash Selection
4. 2a.3. Channel Agility and Adaptive SF
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
slot_id = fnv1a32(eui64 XOR epoch) % num_slots
```

where `fnv1a32` is the FNV-1a hash (see pseudocode in appendix-design-rationale.md:388). The XOR ensures time-varying slots to prevent persistent collisions.

For SFN (superframe number, a u32 epoch counter) wrap-around, all nodes MUST compute using unsigned 32-bit arithmetic (modulo 0x100000000). The time-provider (see `docs/firmware-time-provider.md`) is the canonical source: SFN/epoch updates MUST pass epoch_floor validation, set `wall_clock_valid`, and respect stratum before adoption. RPL version changes or desync MUST reset SFN relative to the new root per the FSM in Section 2a.5. This integrates with `lichen_rpl_dodag_init()` ordering.

Delta = (current_sfn - last_sfn) using uint32_t subtraction ensures correct wrap behavior. 

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

CH0 is the control channel; all nodes MUST listen continuously on it for DIOs and beacons.

Data channels (1+) are selected via the same hash function or root-assigned map in DAO-ACK.

Adaptive SF:

- Base: SF10 (Kconfig default).
- Inputs: local SNR, neighbor density (unique neighbors over last 300s), utilization.
- Rules (MUST match ccp16.json):
  - density < 5 AND snr_db > 8.0 → SF9
  - density > 8 OR snr_db < 0 → SF11
  - else SF10.

Updates MUST be propagated in RPL metric container. Root optimizer uses reported neighbor_count and channel_util to minimize collisions.

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

- Python simulator, Rust RPL/gateway, Zephyr `lichen/subsys` all validate against `ccp16.json`.
- Kconfig: `CONFIG_LICHEN_CCP16=y`, `CONFIG_LICHEN_TDMA_SLOTS=8`.

## References

- `test/vectors/ccp16.json`
- `spec/drafts/draft-lichen-rpl-lora-00.md`
- `spec/appendix-design-rationale.md#7.6`
- `spec/09-packets-timing.md`

