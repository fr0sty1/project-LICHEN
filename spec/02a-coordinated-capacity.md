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

(The state machine from prior section remains; JOINED uses SelectChannel and AdaptiveSFSelect per schedule.)

## 2a.4. Time Synchronization

All nodes synchronize their TDMA slot offset to the DODAG root. The root advertises its wall-clock epoch and SFN in each TDMA_BEACON (SCHC Rule 0x08, Section 2a.2). Synchronization uses layered precision sources with distinct stratum values.

### 2a.4.1. Time Stratum and Epoch Floor

Nodes MUST accept time from providers at equal or better (lower-numbered) stratum. The effective epoch floor is `max(firmware_build_epoch, board_provision_epoch)` per `docs/firmware-time-provider.md`. SFN/epoch updates derived from timestamps below the effective epoch floor MUST be rejected. A node with `wall_clock_valid=true` and stratum ≤ current acts as a time-provider for its children.

| Stratum | Source | Precision | Notes |
|---------|--------|-----------|-------|
| 0 | GNSS PPS | <100 us | Best available; reduces guard to 10 ms |
| 1 | GNSS time fix | <1 s | May require cold-start rejection (below epoch floor) |
| 2 | NTP/SNTP | 1-100 ms | Requires epoch floor validation |
| 3 | Mesh (DIO cascade) | superframe-aligned | Adopts parent stratum + 1 (capped at 15) |
| 4 | Manual/local-client | variable | Lab/simulator only |
| 15 | Uninitialized | N/A | Does not provide time to others |

### 2a.4.2. Drift Compensation

Nodes compute linear drift correction from beacon arrival time against the expected superframe boundary:

```
delta_ms = local_rx_ms - expected_beacon_ms
drift_ppm = (delta_ms * 1000000) / beacon_interval_ms
correction_ms = drift_ppm * future_delta_ms / 1000000
adjusted_time = local_time + correction_ms
```

All implementations MUST apply drift compensation before slot calculation. Threshold >5000 ppm (cumulative) triggers desync (DRIFTING state, Section 2a.5). See `test/vectors/ccp_tdma.json` drift_compensation vector for the canonical oracle.

## 2a.5. Desync Recovery State Machine

This section defines the normative FSM for TDMA synchronization state, multi-root beacon conflict resolution, and recovery transitions. The FSM is referenced by SFN wrap semantics (Section 2a.2), RPL DODAG version changes (05-routing.md), and time-provider stratum updates (Section 2a.4). All implementations MUST match test vectors in `test/vectors/ccp_tdma.json` and `ccp16-desync.json` exactly.

### 2a.5.1. State Definitions

| State | Description |
|-------|-------------|
| **UNJOINED** | CH0 listen only, no TDMA TX. Initial state on power-on or factory reset. |
| **ACQUIRING** | Receiving valid beacons. Adopts SFN/time, sends DAO with slot request. |
| **SYNCED** | DAO-ACK received. TX only in assigned slot (enforced by `tdma_tx_allowed()`). Periodic beacon listen. |
| **DRIFTING** | Lost synchronization. Extended CH0 listen, suppress TDMA TX. |
| **RECOVERING** | Re-acquired beacons, validating consistency. 3 consecutive valid beacons required to re-sync. |

### 2a.5.2. Transition Table

| Current State | Trigger | Timeout | Action | Next State |
|---------------|---------|---------|--------|------------|
| UNJOINED | Valid beacon (stratum ≤ current OR higher root priority) with `ts >= epoch_floor` | BEACON_TIMEOUT = 3×superframe | Adopt SFN, adopt time if stratum is better, send DAO | ACQUIRING |
| UNJOINED | Beacon timeout without valid candidate | — | Retry CH0 scan, widen channel list | UNJOINED |
| ACQUIRING | DAO-ACK received, slot confirmed | — | Load key pair, start slot timer, arm `tdma_tx_allowed()` | SYNCED |
| ACQUIRING | Beacon timeout (no DAO-ACK within 3 superframes) | BEACON_TIMEOUT = 3×superframe | Resend DIS, reset slot request | ACQUIRING |
| ACQUIRING | Higher-priority root detected (better stratum or higher root ID precedence) | — | Abandon current ACQUIRING, flush pending DAO, switch to new root's SFN | ACQUIRING |
| SYNCED | Beacon rx in assigned slot | superframe_timer | TX in slot, update RPL metrics | SYNCED |
| SYNCED | >3 consecutive missed beacons | BEACON_TIMEOUT | Reset SFN, clear stale RPL state, suppress TDMA TX | DRIFTING |
| SYNCED | RPL DODAG version increment from current root | — | Reset SFN relative to new DODAG version (see 2a.5.3), suppress TDMA TX | DRIFTING |
| SYNCED | Drift threshold exceeded (>5000 ppm cumulative) | — | Mark local time invalid, flush slot timer | DRIFTING |
| SYNCED | Multi-root conflict: beacon from different root with higher precedence | — | Abandon current root, adopt new root's SFN and epoch, send DAO | ACQUIRING |
| DRIFTING | Valid beacon (ts >= epoch_floor, same root) | REJOIN_TIMEOUT = 10×superframe | Start extended listen timer, begin validation count | RECOVERING |
| DRIFTING | New DODAG version from same or different root | REJOIN_TIMEOUT = 10×superframe | Reset SFN, clear stale TDMA state, evaluate stratum | ACQUIRING |
| DRIFTING | Rejoin timeout with no valid beacon | — | Fall back to CSMA-only on CH0, periodic DIS | DRIFTING |
| RECOVERING | 3 consecutive valid beacons (SFN advancing monotonically, ts valid, slot consistent) | — | Resume normal TDMA slot usage, clear drift accumulator | SYNCED |
| RECOVERING | Any missed beacon before 3-count completes | — | Restart validation count | RECOVERING |
| RECOVERING | RPL version change (different DODAG version in beacon) | — | Reset SFN, reset validation count, transition | ACQUIRING |
| RECOVERING | Beacon timeout during validation | REJOIN_TIMEOUT | Suppress TDMA TX, resume CSMA fallback | DRIFTING |

### 2a.5.3. RPL DODAG Version Increment and SFN Reset

When the RPL DODAG version increments (detected via DIO `DODAGVersion`), the node MUST:

1. Flush the current SFN value.
2. The new SFN base is derived from the beacon's `epoch` field and the new DODAG version as `SFN_base = epoch XOR (DODAGVersion << 24)`. This ensures that nodes joining the updated DODAG compute a consistent slot hash even when the time-provider has not changed stratum.
3. Re-derive `Slot ID = fnv1a32(EUI64 XOR epoch) % num_slots` using the new epoch. All slot timers are restarted from the recovery timeout.
4. The time-provider stratum is re-evaluated: if the new root advertises stratum ≤ current local stratum, adopt the new root's time as the canonical source. If the new root advertises a strictly worse (higher-numbered) stratum, retain the local time but re-anchor SFN to the new epoch for TDMA slotting.
5. Suppress TDMA TX until re-synced (DRIFTING→ACQUIRING→SYNCED chain).

This interaction guarantees that a DODAG version change does not leave nodes stuck in stale slots, and that nodes rejoining a re-rooted DODAG converge on the same epoch within one REJOIN_TIMEOUT window.

### 2a.5.4. Multi-Root Beacon Conflict

When a node receives beacons from two or more DODAG roots (distinct DODAG IDs), the following precedence rules resolve the conflict deterministically:

1. **Primary key: time-provider stratum.** Lower stratum number wins. GNSS-locked root (stratum 0) always outranks mesh-derived time.
2. **Stratum tiebreaker: root ID precedence.** When stratum is equal, compare DODAG ID bytes in lexicographic order (RFC 6550 Section 8.1.1). Lower DODAG ID wins.
3. **Transition rule.** If the node is ACQUIRING or SYNCED to root A and detects root B with higher precedence, the node MUST abandon root A (flush pending DAO, clear slot timer) and begin ACQUIRING to root B. If the node is SYNCED to a higher-precedence root A and detects lower-precedence root B, the node MUST ignore B's beacons for slot purposes while recording B's presence in neighbor diagnostics.
4. **Oscillation guard.** A node that switches roots more than twice within any 60-second window MUST enter DRIFTING state, set `CONFIG_LICHEN_TDMA_REJOIN_TIMEOUT` * 2, and suppress all TDMA TX until the guard window expires. This prevents oscillation between two roots with near-identical stratum and prevents disruption of the active slot schedule. During the guard window, the node uses CSMA-only on CH0 and monitors both roots for stability.
5. **Diagnostics.** Root conflict events (precedence changes, oscillation triggers) are recorded as diagnostics that can be queried via CoAP `/status` resources.

### 2a.5.5. SFN Wrap-Around Interaction

When SFN wraps from 0xFFFFFFFF to 0x00000000, the unsigned delta computation (Section 2a.2) produces correct advancement. The FSM interprets a single 0xFFFFFFFF→0x00000000 transition as one superframe advance — the SYNCED state is maintained. However, a delta larger than `num_slots × 256` (indicating possible missed wraps or clock skew) triggers DRIFTING and `wall_clock_valid=false` re-evaluation through the time-provider.

Test vectors in `ccp16.json` and `ccp_tdma.json` MUST cover SFN wrap, multi-root FSM transitions, and oscillation guard expiry as independent oracles.

(Codereview pass 3 closure: Section 2a.5 FSM table is normative for all multi-root, desync recovery, and RPL version interactions. All SFN resets and stratum updates follow the procedure in 2a.5.3.)

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

[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](03-adaptation.md)
