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
3. 2a.2. TDMA Frame Structure, Slot Assignment, and SFN
    - 2a.2.1. Superframe Number (SFN) Definition
    - 2a.2.2. TDMA Beacon Format (SCHC 0x08, CDDL, byte layout)
    - 2a.2.3. Slot Assignment (Hash Selection and Join)
4. 2a.3. Channel Agility (select_channel, now())
5. 2a.4. Time Synchronization
6. 2a.5. Desync Recovery State Machine
7. 2a.6. Regional Channel Plans and CH0 Rules
8. 2a.7. Adaptive Spreading Factor Selection (adaptive_sf_select)
9. Implementation Status
10. References

## Overview

LICHEN networks operate under severe bandwidth and duty-cycle constraints. CCP coordinates access to the shared medium using hash-derived TDMA slots synchronized to a network epoch, density-aware adaptive SF selection, multi-channel operation (CH0 dedicated to control per SCHC-compressed beacons and RPL DIOs), deterministic channel agility, time synchronization, signed rx_channel announcements for rendezvous, per-neighbor EMA for RF metrics, and load/density signaling. The root advertises epoch and num_slots. Nodes suppress transmission outside assigned slots. All algorithms are deterministic.

SCHC Rule 0x08 (TDMA_BEACON) compresses beacon headers to a minimum, preserving airtime for the per-beacon Schnorr signature (48 bytes, see [draft-lichen-schnorr-00](drafts/draft-lichen-schnorr-00.md)). In multi-root scenarios a node may hear multiple beacons per superframe; the compressed header keeps signature verification latency bounded by keeping the total on-air beacon footprint small.

## TDMA Frame Structure, Slot Assignment, now(), and Desync Recovery

### 2a.2.1. Superframe Number (SFN) Definition

The Superframe Number (SFN) is a u32 monotonic counter that advances by one each superframe. It provides the time base for slot computation, channel agility, and desynchronization detection across all nodes in a DODAG.

**Normative requirements:**

1. SFN is a 32-bit unsigned integer (u32). All arithmetic on SFN values uses unsigned 32-bit modular arithmetic (modulo 2^32), meaning subtraction and comparison naturally handle wraparound at the 0xFFFFFFFF boundary.
2. The root maintains the canonical SFN, transmitted in every TDMA beacon as the `sfn` field (see §2a.2.2 beacon format).
3. Nodes adopt SFN from the root's beacon upon joining and maintain it via periodic beacon synchronization.
4. SFN delta computation: `SFN_delta = (current_sfn - last_sfn)` using unsigned 32-bit subtraction. This yields correct positive values across the 0xFFFFFFFF boundary (e.g., `0x00000002 - 0xFFFFFFFF = 3`).
5. SFN reset: RPL version changes, desynchronization recovery (see §2a.5), or root change MUST reset SFN relative to the new root.
6. The time provider (`docs/firmware-time-provider.md`) anchors SFN validation: SFN updates from beacons MUST pass `effective_epoch_floor` validation before adoption (see spec/09-packets-timing.md §14.6).
7. All implementations MUST produce identical SFN wrap behavior matching `test/vectors/ccp16.json` and `test/vectors/ccp_tdma.json` (see `test/vectors/ccp16.json:sfn_wrap`, `ccp_tdma.json:sfn_boundary`).
8. The `now()` function (see §2a.3.1) returns the current SFN value.

**Cross-references:**
- Slot computation: §2a.2.3 (hash-based slot from SFN)
- Channel agility: §2a.3 (SFN-seeded channel selection)
- Wrap desync recovery: §2a.5 (FSM for SFN desynchronization)
- Time provider interaction: spec/09-packets-timing.md §14.6 (epoch floor validation)
- Test vectors: `test/vectors/ccp16.json`, `test/vectors/ccp_tdma.json`
- Advertisement: spec/drafts/draft-lichen-rpl-lora-00.md §9.2 (SFN in DIO options)

### 2a.2.2. TDMA Beacon Format (exact, normative for interop)

Multi-byte integers unsigned big-endian (network order). Full byte layout:

| Offset | Bytes | Field          | Description |
|--------|-------|----------------|-------------|
| 0      | 4     | epoch          | u32 BE for slot hash and SFN base |
| 4      | 1     | num_slots      | u8 (default 8); hash modulus |
| 5      | 4     | sfn            | u32 BE superframe number (see §2a.2.1) |
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

### 2a.2.3. Slot Assignment

Slot ID = hash_32(EUI64 XOR epoch) % num_slots (lichen_hash_32, basis 0x811c9dc5; see lichen-core/src/lib.rs, appendix-design-rationale.md). All impls MUST match `test/vectors/ccp_tdma.json`, `ccp16.json`, `link_frame.json`, `l2_payload.json` exactly. Integrates with `lichen_rpl_dodag_init()`, `lichen_link_set_slot()`, `tdma_tx_allowed()`.

Slot duration = max_airtime(current_SF) + guard (default 100 ms per §2a.2.2 guard field). The link layer MUST enforce via `lichen_link_set_slot()` and `tdma_tx_allowed()` (see lichen/subsys/lichen/link implementation). This integrates with TDMA and SCHC compressed control traffic on CH0.

A node MUST only transmit in its assigned slot.

For SFN wrap-around, all nodes MUST compute using unsigned 32-bit arithmetic (modulo 0x100000000). The time-provider (see `docs/firmware-time-provider.md`) is the canonical source: SFN/epoch updates MUST pass epoch_floor validation, set `wall_clock_valid`, and respect stratum before adoption. RPL version changes or desync MUST reset SFN relative to the new root per the FSM in Section 2a.5.

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
    3. Hash = hash_32(Data)  // basis 0x811c9dc5; matches hash_32.json and ccp16.json vectors
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

## Regional Channel Plans and CH0 Rules

- Python simulator, Rust gateway, Zephyr `lichen/subsys/lichen` validate against `test/vectors/ccp16.json`, `ccp_tdma.json`, `link_frame.json`, `l2_payload.json`.
- Kconfig options for CCP16, TDMA_SLOTS, integration with RPL/SCHC/TDMA complete. SCHC Rule 0x08 for TDMA beacon implemented.
- Adaptive SF, desync FSM, channel plans, Multi-RX gateway support implemented and tested.
- All codereview passes closed. Capacity gains verified in simulation per independent oracles.

## References

### Normative References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997, <https://www.rfc-editor.org/info/rfc2119>.

- `test/vectors/ccp16.json`, `ccp_tdma.json`, `link_frame.json`, `l2_payload.json` (authoritative for TDMA beacon format, CDDL, byte layout, slot/hash, join flows, SFN wrap; MUST match exactly)

- `spec/drafts/draft-lichen-rpl-lora-00.md` (see §9.2 for Root Conflict Resolution Option)
- `spec/drafts/draft-lichen-schc-lora-00.md`
- `spec/appendix-design-rationale.md`
- `spec/appendix-schc.md` (Rule 0x08=TDMA_BEACON)
- `lichen/subsys/lichen/link*` (for `lichen_link_set_slot()`, `tdma_tx_allowed()`)
- `docs/firmware-time-provider.md`
- `spec/drafts/draft-lichen-link-01.md` (L2 0x15 join frame)

[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](03-adaptation.md)
