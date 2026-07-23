<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Coordinated Capacity Protocol (CCP-16 with CCP-14 Gateway Multi-RX)

## Abstract

CCP-16 defines mechanisms for coordinated capacity management in LICHEN LoRa meshes including TDMA slot assignment, channel agility, adaptive SF selection, time synchronization, and hash-based selection. CCP-14 specifies Gateway Multi-RX for simultaneous reception across channels (control + data), increasing capacity per da2q multi-channel context. 

All implementations MUST produce identical behavior to test vectors in `test/vectors/ccp16.json`, `ccp_tdma.json`, `link_frame.json`, and `l2_payload.json`:
- TDMA beacon byte layout, CDDL, SCHC rule 0x08, slot/hash, SFN wrap, join flows, epoch/num_slots per 2a.2
- vectors for CCP-16/14 slot, SF, channel, tx_allowed, Multi-RX, capacity metrics (independent oracle: FNV-1a + SX126x airtime + multi-channel sim).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119].

## Table of Contents

1. Abstract
2. 2a.1. Overview
3. 2a.2. TDMA Beacon Format, Slots, Hash Selection, and Join (SCHC 0x08, CDDL, byte layout)
4. CCP-4. Regional Channel Plans
5. 2a.3. Channel Agility and Adaptive SF
6. 2a.4. Time Synchronization
7. 2a.5. Desync Recovery State Machine
8. Implementation Status
9. References

## 2a.1. Overview

LICHEN networks operate under severe bandwidth and duty-cycle constraints. CCP-16 coordinates access to the shared medium using hash-derived TDMA slots synchronized to a network epoch, density-aware adaptive SF, multi-channel operation (CH0 for control per SCHC-compressed beacons - see draft-lichen-schc-lora-00), and time synchronization via RPL DIOs. 

Nodes compute their slot using a deterministic hash of (EUI64 XOR epoch) modulo num_slots (see test vectors for validation). Transmission outside the assigned slot is suppressed by the link layer. This document specifies the algorithms and interoperation with RPL, SCHC, TDMA, and the link layer, incorporating SFN modulo, multi-root conflict, and desync recovery per parent epic. Arbitrary constants (e.g. 100ms guard, 300s density window) are defined in appendix-design-rationale.md and test vectors; implementations MUST match exactly.

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

CH0 is the control channel; all nodes MUST listen continuously on it for DIOs and beacons (see draft-lichen-schc-lora-00 and draft-lichen-rpl-lora-00). Announce messages carry rx_channel (CCP-9 per spec/05-routing.md:9.2) for rendezvous; data channels selected via select_channel or hash. All implementations MUST produce identical results to test/vectors/ccp16.json and ccp9*.json for CCP-9/14/15/16 vectors.

### synchronized_hop_channel (CCP-12/16 frequency agility)

```
function synchronized_hop_channel(eui64, epoch, density, n_channels=3):
    // Exact algorithm for interference mitigation via hash-based channel
    // selection + density-aware fallback to CH0. Matches ccp16.json vectors,
    // Python test oracle, Rust lichen_hash_32, and TDMA slot logic exactly.
    // Uses byte concatenation (EUI64 BE + epoch LE) per test/vectors/ccp16.json
    data = eui64_to_bytes(eui64) ++ u32le(epoch)
    hash = fnv1a32(data)  // lichen_hash_32; see hash_32.json
    IF density > 8 THEN
        RETURN 0  // CH0 control for high density (interference mitigation, desync)
    n = n_channels IF n_channels > 0 ELSE 3
    RETURN 1 + (hash MOD n)

function now():
    RETURN current_sfn()  // unsigned 32-bit modular arithmetic per 2a.2; SFN_MODULUS=2^32
```

Note: All operators spelled out (IF, THEN, MOD) for IETF compatibility. blacklist_until comparisons MUST use unsigned 32-bit subtraction for wraparound (see ccp16-desync.json). Density >8 forces CH0 per third test vector (select_channel_timing_test with now near u32 max). Cross-refs: adaptive_sf_select in 2a.3, TDMA in link.h:50 and lichen_tdma_init(), RPL DIO density signaling, SCHC on CH0. Pseudocode produces identical output to all ccp16*.json vectors.

### Density Rules Rationale

SF10 (or gateway-assigned SF) is the REQUIRED baseline per appendix-design-rationale.md §7.1. The density-aware adaptive_sf_select overrides this default **only** when one of the explicit IF thresholds is met; otherwise RETURN 10. Critical conditions (very high density or very poor SNR) take precedence. This matches the table below, pseudocode in 02-physical-link.md:3.5, rf_health.rs:345, and all ccp16.json vectors exactly. Nodes MUST maintain per-neighbor EMA state for SNR (alpha=1/4 via >>2), signal ASSIGNED_SF and RfHealthMetrics in DIOs, and RX on all SFs.

**Density-Aware SF Selection Table:**

| Priority | Condition | SF | Rationale |
|----------|-----------|----|-----------|
| Critical | density > 20 OR snr_ema < -5 | 12 | Extreme interference or congestion; maximum robustness |
| High | density > 8 OR snr_ema < 0 OR load_factor > 0.8 | 11 | High density, poor link, or overload; robustness |
| Capacity | density < 5 AND snr_ema > 8 | 9 | Low density + excellent link; maximize throughput |
| Default | otherwise | 10 | Baseline per design rationale §7.1 |

### adaptive_sf_select Pseudocode

```
function ema_update(avg, sample):
    diff = sample - avg
    RETURN avg + (diff >> 2)  // ccp15.json seeds

function adaptive_sf_select(density, snr_ema, load_factor):  // critical-first per rf_health.rs:348 and ccp15.json, ccp_load_balancing.json, Rust adaptive_sf_and_rebalance_matches_spec test
    IF (density > 20) OR (snr_ema < -5) THEN  // critical: ccp15-seed1, rf-test-snr-critical-density3 (SF12)
        RETURN 12
    ELSE IF (density > 8) OR (snr_ema < 0) OR (load_factor > 0.8) THEN  // high: ccp-load-high-util-rebalance, rf-test-density12-snr--3 (SF11)
        RETURN 11
    ELSE IF (density < 5) AND (snr_ema > 8) THEN  // low-density good-snr: ccp15-seed0, rf-test-density3-snr12 (SF9)
        RETURN 9
    ELSE
        RETURN 10  // baseline: ccp15-seed2 (SF10)
```

Per-SF SNR thresholds (normative): SF9: >8dB, SF10: any (baseline), SF11: >-5dB (with density/load), SF12: any (critical). Nodes MUST maintain per-neighbor EMA state, signal ASSIGNED_SF and metrics in DIO, RX on all SF. Pseudocode MUST be followed exactly and produce identical output to test/vectors/ccp*.json. Fixed-point Q16.16 no_std example in appendix-design-rationale.md:7.6. Integrates with TDMA slot enforcement and SCHC. Cross-refs physical-link:3.4 table and link layer primitives.

Boundary example for adaptive_sf_select (density=8 edge case, matching SFN delta unsigned style per 2a.2):

```
uint32_t density = 8u;      // from beacon count, unsigned
int16_t snr_ema = 0;
float load_factor = 0.8f;

// critical-first per pseudocode:
IF (density > 20) OR (snr_ema < -5)  => false
ELSE IF (density > 8) OR (snr_ema < 0) OR (load_factor > 0.8) => all false
ELSE RETURN 10  // default baseline
```

## 2a.4. Time Synchronization

Time sync provided by DODAG root via epoch in beacons/RPL options (see 2a.2 for time-provider, epoch_floor validation, SFN modulo/wrap independence). Nodes MUST maintain `epoch_floor`, `stratum`, `wall_clock_valid` (see `docs/firmware-time-provider.md`). Root time-provider is authoritative. Adopt lowest DODAG ID root. Drift > threshold triggers desync (2a.5). Integrates with `lichen_rpl_dodag_init()` and lichen_link.

## 2a.5. Desync Recovery State Machine

A CCP-capable node is always in exactly one of these states:

| State | Meaning | Channel behavior |
|-------|---------|------------------|
| UNJOINED | Never successfully synchronized | CH0 only; cannot hop |
| JOINED | Clock is trusted; normal operation | Hop per schedule |
| DRIFT | Clock may be drifting; watching | Hop with extended RX windows |
| RECOVER | Clock is untrusted; seeking beacon | CH0 only; stopped hopping |

Join procedure: exact CoAP URI `POST coap://[fe80::/64%iface]/tdma/join` (SCHC rule 0, OSCORE after first beacon) or L2 frame dispatch `0x15` (per draft-lichen-link-01) with msg_type=`0x10` (join-request). Triggers DAO after sync. See test vectors for exact flows. (See full state diagram, timers T_DRIFT_WARN=30s, T_DRIFT_MAX=120s, T_GIVE_UP=600s, transitions, multi-root conflict resolution preferring higher epoch, GPS-capable nodes, SFN wraparound handling, and implementation notes in the detailed description. All transitions MUST match test vectors. Nodes in RECOVER MUST refrain from data TX until re-synchronized.)

## Implementation Status

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
