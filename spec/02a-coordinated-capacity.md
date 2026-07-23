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
3. 2a.2. Channel Agility (TDMA Slots and Hash Selection per draft-lichen-tdma)
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

The root advertises `epoch` (u32) and `num_slots` (default 8) in an extended RPL configuration option.

Slot ID MUST be computed as:

Multi-byte integers are unsigned big-endian. Flags bits: 0=scheduled mode, 1=CSMA rendezvous, 2=concurrent CH0 RX, 3=GNSS-PPS, 4-7 reserved (zero). `Setup Window` bounds retune/readiness/CAD. `Occupied Time` bounds data+ACK. `Guard` is separation between occupied envelopes. `RX Chains` is simultaneous receive count (1 for typical single-radio). `Channel Mask` bit 0 = CH0. Receivers compute local intersection. See test/vectors/ccp*.json for format validation.

using `fnv1a32` (lichen_hash_32 primitive, basis 0x811c9dc5; see lichen-core/src/lib.rs, spec/appendix-design-rationale.md). The XOR with epoch ensures time-varying slots to prevent persistent collisions. All implementations MUST match ccp*.json vectors exactly. This integrates with `lichen_rpl_dodag_init()`.

For SFN (superframe number, a u32 epoch counter) wrap-around, all nodes MUST compute using unsigned 32-bit arithmetic (modulo 0x100000000). The time-provider (see `docs/firmware-time-provider.md`) is the canonical source: SFN/epoch updates MUST pass epoch_floor validation, set `wall_clock_valid`, and respect stratum before adoption. RPL version changes or desync MUST reset SFN relative to the new root per the FSM in Section 2a.5.

Delta = (current_sfn - last_sfn) using uint32_t subtraction ensures correct wrap behavior. 

Edge case example (0xFFFFFFFF boundary):

```
last_sfn = 0xFFFFFFFFu;
current_sfn = 0x00000002u;
delta = current_sfn - last_sfn;  /* = 3 in unsigned 32-bit arithmetic */
```

This MUST be treated as advancement of 3 slots. Signed arithmetic would yield a large negative value, breaking desync detection and slot scheduling. Test vectors in ccp16.json MUST cover this and similar boundaries.

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

CH0 is the control channel; all nodes MUST listen continuously on it for DIOs and beacons (see draft-lichen-schc-lora-00 and draft-lichen-rpl-lora-00). Data channels are selected via select_channel. All implementations MUST produce identical results to test/vectors/ccp16.json for CCP-14/15/16 vectors.

### select_channel and now()

```
function select_channel(ctx, metrics, t):
    IF (metrics.density > 8) OR (NOT ctx.wall_clock_valid) THEN
        RETURN 0   // control CH0 for high density or desync (per vectors)
    hash = fnv1a32(ctx.eui64 XOR t XOR ctx.epoch)
    n = ctx.num_data_channels IF ctx.num_data_channels > 0 ELSE 3
    RETURN 1 + (hash MOD n)

function now():
    RETURN current_sfn()   // from time-provider; unsigned modular arithmetic per 2a.2; SFN_MODULUS=2^32
```

Note: All operators are spelled out (OR, NOT, MOD, XOR) for language-agnostic IETF compatibility. blacklist_until[] timer comparisons MUST use unsigned 32-bit subtraction to correctly handle wrap-around. t = now() % SFN_MODULUS (cross-ref 2a.2) if select_channel expanded later. Cross-ref draft-lichen-tdma, RPL, and SCHC.

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

(See full state diagram, timers T_DRIFT_WARN=30s, T_DRIFT_MAX=120s, T_GIVE_UP=600s, transitions, multi-root conflict resolution preferring higher epoch, GPS-capable nodes, SFN wraparound handling, and implementation notes in the detailed description. All transitions MUST match test vectors. Nodes in RECOVER MUST refrain from data TX until re-synchronized.)

## Implementation Status

- Python simulator, Rust gateway, Zephyr `lichen/subsys/lichen` validate against `test/vectors/ccp16.json`.
- Kconfig options for CCP16, TDMA_SLOTS, integration with RPL/SCHC/TDMA complete.
- Adaptive SF, desync FSM, channel plans, Multi-RX gateway support implemented and tested.
- All codereview passes closed. Capacity gains verified in simulation per independent oracles.

## References

### Normative References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997, <https://www.rfc-editor.org/info/rfc2119>.

- `test/vectors/ccp16.json` (authoritative for all MUST-match behavior; all arbitrary constants justified in Appendix A of appendix-design-rationale.md or parameterized via beacon/Kconfig)

- `spec/drafts/draft-lichen-rpl-lora-00.md`
- `spec/drafts/draft-lichen-schc-lora-00.md`
- `spec/appendix-design-rationale.md`
- `lichen/subsys/lichen/link*` (for `lichen_link_set_slot()`, `tdma_tx_allowed()`)
- `docs/firmware-time-provider.md`

[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](03-adaptation.md)
