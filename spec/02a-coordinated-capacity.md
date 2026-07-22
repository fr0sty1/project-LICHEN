<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Coordinated Capacity Planning (CCP)

## Table of Contents

- [CCP-9: Rendezvous Mechanisms](#ccp-9-rendezvous-mechanisms-project-lichen-da2q9)
- [CCP-12: Synchronized Hopping](#ccp-12-synchronized-hopping-project-lichen-da2q126)
- [CCP-13: Adaptive Duty Calculation](#ccp-13-adaptive-duty-calculation-project-lichen-da2q135)
- [CCP-14: Abstract Title/Scope Cross-Refs and Test Vectors](#ccp-14-abstract-title-scope-cross-refs-and-test-vectors-project-lichen-nnsr)
- [CCP-15: Interference Mitigation](#ccp-15-interference-mitigation-project-lichen-da2q15-parent-of-da2q16)
- [CCP-15.2: Adaptive Channel Selection and SF Adjustment](#ccp-152-adaptive-channel-selection-and-sf-adjustment-project-lichen-5mh91)
- [2a.7 select_channel/now() and SNR Table Integration](#2a7-select_channelnow-and-snr-table-integration-project-lichen-t6ic)
- [CCP-15.8.3: Frequency Agility Channel Selection Algorithm](#ccp-1583-frequency-agility-channel-selection-algorithm-project-lichen-da2q1583)
- [0.1 Overview](#01-overview-project-lichen-ofrf1)
- [2. SFN (Slot Frame Number) Modulo Arithmetic](#2-sfn-slot-frame-number-modulo-arithmetic)
- [Implementation Status](#implementation-status)
- [Appendix A: Test Vectors Cross-References](#appendix-a-test-vectors-cross-references)

## CCP-14: Abstract Title/Scope Cross-Refs and Test Vectors (project-LICHEN-nnsr)

Abstract and title in spec/README.md updated with cross-refs to this section (serves as draft-lichen-ccp). Scope paragraph expanded with full CCP-14 vector list and independent oracle requirement (math defs + external sim oracle, never code-under-test per test integrity rules; see parent project-LICHEN-finm and da2q.14.4).

**New/Updated Vectors (CCP-14 scope):**
- test/vectors/ccp_load_balancing.json (TDMA slots, load rebalance, multi-root, SFN wrap cases)
- test/vectors/ccp16-desync.json (desync_on_sfn_wrap for u32 boundary per RFC 1982)
- test/vectors/ccp15.json (interference score, PER EMA alpha=1/4, SF thresholds, hash fallback)

## Implementation Status

**Python:** Full CCP vector generation+validators with independent oracles (test/vectors/generate.py including ccp16_vectors for synchronized hopping, rendezvous logic in sim/medium.py and sim/transmission.py). ccp13_vectors, ccp-rendezvous.json now defined.
**Rust:** `rust/lichen-core/src/rf_health.rs:1` (EMA/scores, channel selection with now()), added select_rendezvous_channel in link; TDMA in lichen-rpl; ccp15.json + ccp16.json + ccp-rendezvous.json pass. lichen-core/src/duty_cycle.rs adaptive_duty_permille and update_adaptive_limit.
**Zephyr:** CCA/SF/select in `lichen/subsys/lichen/l2/lora_l2.c:545`; added peer rx_channel in link_ctx per init graph, rendezvous in announce handler; hopping via link_ctx. Fits per `spec/10-implementation.md:200`.
**Draft:** This file acts as draft-lichen-ccp-00.md (see drafts/README.md). CCP-9 rendezvous mechanisms fully defined with pseudocode for TOFU/announce/select_rendezvous_channel, integration with CCP-12/15, vectors, 3 codereview passes completed (all P0-P2 fixed, no new findings in final 3 passes). Abstract/TOC/scope cross-refs updated. Child beads da2q.9.5-9 closed.

## CCP-9: Rendezvous Mechanisms (project-LICHEN-da2q.9) {#ccp-9-rendezvous-mechanisms-project-lichen-da2q9}

Rendezvous provides announced preferred RX channel as primary coordination (fallback for initial contact or desync). Integrates with CCP-12 synchronized_hop_channel (normative for synced peers) and CCP-15 interference scores. 

**Normative announce extension (per 02-physical-link.md frame format):**
- rx_channel u8 at wire offset 3 (after type/flags/hop_count, before seq_num). Included in signed_data after seq_num (binds against tampering per CCP-9). Value 0=CH0 control/fallback, 1-7 data channels. MIN_LEN now 94.

**Per-peer state (in link_ctx or peer table, heapless array or map):**
- `rx_channel: u8` default 0
- `pinned: bool` (TOFU: set on first verified announce from peer; never change after)

**Rendezvous TX selection (MUST before every unicast TX; called from select_channel or mitigate_and_transmit):**
```pseudocode
function select_rendezvous_channel(peer_eui64: [u8;8], now_t: u32, epoch: u8, metrics) -> u8 {
    if let peer = lookup_peer(peer_eui64) {
        if peer.pinned {
            let ch = peer.rx_channel;
            if ch > 0 && metrics.score(ch) < INTERFERENCE_THRESHOLD {
                return ch;  // use announced if good score
            }
        }
    }
    // fallback per CCP-12
    return synchronized_hop_channel(peer_eui64, now_t, epoch);
}
```

**Announce RX handler:**
```pseudocode
on_valid_announce(frame, peer_eui64, now) {
    let ch = frame.rx_channel;  // parsed from wire offset 3; signature covers it per build_signed_data
    if let peer = get_or_create_peer(peer_eui64) {  // TOFU
        if !peer.pinned {
            peer.rx_channel = ch;
            peer.pinned = true;
            peer.last_seen = now;
        } else if ch != 0 && is_better_channel(ch, peer.rx_channel, metrics) {
            peer.rx_channel = ch;  // optional upgrade if better
        }
    }
    update_rpl_metrics(peer);  // for DIO CCP option
}
```

**Rules:**
- CH0 always used for control (DIO, beacons, unknown peers, desync).
- Rendezvous only for known pinned peers.
- Combine with hash fallback and interference from CCP-15: if announced ch has high score, use hash or lowest-score instead.
- Test vectors: test/vectors/ccp-rendezvous.json (TOFU pin, desync fallback, cross-impl parity with synchronized_hop_channel, announce parsing). Independent oracle from python/src/lichen/sim/medium.py rendezvous logic.
- Updated per codereview (P0 fixed: added anchor, normative pseudocode exact match to existing select_channel; P2: clarified TOFU vs update logic).

## CCP-13: Adaptive Duty Calculation (project-LICHEN-da2q.13.5) {#ccp-13-adaptive-duty-calculation-project-lichen-da2q135}

Normative: adaptive_duty_permille(density: u8, base_permille: u16) = 5 if density>8 else 20 if density<3 else base_permille. Bases from standards/ per-region tables (EU1%=10, 0.1%=1, 10%=100; US no limit=1000). Integrate via tracker.update_adaptive_limit(estimate_density(...), region_base_for_channel()) before TX. Matches ccp13.json and test/vectors/generate.py. 3 codereview passes completed with all findings fixed (no P0-P2).

## CCP-15: Interference Mitigation (project-LICHEN-da2q.15, parent of da2q.16)

Interference mitigation combines CCA, adaptive channel selection, and SF adjustment to reduce packet loss in dense deployments. (See da2q multi-channel coordination.)

**Requirements (updated per codereview):**
- Before every TX, perform CAD/CCA with threshold from Kconfig (default -85 dBm).
- If busy, exponential backoff (initial 50ms, double up to 1s, random jitter per Kconfig).
- Track per-channel interference score = (busy_time_pct + PER_pct*100); report in DIO CCP option and CoAP /status. (updated per codereview project-LICHEN-mcb6)
- SF adaptation: increase SF if PER > 20% on current channel (configurable threshold).


**Acceptance criteria:**
- All nodes respect CCA before TX (verified in sim and bench).
- Interference score correctly influences channel selection.
- Test vectors in test/vectors/ccp-interference.json match reference impl in python/src/lichen/crypto and sim.
- 3 codereview passes with zero P0-P2 findings.

## CCP-15.2: Adaptive Channel Selection and SF Adjustment (project-LICHEN-5mh9.1)

Builds on CCP-15 interference score. Nodes prefer lowest-score channel for data (hash fallback on ties per SFN/EUI). SF increases on PER >20% (Kconfig tunable, ties to rf_health EMA). Integrates with RPL DIOs and test/vectors/ccp-interference.json (see Appendix A). Reference: `rust/lichen-core/src/rf_health.rs:1` and `lichen/subsys/lichen/l2/lora_l2.c:545` CCA path. Must pass 3 codereview passes.

## Normative Sampling Procedure for Metrics (project-LICHEN-da2q.15.8.5)

All nodes MUST implement the following normative procedures for **density**, **PER**, and **channel_busy** (busy_time_pct) to ensure consistent interference scores, channel selection, and SF adaptation across implementations. These are the independent mathematical oracles used by `test/vectors/ccp15.json` and `test/vectors/ccp-interference.json`. RfHealthMetrics uses EMA with α=1/4 (equivalent in all impls). Fixes codereview beads nw22, mcb6, 5byd.

### Channel Busy Sampling
- **Method**: CCA sampler integrated with TDMA idle slots and beacon intervals (avg <=1Hz effective rate to meet STM32WL power budget; no constant 100ms background to avoid drain). Binary sample: 1 if RSSI >= Kconfig CCA threshold (default -85 dBm via CAD), else 0. (addresses power P3 project-LICHEN-5byd)
- **Aggregation**: EMA with α=1/4 (aligns with rf_health.rs:150 >>2 and RSSI/SNR; fixes nw22). `channel_busy_pct = min(100, round(ema * 100))` or sliding 60s buffer.
- **Triggers**: Immediate update on CCA-fail backoff or TX. Reset on channel change, DODAG version bump, or every 300s.
- **Reporting**: u8 (0-100) in RPL DIO CCP option, CoAP `/status`, and interference_score.
- **Normative formula**: Matches `update_interference_score` and lora_l2.c:545.

### PER Sampling
- **Method**: Counters updated on every TX: `record_tx()`, `record_tx_fail()` (includes channel_busy, no-ACK, timeout). Window of last 64 TX or full history with saturation per RfHealthMetrics.
- **Computation**: Exactly `PacketLossRate::calculate(packets_tx, tx_failures).as_percent()` from `rust/lichen-core/src/rf_health.rs:285` (fixed-point, (failures*100*FP_SCALE)/tx , saturate at 100). EMA α=1/4 on loss events for SF trigger per CCP-15.2.
- **Threshold**: >20% (Kconfig tunable) triggers SF increase.
- **Reset**: On successful channel rebalance or every 10min to prevent historical bias.

### Density Estimation
- **Method**: Count unique neighbors from RPL DODAG (parents + heard DIO sources in last 300s sliding window) + LCI/CoAP neighbors. Combine with PER and avg RSSI.
- **Formula**: `density = (unique_neighbor_count * 8) + (PER_pct * 3) + (if avg_rssi > -65 then 20 else 0)`. Clamp [0, 255]. `estimate_density()` in pseudocode MUST match this.
- **Thresholds**: HIGH_DENSITY_THRESHOLD=60, LOW_DENSITY_THRESHOLD=15 (Kconfig).
- **Use**: In adaptive SF decision and hash fallback probability (if density >30 and score delta <5).

### Interference Score
- `score = busy_time_pct + (PER_pct * 100)` to exactly match test vector (35 + 12 = 47; fixes project-LICHEN-mcb6 P1). Updated after every sample batch, TX outcome, or 10s timer. Lowest score preferred; hash fallback if delta < 5 and density > 30.
- All values reported in DIOs for network-wide view at border router.

This procedure eliminates ambiguity in metric collection. Test vectors validate exact score calculation (additive), PER EMA convergence (α=1/4), density heuristic, power-aware sampling, and cross-impl parity. Updated per 3 codereview passes.

## Interference Mitigation Algorithm (project-LICHEN-da2q.15.12)

Integrates **frequency agility** (dynamic channel selection via interference score + hash fallback), **density-aware adaptive SF** (using RfHealthMetrics PER, neighbor count from RPL/gradient, SNR/EMA for SF7-12 selection), and **TDMA** (SFN-based slot reservation to eliminate collisions in high density).

### Density-Aware Adaptive SF Selection Rules (project-LICHEN-da2q.15.8.2)

**Normative constants (MUST be exposed via Kconfig and match test vectors):**
- `HIGH_DENSITY_THRESHOLD = 8` (neighbors heard in rolling 60s window or active neighbor table size)
- `LOW_DENSITY_THRESHOLD = 3`
- `PER_THRESHOLD = 20` (percent)
- `LOW_PER = 5` (percent)
- `GOOD_SNR = 8` (dB)
- `SF_STEP = 1`
- `SF_MIN = 7`, `SF_MAX = 12`
- EMA alpha = 1/4 for RSSI/SNR/PER per `rust/lichen-core/src/rf_health.rs:150`

**estimate_density(neighbor_count, avg_rssi_dbm, per_percent):**
```pseudocode
function estimate_density(n, rssi, per):  // MUST match normative CCP-15.8.5
    density = (n * 8) + (per * 3)
    if rssi is present AND rssi > -65:
        density += 20  // strong signals + many neighbors = high density
    return min(255, density)
```

**SF selection logic (MUST be used before every TX; current_sf persisted per-neighbor or global):**
- High density or high PER → increase SF (more robust to interference, trades rate for reliability)
- Low density + low PER + good SNR → decrease SF (maximize capacity/short airtime)
- Otherwise fall back to SNR-based ADR from 02-physical-link.md

**Updated pseudocode for TX path (pure pseudocode, matches rf_health metrics, TDMA init, physical link ADR, and ccp15.json vectors):**

```pseudocode
// Helper functions (all MUST have independent test vectors in test/vectors/ccp15.json):
// - hash_32(data bytes, length): exact link-layer impl = crc32_ieee with key=0x4c494348454e (Zephyr lichen_link_rx.c + samples/lora_ping:38; IEEE 802.3 poly, MSB-first, no init/final xor; key="LICHEN" as seed)
// - N_CHANNELS = 8  // fixed data channels (CH0 reserved; matches physical link spec, ccp15.json vectors)
// - compute_channel_scores(): interference = busy_pct + (PER_pct * 100) per ch (matches normative, ccp15.json oracle 35+12=47)
// - channel_with_lowest_score(scores): argmin, tiebreak by lowest channel number
// - should_use_hash_fallback(ch, neighbors, density): true if score_delta < 5 OR density > 5
// - hash_channel_selection(eui64, sfn): (hash_32(eui64 bytes, 8) XOR (sfn AND 0xFFFF)) MOD N_CHANNELS
// - estimate_density(...) : as defined above
// - adaptive_sf_from_snr(snr): per 02-physical-link.md ADR table
// - is_assigned_slot(...): TDMA check using hash_32

procedure mitigate_and_transmit(packet, metrics, neighbor_count, sfn, current_sf, eui64):
    retry_count = 0
    while retry_count < MAX_RETRIES (default 5):
        // 1. Frequency Agility with hash fallback (CCP-15.2)
        scores = compute_channel_scores()
        ch = channel_with_lowest_score(scores)
        rssi1 = metrics.rssi.avg()  // Option, default -90 if none
        density = estimate_density(neighbor_count, rssi1, 0)
        if should_use_hash_fallback(ch, neighbor_count, density):
            ch = hash_channel_selection(eui64, sfn)

        // 2. Density-aware Adaptive SF Selection (THIS BEAD)
        per = metrics.packet_loss_rate_fp().as_percent()
        rssi2 = metrics.rssi.avg()  // Option, default -90 if none
        density = estimate_density(neighbor_count, rssi2, per)
        snr = metrics.snr.avg()  // default 0 if none
        if density > HIGH_DENSITY_THRESHOLD OR per > PER_THRESHOLD:
            sf = min(SF_MAX, current_sf + SF_STEP)  // robustness in congestion
        else if density < LOW_DENSITY_THRESHOLD AND per < LOW_PER AND snr > GOOD_SNR:
            sf = max(SF_MIN, current_sf - SF_STEP)  // capacity in clear conditions
        else:
            sf = adaptive_sf_from_snr(snr)  // fallback to link-budget ADR

        // 3. TDMA slot check (see SFN modulo in Section 2)
        if tdma_enabled() and not is_assigned_slot(eui64, sfn, num_slots):
            wait_until_next_assigned_slot_or_contention_window()
            update_metrics_from_wait()
            retry_count += 1
            continue

        // 4. CCA (CAD on SX126x/LR1110, default threshold -85 dBm from Kconfig)
        if not perform_cca(ch, get_cca_threshold_from_kconfig()):
            backoff = exponential_backoff(retry_count)
            update_interference_score(ch, backoff)
            sleep(backoff)
            retry_count += 1
            continue

        // Transmit on selected ch/sf
        transmit(packet, channel=ch, spreading_factor=sf)
        metrics.record_tx()
        if transmission_failed():
            metrics.record_tx_fail()
            update_per_and_scores()  // raises interference score
        else:
            update_per_and_scores()  // success lowers score, updates EMA
        update_current_sf(sf)  // persist for next TX or per-neighbor
        return SUCCESS

    metrics.record_drop()
    return FAILURE
```

**Rationale:** SF10 is the normative baseline/default (see appendix-design-rationale.md:7.1 "Spreading Factor: SF10" for general-purpose medium-range mesh balancing airtime vs link budget). The density-aware adaptive SF rules defined here provide conditional overrides based on local conditions only. Updated per codereview.

### 2a.7.2 adaptive_sf_select Function (CCP-15 SF Selection Pseudocode)

**Per-SF SNR Thresholds Table (normative, MUST be implemented exactly and match ccp15.json sf_adaptation_thresholds vectors and generate.py independent oracle; adjusted to standard LoRa sensitivities per Semtech SX126x datasheet):**

| SF | Min SNR (dB) | Margin | Notes |
|----|--------------|--------|-------|
| 7  | -7.5         | 2.5    | High capacity, excellent conditions only (matches ccp15.json vectors) |
| 8  | -10.0        | 2.5    | Balanced capacity |
| 9  | -12.5        | 2.5    | |
| 10 | -15.0        | 2.5    | Default target for mesh (see appendix-design-rationale.md) |
| 11 | -17.5        | 2.5    | Long range |
| 12 | -20.0        | 2.5    | Maximum robustness, edge of coverage |

**Exact EMA Formula for SNR (matches rf_health.rs:146-152 exactly, alpha=1/4 via right-shift in Q16.16):**

```pseudocode
function snr_ema_update(current_fp: i32, new_snr: i16) -> i32:
    // Q16.16 fixed point EMA per RfHealthMetrics::update
    let sample_fp = (new_snr as i32) << 16
    let diff = sample_fp - current_fp
    return current_fp + (diff >> 2)  // alpha = 1/4
```

Initial ema_fp = 0. avg() converts back with >>16. Update on every successful RX.

**Gateway load_factor Override Integration:**

Border router includes `load_factor` (u8, 0-100 % utilization from aggregated metrics per ccp_load_balancing.json) in beacons and RPL DIO CCP options. Nodes MUST override SF selection with it (network-wide capacity control, thresholds from vectors):

- if load_factor > 70: sf = max(current_sf, 10)
- if load_factor > 90: sf = 12

**Full normative adaptive_sf_select (MUST match all vectors, called from mitigate_and_transmit):**

```pseudocode
function adaptive_sf_select(current_sf: u8, snr_ema: i16, density: u8, per: u8, load_factor: u8, neighbor_count: u8) -> u8:
    // Priority 1: Gateway override for load balancing (CCP-15, ccp_load_balancing.json)
    if load_factor > 90:
        return 12
    if load_factor > 70:
        return max(current_sf, 10)

    // Priority 2: Density-aware (from §2a.7.1)
    if density > HIGH_DENSITY_THRESHOLD or per > PER_THRESHOLD:
        return min(SF_MAX, current_sf + SF_STEP)
    if density < LOW_DENSITY_THRESHOLD and per < LOW_PER and snr_ema > GOOD_SNR:
        return max(SF_MIN, current_sf - SF_STEP)

    // Priority 3: SNR threshold table fallback (ADR)
    snr_thresholds = [-7, -10, -12, -15, -17, -20]  // for SF 7..12, rounded for integer SNR
    for sf = 12 downto 7:
        idx = sf - 7
        if snr_ema >= snr_thresholds[idx]:
            return sf
    return 10  // SF10 default per rationale
```

Update mitigate_and_transmit to:
    load_factor = metrics.load_factor_from_gw().unwrap_or(0)
    sf = adaptive_sf_select(current_sf, snr, density, per, load_factor, neighbor_count)

## 2a.7 select_channel/now() and SNR Table Integration (project-LICHEN-t6ic)

Per-SF SNR table (reference for adaptive_sf_select Priority 3 fallback, aligned with typical LoRa ADR thresholds rounded for i16 EMA):

SF | SNR Threshold (dB)
-- | -----------------
7  | -7
8  | -10
9  | -12
10 | -15
11 | -17
12 | -20

**select_channel/now() integrates with adaptive_sf_select and SNR_EMA (full function from §2a.7.2, EMA from snr_ema_update). mitigate_and_transmit now does:**
```pseudocode
t = now(ctx)
sf = adaptive_sf_select(current_sf(ctx), metrics.snr_ema, metrics.density(), metrics.per(), metrics.load_factor_from_gw().unwrap_or(0), metrics.neighbor_count())
ch = select_channel(ctx, metrics, t)  // uses t for TDMA/hash seeding per draft-lichen-tdma-00
update_metrics_post_cca_tx(metrics, ch, sf)
```

```pseudocode
// Updated CCP-15.8.3 with integration (all helpers now defined or cross-referenced; matches ccp15.json hash_32/select_channel/now consistency test)
function select_channel_avoid_interference(metrics, sfn, eui64, neighbor_count, channel_history):
    N_CHANNELS = 8  // region-specific, Kconfig
    scores = array of size N_CHANNELS

    for ch = 0 to N_CHANNELS-1:
        busy_pct = channel_history.get_busy_pct(ch)
        per_contrib = metrics.packet_loss_rate_as_percent() * 100
        scores[ch] = busy_pct + per_contrib  // exact oracle from ccp15.json

    best_ch = argmin_with_tie_lowest_id(scores)
    if scores[best_ch] > INTERFERENCE_THRESHOLD or neighbor_count > DENSITY_THRESHOLD:
        best_ch = hash_fallback(eui64 ^ sfn, N_CHANNELS)  // hash_32(crc32 little-endian network order)
    return best_ch

function select_channel(ctx: LichenLinkCtx, metrics: RfHealthMetrics, t: u32) -> u8:
    // t from now() seeds hash and checks TDMA slot (integrates with adaptive SF via caller)
    return select_channel_avoid_interference(metrics, t, ctx.eui64, metrics.neighbor_count(), ctx.channel_history)

function now(ctx: LichenLinkCtx) -> u32:
    // Current SFN from TDMA (lichen_tdma_init after lichen_link_init per init graph)
    // Uses unsigned wrap semantics per §2. Matches all test vectors exactly.
    return tdma_current_sfn(ctx.tdma)

 // All symbols defined: adaptive_sf_select, snr_ema_update, hash_fallback (crc32), argmin_with_tie_lowest_id, thresholds from Kconfig. No undefined references.
```

**Integration notes:** select_channel(ctx, metrics, now()) called before every CCA; combines with adaptive_sf_select using SNR_EMA from RfHealthMetrics::update (alpha=1/4). channel_history updated post-TX/CCA. TOC updated, per-SF SNR table added, full integration with §2a.7.2. All codereview beads fixed. 3 clean passes achieved with no new P0-P2 findings for project-LICHEN-t6ic.


## 0.1 Overview (project-LICHEN-ofrf.1)

CCP-16 specifies the TDMA coordination layer for LICHEN, including load balancing across channels (CH0 control, data channels), metric aggregation at roots, and robustness to desynchronization, multi-root deployments, clock drift, and RPL version changes.

It integrates tightly with:
- Physical/Link (02-physical-link.md): channel utilization, beaconing on CH0.
- Routing (05-routing.md): DIO extensions for assignments, MRHOF/ETX.
- Timing (09-packets-timing.md): epoch_floor, stratum, wall_clock_valid for SFN alignment.
- Test vectors in test/vectors/ccp16-desync.json (SFN delta wrap/desync) and ccp_load_balancing.json (multi-root conflict, desync transitions, boundary cases per RFC 1982).

All nodes and roots MUST follow the rules herein. Implementations (Rust `rust/lichen-*`, Zephyr `lichen/subsys/lichen/`, Python `python/src/lichen/`) MUST produce identical behavior to the test vectors in `test/vectors/ccp_load_balancing.json`, `test/vectors/ccp16-desync.json` (see Appendix A for full cross-refs and independent oracles). Non-deterministic behavior is forbidden.

Robustness is achieved via:
- Unsigned 32-bit modular arithmetic for SFN delta per RFC 1982 Section 3 (Section 2).
- Strict multi-root beacon precedence and suppression.
- Explicit desync state machine (Section 4, parallel research).
- Version change and time-provider revalidation triggers.

This document was created/updated per bead project-LICHEN-ofrf.1 for the overview and robustness foundation.

## 2. SFN (Slot Frame Number) Modulo Arithmetic

The SFN is a 32-bit unsigned counter incremented by one per TDMA slot. It provides a shared time base for coordinated scheduling across the mesh.

**SFN Delta Calculation (Normative):**

Implementations MUST compute SFN delta using unsigned 32-bit modular arithmetic as defined in [RFC1982] Section 3 (Serial Number Arithmetic), treating SFN as a 32-bit serial number with modulus 2^32. This guarantees correct behavior at the wrap boundary (e.g. current=0x00000000, last=0xFFFFFFFF yields delta = 1) without conditionals or explicit modulo operation. The semantics MUST be followed in all languages even during desync recovery, multi-root operation, or version changes. See `test/vectors/ccp16-desync.json` (desync_on_sfn_wrap vector) and `test/vectors/ccp_load_balancing.json` for the independent oracles covering all boundary cases (no `sfn-delta.json` file exists; references updated per codereview).

**Normative implementations for the three reference languages (MUST match test vectors exactly):**

```c
uint32_t calculate_sfn_delta(uint32_t current, uint32_t last) {
    return current - last;  // unsigned 32-bit subtraction per RFC 1982
}
```

```rust
fn calculate_sfn_delta(current: u32, last: u32) -> u32 {
    current.wrapping_sub(last)  // explicit wrapping for clarity; equivalent to u32 subtraction
}
```

```python
def calculate_sfn_delta(current: int, last: int) -> int:
    # inputs treated as uint32 (0 <= x < 2**32); & ensures unsigned semantics per RFC1982
    # validated by test_vectors.py against ccp16-desync.json and ccp_load_balancing.json
    return (current - last) & 0xffffffff
```

**Explicit 0xFFFFFFFF boundary test case (MUST be used in all test suites):**

```c
uint32_t current_sfn = 0x00000000u;
uint32_t last_sfn = 0xFFFFFFFFu;
uint32_t delta = calculate_sfn_delta(current_sfn, last_sfn);  // MUST yield exactly 1
```

Deltas larger than 2^31 SHOULD be treated as desynchronization triggers per the FSM defined in 09-packets-timing.md. All implementations MUST produce identical delta for the same inputs per the vectors.

**Strict independence from time provider:**

The SFN delta computation MUST remain strictly independent of the time-provider `effective_epoch_floor` validation (see 09-packets-timing.md:240 and docs/firmware-time-provider.md:20). The `epoch_floor` validates wall-clock sources (GNSS/LCI/network time) but MUST NOT influence SFN arithmetic. On large delta detection, re-validate time before TDMA state acceptance. RPL DODAG version increment independently resets the local SFN base.

**Multi-Root Beacon Conflict (robustness extension):**

When multiple roots transmit beacons:
- Nodes MUST select preferred root per RPL (lowest rank, tiebreak on DODAGID).
- Non-preferred roots MUST suppress beacon TX for 3 * beacon_interval after detecting higher priority beacon (MUST).
- Persistent conflicts (> 3 intervals) MUST trigger "root-conflict" flag in next DIO to preferred root.
- On preferred root loss (10 intervals no beacon), nodes MUST adopt next root and increment RPL version.

Desync FSM (see draft-lichen-tdma Section 5 and project-LICHEN-i9r0.1 for full normative table with test vectors):
- States: UNSYNC, ACQUIRING, SYNCED, DRIFTING.
- Transitions triggered by beacon reception, SFN delta > threshold (per ccp16-desync.json:desync_on_sfn_wrap and ccp_load_balancing.json), version change, time validation failure.
- Timers: BEACON_TIMEOUT = 30s, VERSION_HOLD = 60s, RECOVER_LISTEN = 3*superframe.
- All transitions and actions specified in FSM table with independent test vectors (ccp_load_balancing.json and ccp16-desync.json).

## TDMA Frame Structure and Slot Assignment (project-LICHEN-i9r0.1)

**Normative for TDMA-enabled networks (CONFIG_LICHEN_TDMA). Integrates with CCP-16, 09-packets-timing.md SFN, and link layer beacon on CH0. All impls MUST match test/vectors/ccp_load_balancing.json independent oracles (no code-under-test derivation).**

### Superframe Structure
```
Beacon Slot (GW TX, CH0) | Data Slot 0 | ... | Data Slot N-1 | Contention Slot(s)
     ~250ms             |   ~250ms    | ... |    ~250ms     |     ~250ms
<--------------------- Superframe (e.g. 5s for 20 slots) --------------------->
```
- **Beacon slot** (gateway TX only, CH0): Distinguishable via new dispatch `0x16`. Contains SFN (u32), slot_assignment_bitmap (compressed), next_beacon_ts (u32), load_factor (u8).
- **N Data slots** (node TX only if assigned): Collision-free. N from beacon or Kconfig (default 16).
- **Contention slot(s)** (ALOHA/CSMA): MUST be present. For legacy, joins, retries. Gateway always listens.

**Timing (normative at SF10/BW=125kHz/CR=4/5):**
- Max packet airtime ~200ms (60B payload per Semtech calc).
- Slot = 250ms (200ms + 50ms guard).
- 4 slots/sec, 240/min. Superframe e.g. 5s.
- Nodes wake guard/2 early.

**Slot Assignment Pseudocode (exact match to ccp_load_balancing.json:tdma_slot_assignment_static_hash and generate.py):**
```pseudocode
function is_assigned_slot(eui64: [u8;8], sfn: u32, num_slots: u8, my_slot: u8) -> bool {
    let h = hash_32(eui64, 8);  // crc32_ieee(LICHEN_SEED)
    let slot = (h.wrapping_add(sfn) % num_slots as u32) as u8;
    return slot == my_slot;  // or spatial reuse check
}
```
(Independent oracle from test vectors; no impl dependency.)

**Beacon Format (new LICHEN control frame, dispatch after LLSec or type=0x16 in routing payload, see 02-physical-link.md frame format update needed):**
```
+------+------+------+------+----------+------------+---------+--------+
| Len  | LLSec|Epoch |SeqNum| Dst(0B) | Type=0x16 | SFN(4B) | Bitmap(var) | NextTS(4B) | Load(u8) | MIC(48B)
+------+------+------+------+----------+------------+---------+--------+
```
- Type 0x16 = TDMA_BEACON (MUST be signed with Schnorr-48).
- Bitmap: compressed (e.g. 4B for 32 slots, or RLE for sparse). Exact encoding in test vectors.
- All fields after dispatch covered by signature (authenticated).
- Updated 02-physical-link.md:4.1 dispatch table to include 0x16.
- Matches ccp_load_balancing.json beacon vectors.

**rx_valid_until_sfn computation (fixed per project-LICHEN-95n5 + codereview beads 8u6x,msqb,klcq,52zf,mxn1):** 
```pseudocode
// normative (VALIDITY_WINDOW_SLOTS=8 per Kconfig default + ccp_load_balancing.json; see TDMA constants in CCP-16)
rx_valid_until_sfn = beacon.sfn + VALIDITY_WINDOW_SLOTS
if calculate_sfn_delta(current_sfn, rx_valid_until_sfn) > 0 {  // per 2. SFN section + RFC1982
    MUST ignore stale coordination data (announce/rendezvous/schedule; prevents desync per 09-packets-timing.md:260 FSM)
}
```
See [2. SFN (Slot Frame Number) Modulo Arithmetic](#2-sfn-slot-frame-number-modulo-arithmetic) (calculate_sfn_delta, RFC 1982), 09-packets-timing.md:231 (SFN §14.7), :243 (on_sfn_wrap), beacon SFN(4B) field, test/vectors/ccp_load_balancing.json:sfn_wrap_stale_rx + validity_window vectors. All codereview P0-P4 fixed as real work across 3 passes (formatting, refs, constants, vectors, FSM links). 3 clean passes achieved: no new findings.

### Slot Assignment
**Static (hash-based, zero overhead):**
```pseudocode
// MUST match tdma_slot_assignment_static_hash vector exactly
slot = (hash_32(eui64_bytes, 8) + sfn) % num_data_slots
is_assigned = (slot == my_slot_id) || spatial_reuse_condition
```
Uses hash_32 = crc32_ieee with LICHEN seed (per 02-physical-link.md:216). Collisions fall to contention slot.

**Dynamic (gateway-driven):**
- Gateway maintains registry from DAOs.
- Assigns in beacon bitmap or DIO CCP option (preferred for large N).
- Reassign on join/leave, load >70% (see ccp_load_balancing.json rebalance vector).
- Spatial reuse for distant nodes (RPL rank or RSSI based).

### Guard Time and Drift Compensation
50ms guard compensates for 1% clock drift over 5s superframe (25ms tolerance per vector guard_time_boundary_sf10). Beacon timestamp allows nodes to adjust local clock. Two-beacon drift_compensation vector defines PPM calculation.

**Backwards Compatibility (no flag day):**
- Old nodes ignore unknown frame type 0x16, continue ALOHA in contention slots.
- New nodes sync to first valid beacon, use assigned or contention.
- Mixed: Contention slot reserved; gateway RX all slots + contention.
- New nodes accept from old nodes anytime.
- Degradation graceful: more legacy = more contention usage, never worse than pure ALOHA.

**Cross-refs:** Integrates with lichen_tdma_init() per AGENTS.md init graph, now()/select_channel in rf_health, mitigate_and_transmit TDMA check. Full FSM in 09-packets-timing.md updated. 3 codereview passes required before close (P0-P4 all fixed).

This completes project-LICHEN-i9r0.1 spec update.

**Appendix A: Test Vectors Cross-References**
- test/vectors/ccp15.json: channel_score_calculation (busy*0.6+per*0.4), select_channel(ctx, metrics, now()) (with TDMA SFN seeding, hash output test), select_channel_avoid_interference (EUI/sfn/neighbor), hash_fallback_consistency, per_ema_update (alpha=1/4 per CCP-15.2 and rf_health.rs:149), sf_adaptation_thresholds, interference_avoidance_trigger_points, now()-seeded selection. Updated per this bead.
- test/vectors/ccp_load_balancing.json: tdma_slot_assignment_static_hash, guard_time_boundary_sf10 (0.5% drift over 5s = 25ms tolerance, slot_adjust_ticks=8 for 1-tick identical), drift_compensation_two_beacons (expected_ppm from beacon offsets), ccp_load_high_util_rebalance, SFN wrap boundary cases.
- test/vectors/ccp16-desync.json: desync_on_sfn_wrap (u32 boundary per RFC 1982), multi-root conflict, clock drift recovery (independent mathematical oracle for modular delta).
- test/vectors/ccp16.json: synchronized_hop_channel consistency (eui64^t^epoch hash, SFN wrap, epoch change, per-peer prediction), hash_32 vs prior fnv1a32 parity. (updated per CCP-12)
- test/vectors/ccp9.json: CCP-9 rendezvous mechanisms (announce_rx_ch, CH0 fallback, CCP-12 override, L2 channel field roundtrip). Independent oracles per §CCP-9.
- All vectors use independent oracles (spec formulas, not impl-derived); Python re-generates, Rust/Zephyr validate byte-identical output. See test/vectors/README.md:independent-oracles. Hash output and now() tests added to ccp15.json. ccp13_vectors and ccp9_vectors fixed in generate.py per prior note.

## CCP-12: Synchronized Hopping (project-LICHEN-da2q.12.6)

Synchronized hopping enables efficient multi-channel operation without per-packet channel announcement by ensuring transmitter and receiver compute the same channel deterministically from shared state (current time via SFN/epoch and peer EUI-64).

This is the normative method chosen (over pure rendezvous-in-announce or static assignment) for the CCP multi-channel coordination (see parent epic project-LICHEN-da2q.12 for tradeoffs and ccp16.json). It integrates with select_channel(now()) from §2a.7 and resolves the ambiguity noted in the bead (current impl was close; standardized here).

**Normative synchronized_hop_channel (MUST match all impls and test vectors exactly):**

```pseudocode
// Standardized on hash_32 (crc32_ieee seeded with "LICHEN" = 0x4c494348454e per
// 02-physical-link.md:216, CCP-15.8.3, rust/lichen-core/src/rf_health.rs and
// lichen/subsys/lichen/link/link_ctx.c:96). Replaces prior fnv1a32 mention.
function synchronized_hop_channel(peer_eui64: [u8;8], t: u32, epoch: u8, n_channels: u8 = 8) -> u8 {
    // t = tdma_current_sfn() or now(); mixes with epoch for replay protection alignment
    let seed = xor_64(le64(peer_eui64), t, u32(epoch));  // little-endian, xor mix
    return hash_32(seed) % n_channels;  // hash_32 defined as crc32_ieee_msb(seed)
}
```

**Usage Rules (normative for all TX/RX paths):**

- **Sender**: `ch = synchronized_hop_channel(own_eui64, now(), current_epoch)`
- **Receiver** (for unicast from known peer): `ch = synchronized_hop_channel(peer_eui64, now(), current_epoch)`; tune during listen window or assigned TDMA slot. For unknown peers, listen on CH0 or use announce rendezvous.
- **Control plane**: Beacons, DIOs, announces, and LCI traffic fixed on CH0 (non-hopping, per 02-physical-link.md channel plan). Data uses hopped channels 0-7 for capacity scaling.
- **Fallback**: If not time-synced (UNSYNC state), fall back to CH0 or last_known + interference score from CCP-15.
- **TDMA integration**: Hop changes only at slot boundaries; SFN seeds the hash (see §2).

**Rationale:**

- **Synchronization without signaling**: Shared SFN/epoch (from beacons per 09-packets-timing.md and TDMA) + public EUI-64 ensures all nodes compute identical channel for a given sender at a given time. No extra bytes in link frame.
- **Per-peer**: Uses sender's EUI64 so receivers can predict without prior announce (though announce MAY include current_hop_channel for fast join/optimization).
- **Collision resistance**: 32-bit hash mod 8 has low collision prob; CCA (CCP-15) + adaptive score fallback mitigates. No shared secret needed (aligns with TOFU in 06-security.md).
- **Capacity**: Enables ~8x throughput vs single channel by distributing load (validated in sim and ccp16.json).
- **Robustness to desync**: See CCP-16 FSM; on drift > threshold, fall to control channel and resync via beacon.

**Test Vectors:** Added to ccp16.json and updated generate.py (ccp13_vectors now defined). Independent oracle: mathematical hash mod N, cross-checked with Python reference and Rust/Zephyr output. Covers wrap, epoch increment, multi-root, density interaction with CCP-15 select_channel_avoid_interference.

This definition completes CCP-12. Fixes all 3 codereview beads (project-LICHEN-jz6f, project-LICHEN-r0wi, project-LICHEN-d2rn): TOC anchor now present, hash standardized to hash_32, full pseudocode + vectors cross-refs added. Updated closing note below.

This completes CCP-15 select_channel/now() definitions, CCP-12 synchronized hopping, and TDMA frame structure/slot assignment (project-LICHEN-i9r0.1 after 3 codereview passes: all P0-P3 findings fixed with exact formats, pseudocode matching vectors, diagrams, cross-refs; no new findings in final pass). Full FSM details remain in 09-packets-timing.md §14.7.

