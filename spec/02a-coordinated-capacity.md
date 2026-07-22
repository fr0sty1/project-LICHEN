<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Coordinated Capacity (CCP)

## Introduction to CCP-16

LICHEN's Coordinated Capacity Profiles (CCP-n) provide incremental improvements to medium access. CCP-1 delivers basic TDMA, hash-based slotting, and rendezvous for capacity gains over ALOHA. CCP-9 completes rendezvous mechanisms with Announce-driven preferred RX channel (including Schnorr-48 signed preference), explicit hash fallback, and control-channel fallback protocol. CCP-12 adds synchronized channel hopping (shared hop sequence synchronized via SFN or GPS, rendezvous protocol per §2a.8). CCP-16 adds multi-root beacon conflict resolution, dynamic load balancing via DIO load metrics, density- and SNR-aware adaptive SF selection, multi-channel coordination with gateway-directed assignment, and a precise FSM for desynchronization recovery. This document follows IETF style.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here. 

## Scope

**TOC:** Introduction; Requirements; Scope; 2a.1 TDMA; 2a.2 Channel Agility; 2a.3 Rendezvous; 2a.4 Beacon/FSM (incl. CCP-15.2 CCA integration per interference mitigation); 2a.5 Drift/Compensation; 2a.6 Join; 2a.7 Interference Mitigation (incl. §2a.7.1 normative sampling for density, PER, channel_busy); 2a.8 Synchronized Hopping (CCP-12: hop sequence, SFN/GPS sync, rendezvous protocol per RFC2119); References; Appendix A (constants/drift/slot_adjust_ticks=8); Appendix C.

This document defines the baseline mechanisms for coordinated medium access in LICHEN meshes (cross-ref: Appendix A for constants & drift constant; §2a.5, draft-lichen-tdma for drift compensation & FSM; CCP-15.2 for CCA). CCP-16 compliant nodes implement all CCP-1 behaviors plus the advanced coordination features described herein. Implementations MUST produce identical behavior to the test vectors in test/vectors/ccp_load_balancing.json (incl. slot_adjust_ticks=8), tdma-timing.json, and related files (see Appendix C).

## 2a.1. TDMA Time Slots

### Superframe Structure

A superframe consists of:
- 1 Beacon slot (root/gateway TX)
- N Data slots (assigned or hashed)
- 1 Contention slot (CSMA/ALOHA for joins, retries, legacy nodes)

**Default parameters (SF10, 125kHz, 60B payload):** These values are recommended defaults; see Appendix A for justification and parameterization guidance. All are advertised or configurable via beacon params or Kconfig (LICHEN_TDMA_*).

| Parameter | Value | Notes |
|-----------|-------|-------|
| Slot duration | 250 ms | Derived from airtime + guard_time (configurable) |
| Superframe length | 8 slots (2 s) | Power-of-two; advertised in beacon (nds+1) |
| Guard time | 50 ms | See Appendix A for drift tolerance analysis |

Nodes synchronize to the beacon's Epoch and Superframe Number (SFN). The beacon frame includes current SFN, slot allocation bitmap or map, and absolute timestamp for next beacon to enable drift compensation (see §2a.4).

**Guard Time and Drift Compensation:**

The guard time provides tolerance for crystal drift, turnaround, sync error, propagation, and legacy node margin. Receivers align slot windows using `t_slot = t_beacon + (slot_index * slot_duration) ± (guard_time/2)`. Implementations include drift compensation in the scheduler. Nodes maintain clock sync within the bound specified in the FSM (see §2a.4.1).

Test vectors for timing, slot alignment, and hash assignment are provided in `test/vectors/tdma-timing.json` (see Appendix C).

### Slot Assignment

1. **Hash-based (default for CCP-1)**: slot = hash(EUI64, SFN) % N_DATA_SLOTS
2. **Dynamic assignment**: root uses DIO options or dedicated beacon field to assign specific slots to active nodes (for load balancing, CCP-16).

Collision probability managed by N_slots >> active nodes per channel.

## 2a.2. Frequency/Channel Agility

LoRa networks use multiple channels per band. CCP-1 defines:

- **Control channel**: Fixed frequency for beacons, DIOs, rendezvous (e.g. default channel per region).
- **Data channels**: Hopped or assigned. Nodes advertise current RX channel in Announce or DIO.

**Channel selection**:
- Pseudo-random hopping sequence based on SFN and DODAG ID (to avoid persistent interference).
- Or gateway-directed channel assignment for dense areas (CCP-16 extension).

Nodes listen on control channel during beacon/contention slots, hop to assigned data channel for their TX/RX slots.

## 2a.3. Rendezvous (CCP-9)

Rendezvous ensures sender and receiver are on same channel and time slot for multi-channel meshes (CCP-9 completion).

**Normative Mechanisms (priority order, RFC2119 MUST):**
1. **Scheduled**: Use beacon/DIO slot assignment + channel map from root (preferred for CCP-16 dense nets).
2. **Hash-based rendezvous** (CCP-1/9 default): Both endpoints compute `channel = hash_32(SFN, peer_EUI64 ^ group_ID) % N_CHANNELS`; `slot = hash_32(SFN, peer_EUI64 ^ group_ID, hseed) % N_SLOTS` (using extended hash or chseed/hseed from beacon per §2a.4). Uses FNV-1a from §2a.7.1 exactly; deterministic, no state.
3. **Announce-driven** (CCP-9 core): Last Announce from peer includes `current_channel` (u8 at wire byte 3 per 05-routing.md:184, included in signed_data() after seq_num per Rust/Python impls) . The announced value is the scheduler's current preferred RX channel (from local CCP/TDMA select_channel() or equivalent; default 0/control if unknown). Sender switches TX to announced channel if within validity window. Announce signed with Schnorr-48 per security model.
4. **Fallback**: Control channel (CH0) in next contention slot with CSMA/CCA.

All nodes MUST listen on control channel at least every superframe for beacons, Announces, and neighbor discovery. Receivers advertise preferred RX channel in Announce based on local `select_channel()` from §2a.7. The AnnounceScheduler MUST be provided the current value before each build_announce() (via config, shared state, or callback).

(Note: rx_valid_until_sfn deferred to future extension; binary header only for now. CBOR mention removed for consistency with L2 binary announce format.)

**Compatibility**: Uncoordinated nodes use ALOHA on any channel; CCP nodes use contention slot + CCA. Test vectors in `test/vectors/ccp_load_balancing.json` and new `test/vectors/ccp9-rendezvous.json` (to be generated). All impls (Python sim source-of-truth, Rust, Zephyr) MUST match exactly.

See §2a.8 for CCP-12 synchronized hopping rendezvous integration.

## 2a.4. Beacon Procedure

**Purpose:** Primary synchronization, schedule dissemination, drift reference, and DODAG maintenance anchor for TDMA rendezvous.

**Transmission Rules (MUST):**
- Transmitted exclusively by DODAG root (or self-elected root in isolated mesh) in dedicated beacon slot (slot 0 of superframe).
- Exact alignment to root's clock at superframe boundary (t=0).
- Control channel only, using robust PHY params (e.g. SF12/CR4/5 for SF10 data).
- Includes truncated Schnorr-48 signature (see draft-lichen-schnorr-00.md) verifiable with root public key (TOFU or PKIX).
- Beacon interval advertised and adjustable (default 2s superframe).

**Beacon Content (exact CBOR map per CDDL in appendix, SCHC Rule ID=0x20 compressed to 18-28 bytes):**
- sfn: uint32 (monotonic; on wrap use modulo-2^32 arithmetic for all hash/scheduling computations to maintain continuity)
- ts: uint32 (Unix epoch or mesh epoch; MUST be >= time provider epoch_floor per spec/09-packets-timing.md:176; stratum=1 for mesh beacons)
- params: map
  - nds: uint8 (num data slots, default 7)
  - g: uint8 (guard_ms, default 50)
  - chseed: uint16 (PRNG seed = hash(DODAGID, sfn) for channel sequence)
  - hseed: uint32 (for slot = hash(EUI64, sfn, hseed) % nds)
  - drift: int16 (ppm * 100, root crystal drift estimate)
- rank: uint16 (RPL rank snippet)
- sig: bstr (exactly 48 bytes truncated Schnorr per draft-lichen-schnorr-00 Appendix A test vectors)
**Note:** Full CDDL and example CBOR hex in test/vectors/tdma_beacon.json (to be added). LLSec header applies per link spec with root key.

### 2a.4.1. SFN Wrap-Around (Modulo Arithmetic)

The SFN is a uint32 that increments monotonically and wraps using modular arithmetic. All nodes MUST compute using unsigned 32-bit modulo (2^32) for:

- Delta calculation: `delta_sfn = (current_sfn - last_sfn) mod 2^32` (MUST use unsigned 32-bit arithmetic; see explicit 0xFFFFFFFF boundary example below)
- If `delta_sfn > 2^31`, interpret as backward wrap (though operationally rare).
- All hash-based slot and channel rendezvous: `hash(EUI64, (sfn mod 2^32), seed) % N`. All nodes MUST use identical modulo semantics here (cross-reference draft-lichen-tdma §4.2 for RFC 1982 serial number arithmetic).
- Predictive scheduling and drift compensation formulas. Nodes MUST validate `ts >= epoch_floor` independent of SFN modulo wrap per time-provider spec (spec/09-packets-timing.md:176 and §2a.4.2). SFN computations MUST NOT influence or bypass this independent validation.

No SFN reset signaling is permitted. Continuity across wrap boundary (approximately 272 years at 2s superframes) is REQUIRED for consistent rendezvous and to avoid desynchronization storms.

**Explicit delta edge case at 0xFFFFFFFF boundary (MUST):**  
`uint32_t last = 0xFFFFFFFFU; uint32_t curr = 0x00000000U;`  
`uint32_t delta = curr - last;  // == 1 via unsigned wrap (mod 2^32)`  
`// Similarly for 0xFFFFFFFE -> 0x00000002 yields delta=4.`  

**Pseudocode for delta calculation (MUST match C semantics exactly; all implementations):**
```
uint32_t sfn_delta(uint32_t current, uint32_t last) {
    return current - last;  // unsigned 32-bit wrap == mod 2^32 per RFC 1982
}
```
// Rust: `current.wrapping_sub(last)`
// Python: `(current - last) & 0xffffffff` or `current - last % (1 << 32)`
// Edge cases (test vectors tdma-timing.json:0xFFFFFFFF_boundary):
// sfn_delta(0x00000000, 0xFFFFFFFF) == 1
// sfn_delta(0x00000002, 0xFFFFFFFE) == 4
if (delta > 0x80000000U) {
    // backward wrap (rare; per RFC 1982 serial numbers)
}
```
All three implementations (C, Rust `no_std`, Python sim) MUST produce identical results for wrap edge cases. This delta * superframe_duration feeds time-provider updates; `ts >= epoch_floor` validation (spec/09-packets-timing.md:176 and §2a.4.2) MUST be independent of SFN wrap. Test vectors in `test/vectors/tdma-timing.json` (or sfn-delta.json if added) MUST cover boundary cases.

Test vectors in `test/vectors/tdma-timing.json` MUST demonstrate correct modulo behavior at wrap edge cases (e.g., SFN=0xFFFFFFFE to 0x00000001, 0xFFFFFFFF boundary).

**Sync States:** Nodes MUST implement the following normative TDMA desynchronization recovery state machine using RFC 2119 keywords (MUST, MUST NOT, SHOULD, etc.).

**Table 1: TDMA Desync Recovery FSM (normative).** All transitions MUST be atomic with respect to concurrent time-provider updates, RPL DODAG version changes (see §2a.4.2), and lichen_link_load_key() state (see AGENTS.md initialization order: lichen_link_init() before lichen_tdma_init(); check ctx->has_key before any Schnorr-48 verification or signing in ACQUIRING/SYNCED states to avoid zeroed signatures per common pitfalls). Timers defined in Appendix A and Kconfig (LICHEN_TDMA_REJOIN_TIMEOUT=10*superframe_duration_ms, beacon_miss_threshold=3).

| State     | Entry Condition                          | Actions                                      | Exit Conditions                              | Next State   |
|-----------|------------------------------------------|----------------------------------------------|----------------------------------------------|--------------|
| UNSYNCED  | No valid beacon >30s or cold boot        | Continuous control channel scan on all channels; full RPL join procedure; verify link key loaded | Valid signed beacon (ctx->has_key true, matching DODAGID, ts >= epoch_floor) | ACQUIRING    |
| ACQUIRING | After UNSYNCED, predictive window miss, or DRIFTING timeout | Listen in widened guard (±100ms); update time-provider on any candidate beacon; MUST verify lichen_link_ctx.has_key | Valid beacon RX (valid sig, ts >= epoch_floor, version check passes, key loaded) | SYNCED       |
| SYNCED    | Beacon received <3 superframes ago and abs(drift) < 15 ms | Scheduled hash-based rendezvous for TX/RX; listen for beacon every superframe | 3 consecutive missed beacons, abs(drift) > 25 ms, RPL version change, or multi-root SFN conflict | DRIFTING     |
| DRIFTING  | abs(drift) > 15 ms, version mismatch, or multi-root SFN conflict | Widen guard to 150 ms; send Announce in contention slot using last_SFN; prioritize all beacons | Beacon recovered (valid ts >= epoch_floor, key loaded) within 10 superframes or rejoin_timeout expires | SYNCED or UNSYNCED |

**Multi-Root Beacon Conflict Resolution (CCP-16, normative per RFC 2119):**

When multiple beacons are received in a beacon slot (possible in overlapping root coverage):

- The node MUST verify the Schnorr-48 signature on each beacon (see draft-lichen-schnorr-00). Beacons failing signature verification MUST be discarded immediately and MUST NOT affect TDMA state, timing, or RPL DODAG selection. Such events SHOULD be reported via LCI resource `/log` or `/status`.

- Among valid beacons, the node MUST select the one with the lowest RPL rank (per spec/05-routing.md). 

- If ranks are equal, MUST prefer the beacon with the highest time-provider stratum.

- If still tied, MUST prefer the beacon with the most recent DODAG version number.

- If two valid beacons share the same DODAGID but yield conflicting SFN values (after correct modulo-2^32 computation per §2a.4.1), the node MUST transition to DRIFTING state, invalidate current schedule predictions, and re-acquire using the full ACQUIRING procedure to prevent rendezvous collisions. 

- Overlap resolution between roots with identical rank/stratum/version SHOULD use the lowest root EUI64 as tie-breaker (configurable via DIO option in future extensions). 

RPL version change detected in any beacon MUST trigger DRIFTING transition as described in the FSM table above. All selections MUST be atomic with respect to time-provider updates. See test/vectors/tdma_multi_root.json for exact conflict scenarios.

**RPL Version Change During Join/Drift:** On DIO/beacon with incremented version number:
- Transition to DRIFTING.
- Adopt new version and recompute hash seeds from new DODAGID if changed.
- Retain time-provider state (wall_clock_valid, epoch_floor) unless new ts offers better stratum.
- During join, version change forces full SFN re-acquisition; old SFN predictions MUST NOT be used until re-SYNCED (to prevent rendezvous failure).

**Interaction with Time-Provider:** Beacon `ts` field updates the firmware time-provider (see spec/09-packets-timing.md and docs/firmware-time-provider.md). All nodes MUST:
- Validate `ts >= epoch_floor` (computed as max(build_epoch, provision_epoch)) independently of any SFN value or wrap-around before acceptance. SFN wrap MUST NOT affect this validation.
- On acceptance: update wall_clock and monotonic observation time, set `wall_clock_valid=true`, propagate stratum (root beacons use stratum 1).
- In DRIFTING or UNSYNCED states exceeding 60s without GNSS/RTC, force `stratum=255` and `wall_clock_valid=false`.
- TDMA scheduler MUST query the time-provider for all absolute-time and delta computations. See AGENTS.md initialization order (lichen_link_init before lichen_tdma_init before oscore_init).

**SFN wrap:** See §2a.4.1 above for full details including 0xFFFFFFFF delta example and time-provider interaction. All computations use uint32 modular arithmetic per RFC 2119 MUST. No reset permitted. Pseudocode in Appendix B of draft-lichen-tdma.

Timers in FSM: rejoin_timeout = 10 * superframe_duration (configurable via beacon or Kconfig LICHEN_TDMA_REJOIN_TIMEOUT); beacon_miss_threshold=3.

## 2a.5. Clock Drift and Compensation

Crystal oscillators in target MCUs exhibit 20-50 ppm drift, equating to 40-100us/s or 80-200ms over a 2s superframe — exceeding guard times without correction.

**Drift Measurement:**
- Each beacon RX provides a reference: expected_arrival = last_sync_time + (current_SFN - last_SFN) * superframe_duration.
- delta_t = actual_rx_timestamp - expected_arrival (using high-resolution timer capture).
- Nodes MUST maintain running average drift_rate (in ppm or ticks per superframe).

**Compensation Algorithm (MUST implement simple version):**
1. **Offset correction:** On every beacon, snap local clock: local_time += delta_t.
2. **Rate estimation:** drift_rate = EMA( previous_rate, delta_t / interval ).
3. **Predictive scheduling:** future_wakeup = nominal + (drift_rate * time_to_event / 1e6).
4. **Guard adaptation:** If |drift_rate| > threshold, widen guard time or fall back to contention slot.
5. **Rejoin threshold:** If cumulative uncorrected drift > 25ms, declare desynced and rejoin.

**Test vectors:** See test/vectors/tdma_drift.json (simulates 30ppm crystal over 60 superframes with beacon corrections). All impls MUST match the reference scheduler within slot_adjust_ticks=8 (cross-ref ccp_load_balancing.json, Appendix A for constant definition).

**Root responsibilities:** Periodically measure its own crystal vs GNSS/RTC and advertise in `drift` field (int16 ppm*100 per beacon params map in §2a.4; cross-ref spec/09-packets-timing.md:176).

## 2a.6. Join Procedures

**Cold Join (no prior state):**
1. Scan control channel continuously until first valid signed beacon acquired (acquire SFN, time, DODAGID, params).
2. Compute initial hash-based TX slot: slot = hash(EUI64 ^ DODAGID, SFN) % num_data_slots.
3. In first available contention slot, transmit Join-Request (signed L2 frame or CoAP to root):
   - Fields: EUI64, capabilities bitmap, preferred_duty, current_stratum.
4. Root validates, optionally assigns dedicated slot via beacon slot_map or DIO option, responds with Join-Confirm containing assigned parameters and updated rank.
5. Node sends RPL DAO to complete routing integration.
6. Begins scheduled listening/transmit per computed rendezvous.

**Warm Rejoin (after temporary desync/drift):**
- Use last known SFN to predict next beacon window (± drift tolerance).
- If missed, send Announce in contention with last_SFN to accelerate neighbor sync.
- Fall back to full scan if >10 superframes desynced.

**Security and Rate Limiting:**
- All join messages signed with node's Ed25519 key.
- Root implements exponential backoff and proof-of-work (optional for high-density) to mitigate DoS.
- New nodes start with low duty cycle until vetted.

**Backward Compatibility:** Legacy nodes ignored during beacon slot; join via contention only.

Update to test/vectors/: add tdma_rendezvous_beacon.json, tdma_drift.json, tdma_join_flow.json with exact packet traces and timing simulations. Implementations in all three codebases (Rust, Zephyr C, Python sim) MUST reproduce identical behavior.

## 2a.7 Interference Mitigation (Frequency Agility, Density-Aware Adaptive SF, TDMA)

Interference mitigation in CCP-16 is achieved by coordinated selection of frequency (channel), spreading factor, and time slot. The algorithm uses local metrics (density = unique neighbors observed, SNR, PER, channel_busy; see §2a.7.1 for normative sampling procedures) and gateway-provided load_factor from DIOs. It MUST produce outputs matching test/vectors/ccp_load_balancing.json (and ccp16_vectors in generate.py).

## 2a.7.1 Normative Metric Sampling Procedure (CCP-16)

CCP-16 requires consistent metric computation across all implementations (Rust, Zephyr, Python sim) to ensure reproducible interference mitigation decisions and matching test vector outputs. Nodes MUST use a sliding window of the most recent 60s or the last 128 RX/TX events (whichever first). Metrics MUST be refreshed after every valid beacon/DIO RX or completed TX. Use of a set for unique EUI tracking or equivalent (with <0.01 false-positive rate) is REQUIRED for density on memory-constrained nodes.

- **density** (u8): Count of *unique* EUI-64 (excluding self) from which a cryptographically-verified L2 frame (beacon, DIO, or data frame with valid Schnorr-48 signature) was received in the window. Updated atomically on each valid RX. Capped at 255. This matches "density", "density_nodes", "num_neighbors" values in test vectors.

- **PER** (f32 in [0.0,1.0]): Packet Error Rate = `failed_tx / total_tx_attempts` over TX in the window (including retries). `failed_tx` counts transmissions without L2 ACK (timeout) or confirmed upper-layer delivery. If zero TX attempts in window, PER = 0.0. `success_rate = 1.0 - PER`. Matches "per":0.25, success_rate thresholds in pseudocode and vectors.

- **channel_busy** (u8[N_CHANNELS]): For each channel, percentage busy (0-100) computed from CCA/RSSI samples taken every 20 ms while radio is listening on that channel during the window. Sample is "busy" if RSSI >= -85 dBm or CCA fails. `busy_pct = min(100, round(100.0 * busy_count / total_samples))`. If no samples taken for channel, value=0. Matches array values in "channel_busy" vectors. N_CHANNELS from regional bandplan (see spec/02-physical-link.md).

SNR_db is the most recent valid reception or EMA over window. `load_factor` is received from root/gateway via DIO extension (aggregate of reported child metrics).

These procedures are normative per RFC 2119. All implementations MUST produce identical metric values for the same input events as the Python reference simulator in `python/src/lichen/sim/`. Test vectors in `test/vectors/ccp_load_balancing.json`, generate.py ccp16_vectors, and cross-validation in `tools/sim_validation.py` + Zephyr/Rust tests enforce exact match on computed density, PER, and channel_busy.

**Exact primitives from link layer (normative - MUST match lichen/subsys/lichen/link/ and rust/lichen-rpl impls exactly):**

- `N_CHANNELS = 8` (EU868 default per spec/02-physical-link.md regional plan; configurable via Kconfig `CONFIG_LICHEN_N_CHANNELS` or beacon `params.nch`; channel_busy array sized to this. See ccp16_vectors "n_channels":8)

- `now() -> u32`: Current mesh TDMA time in ms (monotonic from time-provider; cross-ref lichen_link_init before lichen_tdma_init per AGENTS.md, struct LICHEN_TDMA_Slot @ link.h:50, spec/09-packets-timing.md epoch_floor+ts validation, k_uptime_get_32() in C, Instant::now() in Rust). SFN wrap uses unsigned u32 modulo per §2a.4.1/draft-lichen-tdma:2a.2 (RFC 1982); now() independent of SFN (wraps ~49d unsigned). Used for blacklist timers, dwell, rendezvous slot calc. MUST match beacon ts synchronization.

- `hash_32(sfn: u32, key: u64) -> u32`: 32-bit FNV-1a hash (fixed param order with sfn first; key=eui64 only - dodag_id removed for RPL separation per review; consistent with short_addr). Exact:

  ```
  uint32_t hash_32(uint32_t sfn, uint64_t key) {
    uint32_t h = 0x811c9dc5u;  // FNV offset basis
    uint8_t *p = (uint8_t*)&sfn;
    for (int i = 0; i < 4; ++i) { h ^= p[i]; h *= 0x01000193u; }
    p = (uint8_t*)&key;
    for (int i = 0; i < 8; ++i) { h ^= p[i]; h *= 0x01000193u; }
    return h;
  }
  ```

**Core Algorithm Pseudocode (normative; all impls MUST match exactly, including floating point thresholds):**

```
select_mitigation_params(ctx, metrics):
    # metrics per §2a.7.1 normative sampling (density, PER, channel_busy, snr_db, success_rate)
    density := metrics.density
    snr := metrics.snr_db
    load := 0
    IF load_factor field present in metrics THEN load := metrics.load_factor
    success_rate := 1.0
    IF success_rate field present in metrics THEN success_rate := metrics.success_rate

    best_ch := select_channel(ctx, metrics, now())
    # matches test vectors for preferred_channel, hysteresis, blacklist scoring

    sf := adaptive_sf_select(density, snr, metrics.per, success_rate, load)
    # per §2a.7.2 rules/table; exact match to ccp_load_balancing.json required

    sfn := ctx.sfn
    base_slot := hash_32(sfn, ctx.eui64) MOD num_data_slots
    density_guard := 50 + density
    offset := (load * 3) MOD num_data_slots
    slot := (base_slot + offset) MOD num_data_slots

    RETURN {sf, channel: best_ch, slot, guard_ms: density_guard, density}
```

**Frequency Agility Channel Selection (normative; N_CHANNELS from regional bandplan per 02-physical-link.md §4; now_ts from TDMA per draft-lichen-tdma §2a.2 cross-ref SFN/modulo in 2a.4.1):**

```
select_channel(ctx, metrics, now_ts):
    # scored selection with hysteresis, blacklist, PER/SNR/busy. Constants from Kconfig/beacon.
    # now_ts u32 uses unsigned wrap semantics (per 2a.2/draft-lichen-tdma); comparisons safe for short BLACKLIST_MS << 2^32
    best_score := -1000.0
    best_ch := ctx.rx_ch
    FOR ch := 0 TO N_CHANNELS-1:
        IF now_ts < ctx.blacklist_until[ch] THEN CONTINUE
        busy := metrics.channel_busy[ch] / 100.0
        per := PER_FOR(ch) DEFAULT 0.5
        snr := SNR_FOR(ch) DEFAULT -5.0
        snr_factor := MAX(0.0, MIN(1.0, (snr + 15.0) / 25.0))
        success := (1.0 - per) * snr_factor
        score := (1.0 - busy) * success * 20.0
        IF ch == ctx.rx_ch THEN score := score + HYSTERESIS_BONUS
        dwell := now_ts - LAST_USED(ch) DEFAULT 0
        IF dwell < MIN_DWELL_MS THEN score := score - 3.0
        IF score > best_score THEN
            best_score := score
            best_ch := ch
    IF (best_ch != ctx.rx_ch) AND (per > PER_BLACKLIST_THRESH) THEN
        blacklist_until[best_ch] := now_ts + BLACKLIST_MS
    IF (best_ch != ctx.rx_ch) AND (now_ts - last_switch_ts > MIN_SWITCH_INTERVAL_MS) THEN
        last_switch_ts := now_ts
        last_used[best_ch] := now_ts
        RETURN best_ch
    RETURN ctx.rx_ch
```
(Exact match required for ccp_load_balancing.json "preferred_channel". All pseudocode now uses standard notation: IF/THEN, := , FOR, DEFAULT, MAX/MIN, no language operators or method calls.)

## 2a.7.2 Density-Aware Adaptive SF Selection (da2q.15.8.2)

**Rules (MUST follow for interoperability):**
- Baseline default is SF10/125kHz per appendix-design-rationale.md:7.1 (IETF layering: RFC2119 RECOMMENDED general-purpose compromise). The density-aware logic in this CCP-16 section layers on top per RFC 2119: implementations MUST follow the adaptive_sf_select pseudocode and match test vectors exactly; overrides to SF7/8/11/12 occur only on explicit local metric triggers (density, SNR, PER, success_rate, load_factor). This resolves any apparent conflict with SF10 rationale.
- Density drives primary choice: high density (>40 neighbors) biases toward higher SF to improve link margin at cost of airtime (TDMA slots compensate).
- SNR and PER are secondary modifiers. Success_rate <0.85 forces SF increase.
- Gateway load_factor >70 forces SF=10 for network-wide balance (overrides local).
- Use EMA for SNR to smooth noise. All computations deterministic. Exact EMA formula (validated against rust/lichen-tui/src/rf_health.rs and Python sim reference):
  ```
  snr_ema = snr_ema_prev * (1 - 0.25) + snr_current * 0.25
  ```
  Integer form (embedded, Q2): `snr_ema = (snr_ema_prev * 3 + snr_current) / 4`. Matches vectors.
- Embedded impls SHOULD use integer approximation (e.g. snr_q8 = snr_db * 256). Python reference uses f32.
- Output MUST exactly reproduce test vector expected SF for given inputs (see ccp_load_balancing.json vectors 3 and 5; pseudocode now does).

**SNR Threshold Table (updated for consistency with pseudocode decision points, load_factor, EMA-smoothed SNR):**

SF | Min SNR (dB) | Density Trigger | PER/Success Trigger | Notes
---|--------------|-----------------|---------------------|------
7  | >12.0       | density<=20, success>0.9 | per<0.05 | low density good link
8  | >9.0        | density<=30 | per<0.08 | moderate
9  | >8.0        | default | per<0.12 | baseline fallback
10 | >=5.0       | density 40-59 or load>70 | per<0.18 | gateway override forces this
11 | >=0.0       | density>=60 with good SNR | per<0.22 | high density
12 | <5.0 or any poor | density>=60 poor SNR/PER | >0.25 or success<0.85 | robustness

**Normative Pseudocode (MUST be matched exactly by all implementations in Rust, Zephyr, and Python simulator):**

```
adaptive_sf_select(density, snr_db, per, success_rate, load_factor):
    IF load_factor > 70 THEN
        RETURN 10                 # gateway override for network balance (CCP-16)
    sf := 10                      # baseline per appendix-design-rationale.md:7.1
    IF density >= 60 THEN sf := 12
    IF snr_db < 5.0 THEN sf := 12
    IF per > 0.25 THEN sf := 12
    IF density >= 40 THEN
        IF snr_db < 8.0 THEN
            sf := 11
        ELSE
            sf := 10
    IF (density <= 15) AND (snr_db > 12.0) AND (success_rate > 0.9) THEN
        sf := 7
    IF (density <= 25) AND (snr_db > 8.0) THEN
        sf := 8
    IF success_rate < 0.85 THEN sf := MIN(12, sf + 1)
    IF per > 0.20 THEN sf := MIN(12, sf + 1)
    IF snr_db < -18.0 THEN sf := 12
    RETURN MAX(7, MIN(12, sf))
```

Called from `select_mitigation_params` as shown. Full integration with TDMA guard (density_guard = 40 + density*1.2 clamped) and frequency agility already defined. This completes the exact algorithm for project-LICHEN-da2q.15.8. Update test/vectors/ccp_load_balancing.json with additional SF decision test cases. Implementations in rust/lichen-phy, lichen/subsys/lichen/link, and Python simulator MUST be updated to call this logic (filed as follow-up beads).

All parameters are advertised in beacons/DIOs or Kconfig. Test vectors in ccp_load_balancing.json MUST be updated to cover full decision tree (e.g. PER>0.2 triggers channel switch). See Appendix C for validation.

## 2a.8. Synchronized Hopping (CCP-12)

CCP-12 nodes MUST implement synchronized frequency hopping to coordinate channel usage across the mesh. The hop sequence, synchronization, and rendezvous protocol are defined below. All behaviors MUST produce identical results to the test vectors in `test/vectors/ccp12-hopping.json` and `test/vectors/ccp12-rendezvous.json` (to be added; see Appendix C). 

### Hop Sequence

The shared hop sequence is computed deterministically from the current Superframe Number (SFN) or absolute time:

channel = prng(SFN, DODAGID, seed) % N_CHANNELS

where prng is the hash function defined in §2a.1 (FNV-1a with SFN first), seed is from beacon `chseed` or root key hash. Nodes MUST use the same computation. GPS-equipped nodes SHOULD substitute Unix/GPS timestamp for SFN when available and |ts_diff| < 1s (RECOMMENDED for precision rendezvous). 

### Synchronization Mechanism

Primary sync is via beacon SFN and `ts` field (MUST, cross-ref §2a.4 and spec/09-packets-timing.md). Secondary GPS sync (if available) provides absolute time reference for hop calculation when beacons are missed >3 superframes (SHOULD). Nodes advertise sync source capability in DIO/Announce. In case of conflict, beacon SFN takes precedence (MUST). See draft-lichen-schnorr-00.md Appendix A for related test vectors.

### Rendezvous Protocol

Sender and receiver compute the current hop channel independently using shared state. For scheduled slots, TX/RX occurs on the computed channel. For on-demand rendezvous:

- Sender uses last-known peer SFN or hash(peer_EUI, current_SFN) to predict channel.
- Transmission occurs in next available slot on that channel or control channel fallback.
- Receiver cycles listen windows across hopped channels per its sequence + control channel every superframe (MUST).

Announce frames include current hop offset. Implementations MUST follow RFC2119 rules above and match test vectors exactly.

Update to test/vectors/ required per task.

## References

[RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997, <https://www.rfc-editor.org/info/rfc2119>.

[RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017, <https://www.rfc-editor.org/info/rfc8174>.

- spec/02-physical-link.md (PHY parameters, hopping)
- spec/05-routing.md (RPL version handling, DODAG rules)
- spec/09-packets-timing.md (time provider, epoch_floor, ts validation)
- spec/drafts/draft-lichen-schnorr-00.md (signature format)
- spec/drafts/draft-lichen-tdma (SFN modulo pseudocode, Appendix B)
- docs/firmware-time-provider.md (implementation notes)
- test/vectors/*.json (for FSM, multi-root, SFN wrap, drift, rendezvous, ccp12-hopping)
- AGENTS.md (initialization order)

## Appendix A. Design Rationale for Constants and Parameters

Many timing values are chosen to balance capacity, reliability, and hardware constraints. They are either:

* Advertised in the beacon `params` map (e.g., nds, g=guard_ms, drift:int16=ppm*100).
* Defined as Kconfig defaults (LICHEN_TDMA_REJOIN_TIMEOUT=10, BEACON_MISS_THRESHOLD=3) with overrides via DIO.
* Justified below including slot_adjust_ticks=8 (see ccp_load_balancing.json); all implementations SHOULD use these defaults unless justified otherwise by deployment (see test vectors for validation; cross-ref §2a.4, §2a.5).

**Justifications:**
- Slot duration = 250 ms: Covers typical SF10/125kHz airtime (~180-220 ms for 60B) + 30-70 ms guard. Parameterized as `slot_duration = airtime(PHY) + guard`.
- Superframe = 8 slots (2 s): Power-of-two for efficient modulo; balances duty cycle and sync frequency. Larger values reduce beacon overhead but increase latency.
- Guard time = 50 ms: Tolerates ±20-50 ppm crystals over 2s (~40-100 us drift), 15 ms SX126x turnaround, ±25 ms sync error, <1 ms propagation, and CSMA margin. See timing analysis in tdma-timing.json. Wider guards reduce capacity.
- Sync bound ±25 ms: Derived from guard/2; exceeded drift triggers DRIFTING state.
- beacon_miss_threshold = 3, rejoin_timeout = 10 * superframe_duration: Balances responsiveness vs false positives; values from simulation of 30ppm drift scenarios (test/vectors/tdma_drift.json). Parameterized in Kconfig and beacon.
- Scan timeout 30s in UNSYNCED: Sufficient for full channel scan in typical bands without excessive power use.
- Drift EMA threshold 15 ms / 25 ms: From crystal spec and empirical mesh tests; triggers adaptive guard or rejoin.
- `drift` constant (ppm*100): Advertised by root for compensation; `slot_adjust_ticks=8`: scheduler tolerance for predictive wakeup (matches ccp vector; prevents 1-tick arbitrariness while fitting 30ppm over SF).

These choices are not arbitrary; full derivation and sensitivity analysis in Appendix B (to be expanded) or separate design document. All normative behaviors and constants (incl. drift, slot_adjust_ticks) are now cross-referenced to test vectors and appendices. Remaining RFC2119 usage limited to key interoperability points.

## Appendix C. Test Vectors

See test/vectors/ccp16.json, ccp_load_balancing.json, tdma*.json for exact FSM transitions, SFN modulo edge cases (0xFFFFFFFF boundary), multi-root conflicts, drift compensation (30ppm over 60 superframes), CCP-16 channel/load balancing, and join flows. Implementations MUST match bit-exact scheduling, select_channel pseudocode, and state transitions per these vectors (Appendix C fully updated for ccp16.json).

## 6. Implementation Status

**Python** (`python/src/lichen/sim/` and `test/vectors/generate.py:ccp16_vectors()`): Complete reference implementation with full pseudocode coverage for select_channel, adaptive_sf_select, metric sampling, desync recovery. All vectors in ccp16.json and ccp_load_balancing.json pass. Source of truth.

**Rust** (`rust/lichen-rpl/`): CCP-16 TDMA/SF/load balancing stub complete; full integration pending project-LICHEN-da2q.15.8. Matches vectors where implemented.

**Zephyr** (`lichen/subsys/lichen/link/`): Kconfig guard and TDMA hooks present (CONFIG_LICHEN_CCP16); full CCP-16 FSM, channel assignment, and metric logic pending. Matches Python on shared vectors.

<<<<<<< HEAD
Schema and spec appendix updates complete per CODEREVIEW-P2.
=======
```
+----------+---------+---------+----------------+-------------------+
| Msg 0x02 | Version | Subtype | Sender IID (8) | Subtype Body ...  |
+----------+---------+---------+----------------+-------------------+
```

The ordinary link signature covers the complete envelope and lets the receiver
select the pinned immediate-sender key before processing the subtype. Relays MAY
replace `Sender IID` and the link signature. Unknown versions or subtypes MUST
be ignored by protocol logic and MUST NOT be delivered as application data.

SCHEDULE, REVOKE, and DISABLE bodies contain an immutable authority object and
MUST additionally carry a monotonically
increasing 64-bit authority sequence and a 48-byte Schnorr48 signature by the
accepted root over:

```
"LICHEN-CCP-AUTH-v1" || DODAGID || RPLInstanceID ||
subtype || authority_object_without_signature
```

The hop envelope is excluded from the root signature. Relays MUST preserve the
authority object unchanged. Before accepting it, a node MUST already possess an
authenticated and pinned public key for the accepted DODAG root through the
normal Announce/trust process. Otherwise it remains in baseline mode.

A schedule authority object contains, in order:

| Field | Size |
|-------|------|
| Root IID | 8 bytes |
| Recipient IID | 8 bytes |
| Authority sequence | 8 bytes |
| Schedule generation | 4 bytes |
| Epoch GPS seconds | 8 bytes |
| Activation ASN | 8 bytes |
| Lease-end ASN | 8 bytes |
| Join nonce | 16 bytes |
| Plan ID | 2 bytes |
| Plan version | 1 byte |
| Channel mask | 4 bytes |
| Slot duration us | 4 bytes |
| Setup window us | 4 bytes |
| Occupied time us | 4 bytes |
| Guard budget us | 4 bytes |
| Slots per superframe | 2 bytes |
| PHY profile ID | 1 byte |
| Max PHY length | 1 byte |
| Schedule digest | 16 bytes |
| Page index | 1 byte |
| Page count | 1 byte |
| Cell count | 1 byte |
| Cell records | `cell_count * 19` bytes |
| Root signature | 48 bytes |

A cell record contains slot offset (2), channel index (1), transmitter IID (8),
and receiver IID (8), all in that order. Multi-byte integers are big-endian.
`Join nonce` binds a first assignment to its JOIN_REQUEST and is all zero for a
schedule update that does not grant a new node.
`Schedule digest` is the first 16 bytes of SHA-256 over the recipient's complete
cell list, sorted by slot offset, channel index, transmitter IID, then receiver
IID, and serialized as concatenated 19-byte records. Each SCHEDULE frame is a
root-signed page for one recipient and carries exactly one cell record. With an
extended link destination and short SenderID, the complete frame body is 255
bytes; a second cell would exceed the 255-byte length field. Page indices start
at zero and follow
the canonical cell order. Common authority fields and digest are identical
across pages; page index and cell record differ. `Page count` equals the
recipient's cell count. A recipient MUST receive every page before activation
or remain in baseline mode.

The root MUST use its authenticated short SenderID for SCHEDULE pages; the
extended SenderID form does not fit this maximum-size frame.

All pages in one schedule transaction share an authority sequence. Replay state
is keyed by `(root IID, authority sequence, page index)`: each page index MAY be
accepted once, in any order. A transaction with an authority sequence lower
than the highest completed transaction is stale. A higher authority sequence
abandons any incomplete lower transaction and cancels every queued future action
with a lower sequence, including REVOKE and DISABLE. At an equal authority
sequence, a node accepts only previously unseen SCHEDULE pages with the same
recipient, generation, digest, and page count; every other object is a replay or
conflict and MUST be rejected.

REVOKE contains root IID, recipient IID, authority sequence, schedule
generation, activation ASN, and one 19-byte cell record. DISABLE
contains root IID, recipient IID, authority sequence, schedule generation, and
activation ASN. Both take effect when that authenticated activation ASN is
reached; a value less than or equal to the current ASN takes effect immediately.
Canonical vectors MUST cover every control body before production
implementation begins.

A JOIN_REQUEST subtype body contains origin IID (8), origin public key (32),
root IID (8), a random join nonce (16), requested lease in slots (4), capability
length (1), capability bytes (variable), and an origin Schnorr48 signature (48).
The capability bytes use the 36-byte CCP Capability option data format without
its type and length bytes. Other capability lengths are unsupported in version
1. The origin signature covers:

```
"LICHEN-CCP-JOIN-v1" || DODAGID || RPLInstanceID ||
origin_iid || origin_public_key || root_iid || join_nonce ||
requested_lease || capability_length || capability_bytes
```

Relays preserve this subtype body while replacing only the hop envelope and
link signature. The coordinator verifies the IID/public-key binding and origin
signature, then applies the configured TOFU, DANE, or PKIX policy before
pinning. The SCHEDULE authority object binds that nonce when granting the
origin's first cell; subsequent updates carry an all-zero nonce.

## CCP-11. CSMA Channel Rendezvous

When no usable scheduled cell exists, two capable immediate neighbors MAY
negotiate a bounded data-channel rendezvous on CH0.

1. The initiator sends signed CHANNEL_REQUEST on CH0.
2. The receiver validates identities, plan, channel, duration, queue state, and
   regulatory budget.
3. The receiver sends signed CHANNEL_GRANT or CHANNEL_REJECT on CH0.
4. The end of the authenticated GRANT PHY frame is rendezvous time zero. For
   initiator-to-grantor traffic, the grantor retunes immediately and the
   initiator waits the granted switch guard from the end of GRANT reception. For
   grantor-to-initiator traffic, the initiator retunes immediately and the
   grantor waits the switch guard before transmitting.
5. Data and associated ACK/NACK traffic use the granted channel.
6. Both nodes return to CH0 after completion, failure, or expiry.

The exchange binds immediate endpoint IIDs, a random reservation token, plan
ID/version, channel index, direction, retry counter, maximum frame count,
maximum airtime, switch guard, and expiry. A reservation MUST be bounded by both
duration and regulatory airtime. The default maximum absence from CH0 is five
seconds. Expiry is encoded as a duration in milliseconds from rendezvous time
zero. Both endpoints return to CH0 no later than that duration even when data or
acknowledgments are lost.

CHANNEL_REQUEST has this subtype body after the hop envelope:

| Field | Size |
|-------|------|
| Peer IID | 8 bytes |
| Reservation token | 8 bytes |
| Plan ID | 2 bytes |
| Plan version | 1 byte |
| Channel index | 1 byte |
| Retry counter | 1 byte |
| Direction | 1 byte (`0` initiator-to-grantor, `1` grantor-to-initiator, `2` bidirectional) |
| Maximum frame count | 1 byte |
| Reserved | 1 byte |
| Maximum airtime ms | 2 bytes |
| Maximum duration ms | 2 bytes |

CHANNEL_GRANT echoes the complete request body and appends switch guard in
microseconds (4 bytes). CHANNEL_REJECT contains peer IID (8), reservation token
(8), reason (1), and reserved (1). Receivers MUST reject non-zero reserved
fields or direction values above 2. In a bidirectional reservation, the
initiator transmits first after the switch guard; reverse traffic begins only
after the first frame's defined radio-turnaround interval and remains inside the
granted airtime/duration bounds. All multi-byte integers are unsigned
big-endian.

The eligible channel set is the ordered intersection of both local plans and
advertised masks. The initiator distributes retries with:

```
A = min(full_iid_local, full_iid_peer)
B = max(full_iid_local, full_iid_peer)
digest = SHA-256("LICHEN-MC-RV1" || plan_id || plan_version ||
                A || B || reservation_token || retry_counter)
index = uint32_be(digest[0:4]) mod eligible_channel_count
```

The selected channel is still carried explicitly in request and grant; hashing
does not authenticate a reservation or make a receiver listen. A busy data
channel causes wait within the reservation or CH0 fallback, never an implicit
channel change.

Rendezvous is per-hop. A relay returns to CH0 and negotiates separately with its
next hop. Multicast and broadcast rendezvous are not defined.

## CCP-12. Scheduled Multi-Channel Operation

In scheduled mode, a root-authorized cell is the rendezvous and replaces the
CHANNEL_REQUEST/CHANNEL_GRANT exchange. Channel switch time and guard are
deducted from usable slot airtime. A node MUST NOT be assigned simultaneous CH0
and data-channel reception unless it advertises concurrent receive chains.

The scheduler MUST account for root and relay airtime, half-duplex conflicts,
and regulatory budgets. A cell grants a transmission opportunity, not
permission to violate regional rules. A node without sufficient budget skips
the cell.

Plan ID, plan version, channel mask, PHY profile, timing envelopes, schedule
digest, and all cells are covered by the root signature. A hop-authenticated DIO
advertisement alone MUST NOT alter interpretation of an accepted schedule.

Network-wide synchronized frequency hopping is not part of version 1. Such
hopping can provide interference or regulatory distribution but does not create
parallel capacity on single-radio hardware. It requires a separate hopping
sequence, reacquisition, multicast, and certification specification.

## CCP-13. Loss, Fallback, and Compatibility

A node MUST stop scheduled transmission immediately when:

- uncertainty exceeds the guard budget;
- its cell lease expires;
- GNSS-PPS is invalid and its calculated holdover expires;
- it accepts a different root or incompatible schedule generation;
- an authenticated revocation or disable reaches its activation ASN;
- a time correction exceeds its conservative error envelope.

The node then returns to CH0, uses baseline CAD/CSMA, restores valid GNSS-PPS
state if needed, listens for authenticated capability/schedule traffic, and
rejoins. It MUST NOT continue transmitting in remembered cells. This holdover
deadline is independent of the much longer RPL root-failure interval.

Legacy nodes remain on CH0 and ignore unsupported routing/control types.
CCP-capable nodes use CH0 for traffic to legacy or unknown peers. A root assigns
a cell only when both immediate endpoints advertise compatible versions.

Mixed operation cannot guarantee performance equal to pure baseline operation:
beacons consume airtime, empty cells waste opportunities, and legacy nodes may
collide with scheduled CH0 cells. Compatibility means continued communication
and bounded fallback, not guaranteed improvement.

## CCP-13a. Desync Recovery State Machine

This section defines how a node detects synchronization loss and recovers.
Terminology uses plain language because the state machine must be implementable
by firmware engineers without real-time systems backgrounds.

### States

A CCP-capable node is always in exactly one of these states:

| State | Meaning | Channel behavior |
|-------|---------|------------------|
| UNJOINED | Never successfully synchronized | CH0 only; cannot hop |
| JOINED | Clock is trusted; normal operation | Hop per schedule |
| DRIFT | Clock may be drifting; watching | Hop with extended RX windows |
| RECOVER | Clock is untrusted; seeking beacon | CH0 only; stopped hopping |

### State Diagram

```
                         beacon_rx
    ┌──────────┐ ───────────────────────▶ ┌──────────┐
    │ UNJOINED │                          │  JOINED  │
    └──────────┘                          └────┬─────┘
         ▲                                     │
         │                                     │ no_beacon(T_DRIFT_WARN)
         │                                     ▼
         │                                ┌─────────┐
         │          beacon_rx             │  DRIFT  │
         │       ◀───────────────────     └────┬────┘
         │       │                             │
         │       │                             │ no_beacon(T_DRIFT_MAX)
         │       │                             ▼
         │       │                        ┌─────────┐
         └───────┴─── no_beacon(T_GIVE_UP)│ RECOVER │
                      beacon_rx           └─────────┘
                   ◀──────────────────────────┘
```

### Clock Reference

The SX1262 temperature-compensated oscillator (TCXO) is the timing reference,
not the nRF52840 main crystal. Typical accuracy:

| Source | Accuracy | Drift per minute |
|--------|----------|------------------|
| nRF52840 crystal | ±40 ppm | ±2.4 ms |
| SX1262 TCXO | ±2.5 ppm | ±0.15 ms |

At ±2.5 ppm, a node drifts approximately 0.3 ms after 2 minutes without
synchronization—within tolerance for typical 10–50 ms slots.

### Timers

| Timer | Default | Description |
|-------|---------|-------------|
| `T_DRIFT_WARN` | 30 s | Time without beacon before entering DRIFT |
| `T_DRIFT_MAX` | 120 s | Time in DRIFT before entering RECOVER |
| `T_GIVE_UP` | 600 s | Time in RECOVER before returning to UNJOINED |

`T_GIVE_UP` MUST be configurable. The default balances battery life against
recovery robustness. Deployments with frequent temporary RF shadows MAY
increase it; solar-powered nodes MAY decrease it.

### Transitions

#### UNJOINED → JOINED

**Trigger:** Receive authenticated beacon containing SFN and epoch.

**Actions:**
1. Set local SFN and epoch from beacon.
2. Set `wall_clock_valid = true`.
3. Start drift watchdog with period `T_DRIFT_WARN`.
4. Begin channel hopping per schedule.

A node in UNJOINED MUST listen on CH0 continuously. It cannot hop because it
does not know the current time.

#### JOINED → DRIFT

**Trigger:** Drift watchdog expires (no beacon received for `T_DRIFT_WARN`).

**Actions:**
1. Extend RX window by 50% on each channel.
2. Start recovery countdown with period `T_DRIFT_MAX`.
3. Continue hopping but with extended windows.

The extended window hedges against clock uncertainty without abandoning the
schedule. A quiet network is not necessarily a lost network.

#### DRIFT → JOINED

**Trigger:** Receive authenticated beacon.

**Actions:**
1. Apply small SFN correction if within tolerance.
2. Reset drift watchdog.
3. Cancel recovery countdown.
4. Restore normal RX window duration.

Small corrections adjust for measured drift. A correction exceeding the
guard budget indicates the node was further off than believed; it MUST
transition to RECOVER instead.

#### DRIFT → RECOVER

**Trigger:** Recovery countdown expires (`T_DRIFT_MAX` elapsed without beacon).

**Actions:**
1. Set `wall_clock_valid = false`.
2. Stop channel hopping immediately.
3. Return to CH0 and listen continuously.

A node in RECOVER MUST NOT transmit in scheduled cells. Its clock is
untrusted and it would likely transmit in the wrong slot, causing collisions.

Recovery is passive: the node listens on CH0 for beacons. It does not
actively solicit beacons because:
- Solicitation consumes airtime on an already-stressed network.
- A lost node does not know when its solicitation would collide.
- Beacons arrive at coordinator-controlled intervals regardless.

#### RECOVER → JOINED

**Trigger:** Receive authenticated beacon on CH0.

**Actions:**
1. Hard-reset SFN and epoch from beacon (not a small correction).
2. Set `wall_clock_valid = true`.
3. Start drift watchdog.
4. Resume channel hopping.
5. Log recovery event for diagnostics.

The hard reset acknowledges that the node's prior time estimate was wrong.

#### RECOVER → UNJOINED

**Trigger:** No beacon received for `T_GIVE_UP`.

**Actions:**
1. Clear cached routing and schedule state (it is stale).
2. Enter low-power periodic listen mode on CH0.
3. Remain in UNJOINED until beacon reception.

This transition indicates prolonged isolation. The node conserves power while
remaining available for rejoining.

### Multi-Root Conflict

A node MAY receive beacons from multiple roots with different epochs.

**Resolution order:**
1. Prefer the root with the higher epoch number.
2. If epochs are equal, prefer the root the node was already following.
3. If newly joining, prefer the root with the lower Node ID (deterministic
   tiebreak).

Higher epoch indicates more recent network time. A node MUST NOT oscillate
between roots; once it accepts a root's beacon, it ignores lower-epoch
beacons from other roots until it returns to UNJOINED.

### RPL Version Independence

An RPL DODAG version change does not reset SFN. Routing topology and time
synchronization are independent concerns. A node MAY experience an RPL
version increment while remaining in JOINED with unchanged time state.

Exception: if the RPL version change accompanies a new CCP epoch from the
same root, the node treats the epoch change normally.

### SFN Wraparound

SFN is an unsigned integer that wraps to zero. Wraparound within the same
epoch is expected and handled by modular arithmetic.

When local SFN wraps:
1. Increment local epoch counter.
2. Continue hopping normally.

If a received beacon's epoch differs from the local epoch by more than one,
the node's time estimate is grossly wrong. It MUST transition to RECOVER
regardless of current state.

### GPS-Capable Nodes

Nodes with GNSS-PPS hardware MAY use GPS time instead of beacon time:

- `wall_clock_valid = true` when GPS lock is acquired with valid PPS.
- GPS provides authoritative SFN; beacons are used to detect epoch changes.
- Loss of GPS lock starts the drift watchdog as if a beacon were missed.

GPS-capable nodes still listen for beacons to detect:
- Epoch increments from the root.
- Network-wide schedule changes.
- Multi-root conflicts.

### Implementation Notes

1. **Drift watchdog** resets on any authenticated beacon reception, not only
   beacons from the preferred root.

2. **Extended RX windows** in DRIFT increase power consumption. The 50%
   extension is a tradeoff; deployments MAY tune this via configuration.

3. **Recovery logging** aids debugging but MUST NOT delay state transitions.

4. **State persistence** across reboot: a node that reboots without
   persisted time state MUST start in UNJOINED regardless of prior state.

## CCP-14. Security Requirements

- Capability, join, schedule, revocation, disable, request,
  grant, and rejection messages MUST be signed and replay-protected.
- Schedule authority MUST be verified against the accepted root key; ordinary
  link authentication by a relay is insufficient.
- Schedule generation, activation ASN, lease end, and authority sequence MUST
  reject stale or replayed state.
- A node without persisted replay state MUST complete a fresh nonce-bound join
  before obeying a dedicated assignment.
- Remote messages MUST NOT enable a locally prohibited channel.
- Requests MUST be rate-limited before expensive signature or radio work.
- An unauthenticated downgrade MUST NOT change schedule state. Lease expiry and
  synchronization loss provide autonomous safe downgrade.

Jamming CH0, GNSS jamming or spoofing, and compromised authorized roots remain
denial-of-service risks.

## CCP-15. Capacity Claims

CCP does not guarantee a fixed capacity multiplier.

TDMA can remove scheduler-created same-domain overlaps under bounded clocks,
but not external interference, legacy transmissions, jamming, or unsafe reuse.
Multiple channels increase aggregate capacity only when disjoint links and
receiver hardware can operate concurrently. A single-radio gateway star remains
approximately serialized even when many frequencies exist.

For eight total frequencies with CH0 reserved for control, capable payload has
an ideal seven-data-channel bound before control overhead, topology, half-duplex
relays, interference, and regulation. Implementations MUST report measured
goodput and collision reduction with topology and hardware assumptions; they
MUST NOT claim "8x capacity" from channel count alone.

## CCP-16. Simulator Gates

Production implementation is blocked until a deterministic simulator verifies:

1. byte-exact codecs, signature transcripts, malformed inputs, and canonical
   vectors for every capability and control format;
2. canonical LoRa airtime vectors for complete PHY frames;
3. slot fit including ramp, retune, guard, data, and acknowledgment;
4. GNSS PPS alignment, worst-case clock drift, and holdover boundaries;
5. GNSS loss/spoof discontinuity, stale schedule rejection, and CH0 fallback;
6. zero scheduler-created overlap in star, hidden-terminal, line, tree, and
   diamond topologies without spatial reuse;
7. no simultaneous TX/RX assignment on single-radio nodes;
8. concurrent distinct-channel cells limited by endpoint and receiver-chain
   constraints;
9. atomic schedule-generation activation after update loss or delay;
10. randomized join progress without starvation under declared load;
11. per-hop channel rendezvous, request/grant loss, and five-second recovery;
12. plan mismatch, prohibited-channel rejection, and regulatory accounting;
13. all-legacy behavior unchanged and mixed-version communication preserved;
14. single-radio gateways modeled without fabricated parallel reception;
15. parallel-radio gateways limited to their advertised demodulator count;
16. forged, modified, replayed, stale, and unauthenticated control rejected;
17. identical-seed comparisons of delivery ratio, latency, goodput, collision
    loss, and control airtime against baseline CSMA.

For each seed, metrics are paired between baseline and CCP. Favorable
multi-channel tests MUST produce a median delivered-payload ratio of at least
4.0 and a 5th-percentile ratio of at least 3.0 for seven disjoint saturated
capable pairs before
multi-channel production implementation is unblocked. This is a simulator
product gate, not a protocol guarantee. In an all-capable dense reference
topology, the median paired collision-attributed-loss reduction MUST be at least
50%, at least 90 of 100 seeds MUST show no increase, and median delivery ratio
MUST NOT decrease.

The canonical gate uses seeds 0 through 99 and two fixed scenarios:

1. **Parallel capacity:** Seven disjoint one-hop pairs, one pair on each data
   channel, saturated 76-byte PHY frames, compared with all seven pairs on CH0.
2. **Dense mixed star:** 64 sources and one coordinator with eight receive
   chains. Sources offer one 76-byte frame per superframe. Capability fractions
   are 25%, 50%, 75%, and 100%, selected by ascending IID.

Both runs use the same regional plan, SF, bandwidth, coding rate, traffic trace,
and seed on baseline and CCP paths. The simulator issue MUST freeze those PHY,
superframe, clock-error, and regulatory values as versioned JSON before results
are accepted. For each mixed capability fraction, the 95th percentile of paired
delivery-ratio regression and RPL-convergence-time regression MUST NOT exceed
5%. Results MUST include
goodput, PDR, p95 latency, collision-attributed loss, control airtime, and
regulatory deferrals for every seed; averages alone are insufficient.

For seed `s`:

```
payload_ratio_s = delivered_payload_ccp_s / delivered_payload_baseline_s
pdr_regression_s = max(0, (pdr_baseline_s - pdr_ccp_s) / pdr_baseline_s)
convergence_regression_s =
    max(0, (convergence_ccp_s - convergence_baseline_s) /
           convergence_baseline_s)
```

The canonical scenario is invalid and cannot unblock implementation if any
baseline seed delivers zero payload, has zero PDR, or fails to converge by the
declared test deadline. A CCP seed that fails to converge is an automatic gate
failure. Percentile gates apply to the 100 paired per-seed values, using nearest-
rank percentiles.

## CCP-17. Deferred Extensions

The following require separate specifications and evidence:

- same-channel receiver-specific spatial cell reuse;
- synchronized network-wide hopping;
- multicast data-channel scheduling;
- distributed cell negotiation;
- adaptive slot duration or per-cell PHY profiles;
- sleep scheduling that removes baseline receive availability.

---

[← Physical and Link Layers](02-physical-link.md) | [Index](README.md) |
[Next: Adaptation Layer →](03-adaptation.md)
>>>>>>> 47566351a (spec(ccp): add desync recovery state machine (CCP-13a))
