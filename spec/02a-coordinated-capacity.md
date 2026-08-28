<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Coordinated Capacity Protocol (CCP)

## Abstract

The Coordinated Capacity Protocol (CCP) defines mechanisms for coordinated capacity management in LICHEN LoRa meshes. This includes TDMA slot assignment, channel agility via select_channel with density-aware fallback, adaptive spreading factor selection via adaptive_sf_select (incorporating EMA-smoothed SNR and load_factor), time synchronization via now(), CH0 control channel rules, signed rx_channel for CCP-9 da2q rendezvous, density/load rules, capability signaling in DIOs, the consolidated CCP-15 interference mitigation algorithm (Section 2a.10: CCA, frequency agility, density-aware SF, TDMA coordination), and desynchronization recovery.

All implementations MUST produce identical behavior to test vectors in `test/vectors/ccp16.json`, `ccp15.json`, `ccp-interference.json`, `ccp_tdma.json`, `link_frame.json`, and `l2_payload.json`:
- TDMA beacon byte layout, CDDL, SCHC rule 0x08, slot/hash, SFN wrap, join flows, epoch/num_slots per 2a.2
- vectors for CCP-16/14 slot, SF, channel, tx_allowed, Multi-RX, capacity metrics (independent oracle: FNV-1a + SX126x airtime + multi-channel sim).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## Table of Contents

1. Abstract
2. 2a.1. Overview
3. 2a.2. TDMA Beacon Format, Slots, Hash Selection, and Join (SCHC 0x08, CDDL, byte layout)
4. 2a.3. Channel Agility (select_channel, now())
5. 2a.4. Time Synchronization
6. 2a.5. Multi-Root Beacon Conflict Resolution
7. 2a.5.5. Security Properties of TDMA Sync
8. 2a.6. Desync Recovery State Machine
9. 2a.7. Regional Channel Plans and CH0 Rules
10. 2a.8. Adaptive Spreading Factor Selection (adaptive_sf_select)
11. 2a.9. Adaptive Duty Cycle (adaptive_duty_permille)
12. 2a.10. Interference Mitigation Algorithm (CCP-15)
13. Implementation Status
14. References

## Overview

LICHEN networks operate under severe bandwidth and duty-cycle constraints. CCP coordinates access to the shared medium using hash-derived TDMA slots synchronized to a network epoch, density-aware adaptive SF selection, multi-channel operation (CH0 dedicated to control per SCHC-compressed beacons and RPL DIOs), deterministic channel agility, time synchronization, signed rx_channel announcements for rendezvous, per-neighbor EMA for RF metrics, and load/density signaling. The root advertises epoch and num_slots. Nodes suppress transmission outside assigned slots. All algorithms are deterministic.

## TDMA Frame Structure, Slot Assignment, now(), and Desync Recovery

## 2a.2. TDMA Slots and Hash Selection

The root advertises `epoch` (u32) and `num_slots` (default 8) via SCHC Rule ID 0x08 (TDMA_BEACON) on CH0 (see draft-lichen-schc-lora-00 and appendix-schc.md). 

**TDMA Beacon Format (exact, normative for interop):**

Multi-byte integers unsigned big-endian (network order). Full byte layout:

| Offset | Bytes | Field          | Description |
|--------|-------|----------------|-------------|
| 0      | 4     | epoch          | u32 BE schedule generation and SFN base |
| 4      | 1     | num_slots      | u8 (default 8); hash modulus |
| 5      | 4     | sfn            | u32 BE superframe number |
| 9      | 4     | timestamp      | u32 BE for epoch_floor validation |
| 13     | 1     | flags          | bits 0=scheduled, 1=CSMA, 2=CH0-RX, 3=GNSS-PPS, 4-7=0 |
| 14     | 1     | rx_chains      | u8 (1 for single-radio) |
| 15     | 2     | setup_window   | u16 ms (retune/CAD) |
| 17     | 2     | occupied_time  | u16 ms (data+ACK) |
| 19     | 1     | guard          | u8 ms (MUST be 50 for this revision) |
| 20     | 4     | channel_mask   | u32 (bit 0=CH0); local intersection computed |
| 24+    | var   | cbor_options   | density, slot_map, etc. |
| E-48   | 48    | beacon_sig     | Schnorr48 signature over bytes 0..(E-48) per draft-lichen-schnorr-00 |

**CDDL (RFC 8610) for CBOR options tail (offset 24+):**

The fixed binary header (bytes 0-23) is NOT CBOR-encoded; the following CDDL
describes only the variable-length CBOR options starting at offset 24:

```cddl
cbor-options = {
    ? density: uint .size 1,
    ? slot_map: [* uint .size 1],
    ? pow_challenge: bstr .size 8,
    * any
}
```

Slot ID = `(fnv1a32(EUI64) + u32(SFN)) mod num_slots`, where FNV-1a32 uses basis `0x811c9dc5`, EUI64 is the exact eight-byte wire value, and addition wraps modulo 2^32 before the positive `num_slots` modulus. All implementations MUST match `test/vectors/ccp_sfn_wrap_slot_hash.json`, `ccp_tdma.json`, `ccp16.json`, `link_frame.json`, and `l2_payload.json` exactly. Integrates with `lichen_rpl_dodag_init()`, `lichen_link_set_slot()`, `tdma_tx_allowed()`.

slot_map (CBOR array of u8): A sorted list of slot indices assigned to this node for the current superframe; an empty array indicates no transmit slots. Receivers MUST validate that each entry is less than num_slots. The root MUST set slot_map on each beacon; joiners MUST adopt the assigned slot_map and MUST NOT transmit outside it. See ccp_tdma.json for edge-case vectors (wraparound, slot_map order, num_slots change).

**Test Vector Example — Slot Hash Computation:**

```
EUI64 = 0x1122334455667788 (exact eight wire bytes)
SFN   = 0x00000005 (unsigned u32)

fnv1a32(0x1122334455667788, basis=0x811c9dc5) = 0x912fa46d
(0x912fa46d + 0x00000005) mod 2^32 = 0x912fa472
num_slots = 8
Slot ID = 0x912fa472 % 8 = 2

This is the one true slot calculation; hashing a concatenation or XOR-mutated EUI64 breaks interop. SFN values normalize as unsigned 32-bit counters. The fixed cases at SFN 0, 1, 0xFFFFFFFF, and wrap MUST match `test/vectors/ccp_sfn_wrap_slot_hash.json`.
```

Beacons MUST be signed with a Schnorr48 signature per [draft-lichen-schnorr-00]. The signature covers bytes 0 through (E-48) of the beacon (all fixed fields and CBOR options, excluding the signature itself). Receivers MUST verify the signature against the sender's public key before accepting slot assignments or time updates. The root's public key MUST be distributed out-of-band (TOFU on first beacon or pre-provisioned); nodes MUST NOT relay beacons whose Schnorr48 signature fails verification.


For SFN (superframe number, a u32 epoch counter) wrap-around, all nodes MUST compute using unsigned 32-bit arithmetic (modulo 0x100000000). The time-provider (see `docs/firmware-time-provider.md`) is the canonical source: SFN/epoch updates MUST pass epoch_floor validation, set `wall_clock_valid`, and respect stratum before adoption. RPL version changes or desync MUST reset SFN relative to the new root per the FSM in Section 2a.6.

Delta = (current_sfn - last_sfn) using uint32_t subtraction ensures correct wrap behavior. 

Edge case example (0xFFFFFFFF boundary):

```
last_sfn = 0xFFFFFFFFu;
current_sfn = 0x00000002u;
delta = current_sfn - last_sfn;  /* = 3 in unsigned 32-bit arithmetic */
```

This MUST be treated as advancement of 3 slots. Signed arithmetic would yield a large negative value, breaking desync detection and slot scheduling. Test vectors in ccp16.json and ccp_tdma.json MUST cover this and similar boundaries.

A node MUST only transmit in its assigned slot. At each configured schedule profile, slot duration MUST be at least `ceil(maximum permitted PHY-payload airtime in milliseconds) + 50 ms`; it MUST NOT be derived from a typical frame. The data window begins at the slot start and ends before the single trailing 50 ms guard; nodes MUST NOT transmit during that guard. For profile `0x01` and the 255-byte maximum, airtime is 2,295.808 ms and the minimum slot duration is 2,346 ms. The link layer MUST enforce the schedule via `lichen_link_set_slot()` and `tdma_tx_allowed()` (see lichen/subsys/lichen/link implementation). This integrates with TDMA and SCHC compressed control traffic on CH0.

## 2a.5. Multi-Root Beacon Conflict Resolution

When a node receives TDMA beacons from multiple candidate roots on CH0, it MUST apply the following selection criteria in order to resolve conflicts deterministically. All overlap comparisons (RSSI, SNR) MUST use the most recent valid measurement from each candidate.

### 2a.5.1. Signature Verification

Every TDMA beacon received on CH0 for a candidate root MUST carry a valid Schnorr48 signature (see draft-lichen-schnorr-00) over the beacon payload. The node MUST verify the signature against the root's public key before evaluating any selection criteria.

If signature verification fails:
- The received beacon MUST be discarded immediately.
- The candidate root MUST NOT cause any state transition (no SFN adjustment, no slot reassignment, no timer reset, and no DODAG version update).
- The failure MUST NOT alter the node's current sync state or time-provider binding.

The node SHOULD log the signature failure for diagnostic purposes but MUST NOT retain the untrusted root in its candidate list.

### 2a.5.2. Root Selection Criteria

When signatures are valid, nodes MUST select a single root using the following ordered criteria:

1. **RPL DODAG Preference** (MUST): The node MUST prefer the root advertising the highest RPL DODAG Preference field value (higher = more preferred, per RFC 6550). If a root's DIO includes an explicit preference metric, it overrides any default.

2. **Stratum** (MUST): The node MUST prefer the root with the lowest time-provider stratum value (see docs/firmware-time-provider.md). Roots sourcing time from GNSS or a trusted upstream NTP reference (stratum 0-1) MUST take precedence over roots with higher stratum values.

3. **RSSI/SNR** (SHOULD): Between roots of equal DODAG Preference and stratum, the node SHOULD select the root with the highest combined RSSI and SNR (RSSI_EMA + SNR_EMA, with RSSI weighted 2:1 over SNR per EMA update).

4. **EUI-64 Tiebreak** (MUST): If all above criteria are equal, the node MUST select the root with the numerically smaller link-local IID (last 8 bytes of the EUI-64, compared as unsigned big-endian integers).

### 2a.5.3. Overlap Resolution

Beacons from distinct roots that arrive within the same beacon window (setup_window + occupied_time + guard) constitute an overlap. When multiple valid beacons overlap in time:

- If any beacon signature fails verification, the receiving node MUST discard that beacon and proceed as if it were not received.
- The node MUST retain only the one candidate selected per Section 2a.5.2.
- If the selected root differs from the node's current root, the node MUST NOT transition immediately; rather, it MUST defer the transition for a hold-off period of 3 superframes. If the new root remains preferred across the entire hold-off, the node MUST initiate desync and rejoin per Section 2a.6.
- Discarded beacons from non-selected roots MUST NOT accumulate state or influence scheduling decisions.

### 2a.5.4. RPL Version Change During Multi-Root Conflict

When a node's current root increments the RPL DODAG Version Number (as signaled in DIO messages per RFC 6550) while other root candidates remain present:

- The node MUST reset its superframe number (SFN) relative to the current root's new epoch.
- If the version increment coincides with a multi-root conflict (i.e., another root becomes preferred per Section 2a.5.2), the node MUST first complete the version-handling steps below before evaluating the conflict:
  1. Accept the new DODAG Version from the current root.
  2. Reset any desync state that depended on the prior version.
  3. Re-verify the current root's beacon signature upon the first beacon with the new version.
  4. If signature verification fails for the new version, discard the current root and proceed to evaluate remaining candidates per Section 2a.5.2.
- During the hold-off transition described in Section 2a.5.3, a version change from the selected root MUST reset the hold-off counter to zero and restart the 3-superframe hold-off period. If the selected root fails signature verification on the new version, the node MUST immediately evaluate remaining candidates.

### 2a.5.5. Security Properties of TDMA Sync

This section specifies security requirements for TDMA beacon verification and join procedures. See `spec/06-security.md` for the full security architecture.

#### 2a.5.5.1. Beacon Signature Verification Timing

SECURITY: Beacon signature verification MUST use constant-time comparison to prevent timing side-channel attacks. An attacker observing verification latency MUST NOT be able to infer information about the root's private key or the expected signature.

Implementation requirements:
- Schnorr48 verification MUST complete in time independent of input values.
- The final comparison `e'[0:16] == e_received` MUST use a constant-time equality function.
- Implementations SHOULD use platform-provided constant-time primitives (e.g., `crypto_verify_16` from libsodium, `timingsafe_bcmp` on BSD, or equivalent).
- Early-exit on malformed beacon structure (length checks, field bounds) is permitted before cryptographic operations begin.

Receivers MUST NOT log or expose verification timing to untrusted parties. Verification failure events MAY be rate-limited in logs to prevent timing oracle via log inspection.

#### 2a.5.5.2. Join Rate Limiting

Nodes MUST implement join-attempt rate limiting to prevent resource exhaustion attacks on the root and existing mesh members.

**Per-Node Limits:**
- A node MUST NOT transmit more than 1 join request per 10-second window.
- After 3 consecutive failed join attempts (no slot_map received), the node MUST enter exponential backoff: 20s, 40s, 80s, up to a maximum of 320s between attempts.
- The backoff counter resets on successful join (valid slot_map received and adopted).

**Root-Side Limits:**
- The root SHOULD track join requests per source IID with a sliding window.
- The root SHOULD ignore join requests from any IID that exceeds 6 requests per 60-second window.
- The root MAY silently drop excessive join requests without response; it MUST NOT allocate state for dropped requests.

**Proof-of-Work (OPTIONAL):**

Deployments under sustained join-flood attack MAY enable proof-of-work. When enabled:
- The root includes a `pow_challenge` (8-byte nonce) in its beacon.
- Joiners MUST include a `pow_response` in their join frame: a 4-byte value such that `SHA-256(pow_challenge || joiner_iid || pow_response)[0:2] == 0x0000` (16-bit leading zeros).
- The root MUST reject join requests with invalid or missing pow_response when pow_challenge is advertised.
- Finding a valid pow_response requires approximately 2^16 hash evaluations (tens of milliseconds on constrained hardware, negligible for legitimate joins, prohibitive at flood rates).

PoW is disabled by default. The root signals PoW requirement by including the `pow_challenge` field in the CBOR options of the TDMA beacon; absence indicates PoW is not required.

#### 2a.5.5.3. Root Key Compromise Detection

The root beacon is a single point of trust for time synchronization and slot assignment. Nodes MUST implement the following defenses against root key compromise or malicious root behavior.

**Anomaly Detection:**

Nodes SHOULD monitor for indicators of root compromise:
- Sudden large changes in epoch (>100 SFN jump without RPL version change).
- Beacon timestamp significantly inconsistent with local time-provider (>60s drift when GNSS-PPS flag was previously set).
- slot_map assignments that exclude all previously active nodes simultaneously.
- Beacon rate exceeding 1 per expected beacon interval by more than 50%.

On detecting anomalies, nodes SHOULD:
1. Log the anomaly with beacon hash and timestamp.
2. Increment a per-root anomaly counter.
3. If anomaly_count > 3 within 5 minutes, demote the root's trust score for selection (treat as if stratum were increased by 1).
4. If anomaly_count > 10, quarantine the root: refuse to adopt its schedule until manual intervention or out-of-band verification.

**Root Key Rotation:**

Root key rotation follows the COSE_Sign1 attestation protocol in `spec/06-security.md` section 8.7.4. In the TDMA context:

- When a root rotates its key, the new root identity has a different IID (derived from the new public key per section 8.7).
- Nodes MUST receive and validate a key rotation attestation (signed by the OLD key) before accepting beacons from the new IID as the same logical root.
- Without a valid attestation, a new IID appearing as root is treated as a distinct candidate and evaluated per Section 2a.5.2.
- Nodes MUST clear cached slot_map, SFN, and schedule state upon accepting a root key rotation; the new root establishes fresh schedule parameters.

**Compromised Root Recovery:**

If a root key is suspected compromised (out-of-band notification, anomaly quarantine, or administrative action):
1. Nodes with out-of-band revocation capability MUST mark the root's public key as revoked in their trust store.
2. Revoked root beacons MUST be discarded (treated as signature-verification failure per Section 2a.5.1).
3. Nodes MUST fall back to evaluating remaining candidate roots or enter desync recovery (Section 2a.6) if no valid root remains.
4. Mesh recovery from root compromise requires either a surviving trusted root candidate or out-of-band re-provisioning of a new root identity.

**Trust-on-First-Use (TOFU) for Root:**

In self-provisioned deployments, nodes TOFU-pin the root's public key on first beacon (Section 8.7 of 06-security.md). This is a single point of failure: compromise of the root before or during initial pinning allows permanent MITM.

Mitigations for high-security deployments:
- Pre-provision root public key out-of-band (factory, USB, LCI).
- Use multi-root deployments with diversity (Section 2a.5.2) so compromise of one root does not compromise the mesh.
- Enable periodic out-of-band verification of root identity (e.g., display root public key fingerprint for manual comparison).

## 2a.6. Desync Recovery State Machine

This section defines the finite state machine (FSM) for desynchronization detection and recovery. All implementations MUST match test vectors in `test/vectors/ccp16-desync.json`.

### 2a.6.1. States

The desync recovery FSM has three states:

| State | Description |
|-------|-------------|
| SYNCED | Node has valid time synchronization with the root; transmits in assigned slot |
| DESYNCED | Node has lost synchronization; suppresses all scheduled transmission |
| RECOVERING | Node is re-acquiring synchronization; listens for valid beacons |

### 2a.6.2. State Transitions

| Current State | Event | Condition | Next State | Action |
|---------------|-------|-----------|------------|--------|
| SYNCED | SFN wrap | `time_valid=false` (epoch_floor validation failed) | DESYNCED | Suppress TX, reset counters |
| SYNCED | >=3 missed beacons | - | DESYNCED | Suppress TX, reset counters |
| SYNCED | Excessive clock drift | `drift_ppm > GUARD_PPM` | DESYNCED | Trigger epoch_floor revalidation |
| DESYNCED | Valid beacon received | Signature verified, stratum acceptable | RECOVERING | Set `consecutive_valid=1` |
| RECOVERING | Valid beacon received | `consecutive_valid < 3` | RECOVERING | Increment `consecutive_valid` |
| RECOVERING | Valid beacon received | `consecutive_valid >= 3` | SYNCED | Resume scheduled TX |
| RECOVERING | Invalid beacon received | - | DESYNCED | Reset `consecutive_valid=0` |
| RECOVERING | Missed superframe | `missed_superframes >= 3` | DESYNCED | Reset counters, restart listen |

### 2a.6.3. Timing Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| LISTEN_PERIOD_MIN_S | 30 | Minimum listen duration in DESYNCED state |
| LISTEN_PERIOD_MAX_S | 60 | Maximum listen duration before backoff |
| DELAY_PER_NODE_S | 5 | Startup delay per neighbor heard |
| MAX_STARTUP_DELAY_S | 300 | Maximum startup delay |
| BEACON_TIMEOUT_SUPERFRAMES | 3 | Consecutive missed beacons before DESYNCED |
| REJOIN_TIMEOUT_SUPERFRAMES | 10 | Maximum recovery attempts before rejoin |
| GUARD_PPM | 250 | Maximum tolerable clock drift (parts per million) |

### 2a.6.4. Interaction with Time Provider

Desync recovery integrates with the firmware time provider (see `docs/firmware-time-provider.md`):

1. **Epoch Floor Validation**: SFN updates MUST pass `effective_epoch_floor` validation before adoption. A timestamp below the floor triggers transition to DESYNCED.

2. **Wall Clock Valid**: The node MUST NOT transition from DESYNCED to RECOVERING unless `wall_clock_valid=true` after accepting the beacon's timestamp.

3. **Stratum Precedence**: When evaluating candidate beacons in RECOVERING state, the node MUST apply stratum ordering (Section 2a.5.2) before accepting the beacon as valid.

4. **SFN Wrap Handling**: SFN delta computation MUST use unsigned 32-bit arithmetic (`(current_sfn - last_sfn) mod 2^32`) per Section 2a.2. A wrap with invalid time source triggers DESYNCED.

### 2a.6.5. RPL Version Change Interaction

When the RPL DODAG Version Number increments during recovery:

1. The node MUST reset `consecutive_valid=0` and remain in RECOVERING state.
2. The node MUST revalidate the first beacon with the new version against both signature and stratum criteria.
3. If the version change coincides with a root change (multi-root conflict per Section 2a.5), the node MUST complete root selection before resuming recovery count.

### 2a.6.6. Pseudocode (IETF-style)

```
Procedure OnSfnWrap(TimeValid):
    IF State == SYNCED AND NOT TimeValid THEN
        State = DESYNCED
        ConsecutiveValid = 0
        MissedSuperframes = 0
    RETURN State

Procedure OnBeacon(Valid):
    IF State == SYNCED THEN
        IF Valid THEN
            MissedSuperframes = 0
    ELSE IF State == DESYNCED AND Valid THEN
        State = RECOVERING
        ConsecutiveValid = 1
        MissedSuperframes = 0
    ELSE IF State == RECOVERING THEN
        IF Valid THEN
            ConsecutiveValid = ConsecutiveValid + 1
            MissedSuperframes = 0
            IF ConsecutiveValid >= 3 THEN
                State = SYNCED
                ConsecutiveValid = 0
        ELSE
            State = DESYNCED
            ConsecutiveValid = 0
            MissedSuperframes = 0
    RETURN State

Procedure OnMissedSuperframe():
    IF State == SYNCED THEN
        MissedSuperframes = MissedSuperframes + 1
        IF MissedSuperframes >= 3 THEN
            State = DESYNCED
            ConsecutiveValid = 0
            MissedSuperframes = 0
    ELSE IF State == RECOVERING THEN
        MissedSuperframes = MissedSuperframes + 1
        IF MissedSuperframes >= 3 THEN
            State = DESYNCED
            ConsecutiveValid = 0
            MissedSuperframes = 0
    RETURN State

Procedure InitialStartupDelay(NodesHeard):
    RETURN MIN(MAX_STARTUP_DELAY_S, NodesHeard * DELAY_PER_NODE_S)
```

## 2a.4. Time Synchronization

Time synchronization in LICHEN is provided by the firmware time provider (see `docs/firmware-time-provider.md`). The canonical time source is the root's TDMA beacon, which carries a `timestamp` field (u32 BE) and SFN (superframe number). All time-related operations use the `now()` procedure defined in Section 2a.3.1.

Key properties:
- SFN arithmetic MUST use unsigned 32-bit modular arithmetic (modulo 2^32) for correct wrap handling.
- Epoch floor validation MUST pass before adopting time updates.
- Stratum ordering determines time source precedence (Section 2a.5.2).
- The `wall_clock_valid` flag indicates valid synchronization.

For desynchronization detection and recovery, see Section 2a.6.

## 2a.7. Regional Channel Plans and CH0 Rules

A regional channel plan MUST be provisioned locally. An over-the-air message MUST NOT expand the local plan, increase transmit power, or relax regulatory limits.

Each versioned plan contains:
- plan identifier and version;
- ordered channel entries, with CH0 at index zero;
- center frequency, bandwidth, spreading factors, coding rates, and maximum power allowed for each entry;
- regulatory accounting group for each channel;
- applicable duty-cycle, dwell-time, occupancy, and listen-before-talk rules;
- hardware-specific permitted channel mask.

CCP PHY profile ID `0x01` is fixed as LoRa bandwidth 125 kHz, SF10, coding rate 4/5, eight-symbol preamble, explicit header, payload CRC enabled, and low-data-rate optimization disabled. ADR MUST NOT change these parameters inside a schedule generation. See 2a.3 for normative adaptive SF outside schedules. Future profile IDs REQUIRE canonical airtime vectors and a new specification revision before use.

Remote capability and schedule messages MAY reduce the locally permitted intersection. Unknown plan identifiers or versions MUST cause CH0 fallback.

## 2a.3. Channel Agility and Adaptive SF

CH0 is the control channel; all nodes MUST listen continuously on it for DIOs and beacons (see draft-lichen-schc-lora-00 and draft-lichen-rpl-lora-00). Announce messages carry rx_channel (CCP-9 per spec/05-routing.md:9.2) for rendezvous. Data channels selected via select_channel() or hash. All implementations MUST produce identical results to test vectors in ccp16.json, ccp9*.json, ccp_load_balancing.json.

### 2a.3.1. Pure Pseudocode Definitions (IETF-style, language agnostic)

Procedure Now():
   1. RETURN current SFN value.
   2. All subtractions, comparisons, and MOD operations MUST use unsigned 32-bit modular arithmetic (modulo 2^32) to handle wraparound correctly per test vectors.

Procedure SelectChannel(EUI64, Epoch, Density, NChannels):
   1. IF Density > 8 THEN RETURN 0
   2. IF NChannels <= 1 THEN RETURN 0
   3. Data = CONCAT(EUI64 as BE bytes, Epoch as LE u32 bytes)
   4. Hash = FNV1A32(Data)  // basis 0x811c9dc5; matches hash_32.json and ccp16.json vectors
   5. N = NChannels - 1    // exclude reserved CH0
   6. RETURN 1 + (Hash MOD N)

## 2a.8. Adaptive Spreading Factor Selection (per 8gac)

SF10 is the REQUIRED baseline for moderate density (5-20 nodes). Density-aware adaptation and per-neighbor EMA (alpha = 1/4) override only on explicit thresholds. Load_factor from gateway DIOs takes precedence. All paths MUST match ccp16.json and ccp_load_balancing.json exactly (independent oracle).

**Thresholds Table:**

| SF | Sensitivity | Upgrade Condition (SHOULD) | Downgrade Condition (MUST) |
|----|-------------|----------------------------|----------------------------|
| 7  | -123 dBm   | N/A                        | SNR < 0 OR loss > 0.25    |
| 8  | -126 dBm   | Density < 5 AND SNR_EMA > 8 | SNR < 0 OR loss > 0.25    |
| 9  | -129 dBm   | Density < 5 AND SNR_EMA > 8 | SNR < 0 OR Density > 8    |
| 10 | -132 dBm   | DEFAULT (moderate density) | SNR < 0 OR load_factor > 0.8 |
| 11 | -134 dBm   | N/A                        | Density > 8 OR SNR_EMA < 0 OR load > 0.8 |
| 12 | -137 dBm   | N/A                        | Density > 20 OR SNR_EMA < -5 |

Procedure AdaptiveSFSelect(AssignedSF, Neighbor, Density, Utilization, LoadFactor):
   1. SF = AssignedSF
   2. IF SF absent THEN SF = 10
   3. IF (Density > 8) OR (Utilization > 150) THEN SF = MIN(12, SF + 2)
   4. IF (Neighbor.EMA_SNR > 8) AND (Density < 5) THEN SF = MAX(7, SF - 1)
   5. IF (Neighbor.EMA_Loss > 0.25) OR (Utilization > 200) OR (LoadFactor > 0.8) THEN
          SF = MIN(12, SF + 1)
          IF Utilization > 200 THEN RETURN (12, false)  // tx not allowed; fixed maximum per ccp16_utilization.json
   6. RETURN (SF, true)

After step 6, the Downgrade (MUST increase SF) column of the thresholds table above applies as minimum-SF floors, in this order:
   a. IF Neighbor.EMA_SNR < -5 THEN SF = 12
   b. IF Neighbor.EMA_SNR < 0 THEN SF = MAX(11, SF)
   c. IF Density > 8 THEN SF = MAX(11, SF)
   d. IF LoadFactor > 0.8 THEN SF = MAX(11, SF)

EMA_Update(Avg, Sample) = Avg + ((Sample - Avg) right-shift 2). Update per-neighbor state on every RX. Integrate with RPL DIO capability signaling. No dead code.

(The state machine from prior section remains; JOINED uses SelectChannel and AdaptiveSFSelect per schedule.)

## 2a.9. Adaptive Duty Cycle (adaptive_duty_permille)

Each node SHALL enforce a transmit-airtime budget over a rolling 1-hour window (3600000 ms) as specified here (CCP-13). The budget is expressed in permille of the window: duty_permille of 10 corresponds to 36000 ms of airtime per hour.

Nodes MUST estimate neighbor density from the number of distinct link-layer peers heard within the current window and MUST report that estimate to the L2 layer whenever it changes. Implementations SHOULD re-evaluate the effective budget before every transmission so the ceiling always reflects the currently reported density.

### 2a.9.1. Density-to-Budget Mapping

The duty region is the `duty_region` value of the node's configured operating class (CCP-4, section 2a.7): region 0 covers strictly duty-cycle-limited regulatory domains (EU, AU/NZ); region 1 covers lenient domains (US/CA).

| Density | Condition | Region 0 (EU, AU/NZ) | Region 1 (US/CA) |
|---------|-----------|----------------------|------------------|
| Dense   | density > 8  | 5 permille (0.5%)  | 10 permille (1%) |
| Moderate| 3 <= density <= 8 | 10 permille (1%) | 20 permille (2%) |
| Sparse  | density < 3  | 20 permille (2%)   | 50 permille (5%) |

A node MUST NOT exceed the budget in force for its reported density, and MUST use the most conservative (lowest) applicable value when the operating class is unknown.

### 2a.9.2. Pure Pseudocode Definitions (IETF-style, language agnostic)

Procedure AdaptiveDutyPermille(Density, Region):
   1. IF Density > 8 THEN
         RETURN Region == 0 ? 5 : 10
   2. IF Density < 3 THEN
         RETURN Region == 0 ? 20 : 50
   3. RETURN Region == 0 ? 10 : 20

Procedure MaxTxMs(DutyPermille):
   1. RETURN (3600000 / 1000) * DutyPermille

The maximum transmit time MaxTxMs(DutyPermille) MUST be computed from the current adaptive DutyPermille; hardcoding a default constant is non-conformant. The per-transmission airtime check, window accounting, and next-available-time computation are those of the CCP-13 DutyCycleTracker and MUST match test/vectors/ccp13.json exactly (independent oracle). Adaptive mapping vectors in ccp13.json carry a crc32 integrity tag over their inputs.

## 2a.10. Interference Mitigation Algorithm (CCP-15)

This section consolidates the CCP-15 interference mitigation algorithm. Three coordinated mechanisms share one deterministic per-transmit-opportunity procedure:

1. **Frequency agility** — deterministic hash-based data-channel selection (Section 2a.3.1) with mandatory CH0 fallback at high density, plus CCA-driven contention handling;
2. **Density-based adaptive SF selection** — the AdaptiveSFSelect procedure and threshold table of Section 2a.8, fed by a locally estimated density;
3. **TDMA coordination** — hash-derived slot admission with slot_map and guard enforcement (Section 2a.2), which removes contention the other two mechanisms would otherwise have to tolerate.

All three mechanisms consume the same density estimate (Section 2a.10.3): when density exceeds DENSITY_HIGH (8), SelectChannel returns CH0, AdaptiveSFSelect floors SF at 11, and the 2a.9 duty budget tightens simultaneously. Every implementation MUST reproduce the results of `test/vectors/ccp15.json` (categories `cca`, `frequency_agility`, `interference`, `adaptive_sf`, `tdma`), `test/vectors/ccp-interference.json` (interference score), `test/vectors/ccp_ema_update_integer.json` (EMA), and `test/vectors/ccp16.json` with `ccp16_utilization.json` (SF and channel selection) exactly.

### 2a.10.1. Inputs and Outputs

Inputs, evaluated at each transmit opportunity:

| Input | Type | Source | Description |
|-------|------|--------|-------------|
| NodeEUI64 | 8 bytes | Provisioned | This node's EUI-64, exact wire byte order |
| Epoch | u32 | Root beacon / DIO | Current schedule generation (2a.2) |
| SFN | u32 | Time provider | Current superframe number (2a.4) |
| NumSlots | u8 | Root beacon | TDMA slot count, hash modulus (default 8) |
| SlotMap | u8[] | Root beacon | Assigned slot indices for this node (2a.2) |
| NChannels | u8 | Regional plan | Configured channel-plan entries including CH0 (2a.7) |
| Density | u8 | Local estimate | Output of EstimateDensity (2a.10.3) |
| ChannelBusy | bool | CAD result | Clear-channel-assessment outcome for the selected channel |
| BusyPercent | u8, 0..100 | L2 sampling | Channel busy-time percentage over the metrics window |
| PacketErrorPermille | u16, 0..1000 | L2 sampling | TX failures per 1000 attempted frames |
| EMA_SNR, EMA_Loss | per-neighbor | RF health | EMA-smoothed SNR (dB) and loss ratio, alpha = 1/4 (2a.8) |
| Utilization | u8, 0..255 | L2 sampling | Fractional airtime occupancy (255 = 100%) (2a.8) |
| LoadFactor | u32, Q16.16 | Gateway DIO | Gateway-reported load (2^16 = 1.0) (2a.8) |

Outputs:

| Output | Type | Description |
|--------|------|-------------|
| Channel | u8 | Data channel index (0 = CH0) |
| SF | u8, 7..12 | Spreading factor for this transmission |
| TxAllowed | bool | false means suppress this transmit opportunity |
| CcaState | (BackoffExp, Retries) | Contention state carried to the next attempt |
| InterferenceScoreTenths | u16 | Monitoring metric (2a.10.4) |

### 2a.10.2. Node State

| State | Type | Scope | Reset | Defined in |
|-------|------|-------|-------|------------|
| BackoffExp, Retries | u8 | Per contention cycle | Clear CAD result | 2a.10.5 |
| Neighbor.EMA_SNR, Neighbor.EMA_Loss, sample count | per neighbor | Neighbor table | Neighbor expiry | 2a.8 |
| DensityEstimate | u8 | Node | Recomputed each metrics window | 2a.10.3 |
| BusyPercent, PacketErrorPermille accumulators | u32 counters | Node, rolling window | Window rollover | 2a.10.3 |
| Desync FSM state | SYNCED / DESYNCED / RECOVERING | Node | Per 2a.6 | 2a.6 |
| Duty-window airtime counters | u32 | Node | Rolling 1-hour window | 2a.9 |

All counters MUST be saturating (a wraparound MUST NOT corrupt mitigation state). no_std implementations SHOULD use Q16.16 fixed point per appendix-design-rationale.md:7.6 and lichen-core::rf_health.

### 2a.10.3. Metrics Collection and Density Estimation

The mitigation decisions above are only as good as their inputs; the following sampling procedure is normative:

1. A node MUST perform a CAD immediately before every scheduled transmission and MUST feed the boolean result to CcaUpdate (2a.10.5).
2. BusyPercent MUST be computed as TX-time based occupancy (total detected airtime divided by the observation window) and MUST NOT be derived from RSSI-only averaging, per 02-physical-link.md Section 3.5.
3. PacketErrorPermille = floor(tx_failures * 1000 / MAX(1, packets_tx)) over the metrics window, where packets_tx counts scheduled data frames and tx_failures counts frames abandoned after CCA exhaustion or unanswered (per link-layer retransmission policy).
4. BusyPercent and PacketErrorPermille MUST be measured over a rolling window of RF_METRICS_WINDOW_SF superframes (default 32; proposed constant, see 2a.10.6). Sampling SHOULD be performed during TDMA guard or idle time so that measurement does not consume data-slot airtime.
5. Per-neighbor EMA_SNR and EMA_Loss MUST be updated on every received frame using the integer EMA of ccp_ema_update_integer.json (alpha = 1/4, right shift 2), matching 2a.8.
6. Density MUST be estimated at least once per metrics window:

```
Procedure EstimateDensity(NeighborCount, LossPermille, RssiEmaDbm):
   1. D = NeighborCount          // distinct link-layer peers heard in the current
                                 // window; the same estimate feeds 2a.9 reporting
   2. IF LossPermille > DENSITY_PER_BONUS_PERMILLE THEN D = D + 2
                                 // persistent loss implies hidden congestion
   3. IF RssiEmaDbm < DENSITY_RSSI_BONUS_DBM THEN D = D + 1
                                 // weak links imply a larger effective cell
   4. RETURN MIN(255, D)
```

DENSITY_PER_BONUS_PERMILLE (default 100, i.e. PER > 10%) and DENSITY_RSSI_BONUS_DBM (default -90 dBm) are proposed constants not yet present in implementation constant files; until promoted, implementations MUST use exactly these defaults so that density estimates remain interoperable.

### 2a.10.4. Interference Score

The interference score is a monitoring metric combining channel occupancy and loss:

```
InterferenceScoreTenths = BusyPercent * 10 + PacketErrorPermille
```

expressed in tenths of a percentage point, equivalently `busy_pct + PER * 100` in percentage points. Implementations MUST reject BusyPercent > 100 or PacketErrorPermille > 1000 and MUST match `test/vectors/ccp15.json` (`score_tenths`) and `test/vectors/ccp-interference.json` (`interference_score`) exactly. The `backoff_jitter_ms` column of ccp-interference.json is non-normative: no closed form is specified by any normative text, and conformance tests intentionally do not assert it.

A node SHOULD evaluate InterferenceScoreTenths once per metrics window and log it for diagnostics. A node MAY treat a score persistently above INTERFERENCE_ESCAPE_TENTHS (default 1000, proposed; deployment-configurable) as a trigger to request an epoch rollover per 2a.10.5. No transmission decision is gated on the score alone; the per-mechanism thresholds of 2a.3.1, 2a.8, and 2a.10.5 remain normative.

### 2a.10.5. Consolidated Pseudocode (IETF-style, language agnostic)

Channel selection reuses SelectChannel (2a.3.1) inside the priority chain of appendix-ccp12-hopping.md Section 6 (CCP-9 announce > CCP-16 hash > CH0). SF selection reuses AdaptiveSFSelect (2a.8) including the threshold-table floors that follow its steps. TDMA admission reuses 2a.2.

```
Procedure SlotHash(EUI64, SFN, NumSlots):
   // Exact per 2a.2 and ccp15.json category `tdma`
   1. H = FNV1A32(EUI64 as 8 BE bytes)              // basis 0x811c9dc5
   2. RETURN ((H + u32(SFN)) MOD 2^32) MOD NumSlots

Procedure CcaUpdate(State, ChannelBusy):
   // Exact per ccp15.json category `cca`
   1. IF NOT ChannelBusy THEN
          State.BackoffExp = 0
          State.Retries = 0
          RETURN (TX_SUCCESS, State)                // TxAllowed = true
   2. IF State.Retries > CSMA_RETRY_LIMIT THEN
          RETURN (RETRY_EXHAUSTED, State)           // fail closed, no further increments
   3. State.Retries = State.Retries + 1
   4. IF State.Retries > CSMA_RETRY_LIMIT THEN
          RETURN (RETRY_EXHAUSTED, State)
   5. State.BackoffExp = MIN(CSMA_BACKOFF_MAX, State.BackoffExp + 1)
   6. RETURN (CAD_BUSY, State)                      // TxAllowed = false

Procedure MitigateInterference(Op):
   // Op carries the inputs of Section 2a.10.1; run at each transmit opportunity
   1. IF DesyncState != SYNCED THEN
          suppress all scheduled transmission and listen on CH0 per 2a.6; RETURN
   2. Slot = SlotHash(Op.NodeEUI64, Op.SFN, Op.NumSlots)
   3. IF Op.SlotMap is empty OR Slot NOT IN Op.SlotMap THEN
          RETURN (defer to next assigned slot)      // MUST NOT transmit outside slot_map (2a.2)
   4. IF local time is within GUARD (50 ms) of the slot end THEN
          RETURN (defer)                            // MUST NOT transmit in guard (2a.2)
   5. Channel = ChannelPriorityChain(Op.NodeEUI64, Op.Epoch, Op.Density, Op.NChannels)
                                                    // 2a.3.1: Density > 8 yields CH0
   6. ChannelBusy = CAD(Channel)
   7. (Result, CcaState) = CcaUpdate(CcaState, ChannelBusy)
   8. IF Result == CAD_BUSY THEN
          RETURN (defer; retry within the same slot per link-layer backoff, up to CSMA_RETRY_LIMIT)
   9. IF Result == RETRY_EXHAUSTED THEN
          record one TX failure (feeds PacketErrorPermille and EstimateDensity)
          evaluate InterferenceScoreTenths per 2a.10.4
          defer to next assigned slot
          MAY request an epoch rollover from the root (deterministically rotates
          every node's hash-derived data channel; see 2a.10.6 normative notes)
          RETURN (TxAllowed = false)
  10. (SF, TxAllowed) = AdaptiveSFSelect(Op.AssignedSF, Op.Density, Op.Metrics)
                                                    // 2a.8 including floors;
                                                    // Utilization > 200 returns (12, false)
  11. IF NOT TxAllowed OR the 2a.9 duty budget is exhausted THEN RETURN (suppress)
  12. Transmit on Channel with SF inside the data window (before GUARD)
  13. On TX outcome, update packets_tx / tx_failures and per-neighbor EMA state per 2a.10.3
```

Normative statements:

- A node MUST perform CCA before every scheduled transmission and MUST fail closed (no transmission) on RETRY_EXHAUSTED.
- A node MUST NOT transmit outside its assigned slot_map or during the trailing 50 ms guard (2a.2).
- Slot, SFN, and channel arithmetic MUST use unsigned 32-bit modular arithmetic (2a.2, 2a.4).
- When Density > DENSITY_HIGH (8), a node MUST use CH0 for data (2a.3.1) and MUST select SF >= 11 (2a.8).
- A node MUST listen continuously on CH0 (2a.3) even while using a hash-selected data channel.
- SF selection MUST apply the 2a.8 threshold-table floors after the AdaptiveSFSelect steps; the Utilization > 200 path MUST return (12, false).
- After RETRY_EXHAUSTED a node SHOULD defer until its next assigned slot and MAY request an epoch rollover; a node MUST NOT change channels by any over-the-air-negotiated mechanism (2a.7).
- CCP-12 synchronized hopping (appendix-ccp12-hopping.md) MAY replace per-peer hash selection in deployments with stratum <= 2 time sources; it is OPTIONAL and MUST NOT be interleaved with CCP-16 selection within one schedule generation.
- InterferenceScoreTenths is a monitoring metric only; implementations MUST NOT gate transmission on it alone.

### 2a.10.6. Parameter Table

Parameters marked **proposed** are not yet present in implementation constant files and MUST be used with exactly the default value shown until promoted.

| Parameter | Default | Status | Provenance |
|-----------|---------|--------|------------|
| FNV_OFFSET_BASIS | 0x811c9dc5 | existing | 2a.2; appendix-ccp12-hopping.md Sec. 3.1 |
| FNV_PRIME | 0x01000193 | existing | appendix-ccp12-hopping.md Sec. 3.1 |
| NUM_SLOTS | 8 | existing | 2a.2 |
| GUARD_MS | 50 | existing | 2a.2 |
| SF_BASELINE | 10 | existing | 2a.8; 02-physical-link.md Sec. 3.5 |
| SF_MIN / SF_MAX | 7 / 12 | existing | 2a.8 |
| DENSITY_LOW | 5 | existing | 2a.8; `LICHEN_RF_DENSITY_LOW`, rf_health.rs |
| DENSITY_HIGH | 8 | existing | 2a.3.1, 2a.9; `LICHEN_RF_DENSITY_HIGH` |
| DENSITY_CRITICAL | 20 | existing | 2a.8; `LICHEN_RF_DENSITY_CRITICAL` |
| SNR_GOOD | 8 dB | existing | 2a.8; `LICHEN_RF_SNR_GOOD` |
| SNR_POOR | 0 dB | existing | 2a.8; `LICHEN_RF_SNR_POOR` |
| SNR_CRITICAL | -5 dB | existing | 2a.8; `LICHEN_RF_SNR_CRITICAL` |
| LOSS_HIGH | 0.25 | existing | 2a.8 step 5 |
| LOAD_HIGH | 0.8 | existing | 2a.8; `LICHEN_RF_LOAD_HIGH_FP` (4/5 in Q16.16) |
| UTILIZATION_ESCALATE | 150 | existing | 2a.8 step 3; ccp16_utilization.json |
| UTILIZATION_BLOCK | 200 | existing | 2a.8 step 5; ccp16_utilization.json |
| EMA_ALPHA | 1/4 (shift 2) | existing | 2a.8; ccp_ema_update_integer.json; `LICHEN_RF_EMA_ALPHA_SHIFT` |
| CSMA_RETRY_LIMIT | 3 | existing | lichen-core constants.rs; ccp15.json `cca` |
| CSMA_BACKOFF_MAX | 5 | existing | lichen-core constants.rs; ccp15.json `cca` |
| DUTY_WINDOW_MS | 3600000 | existing | 2a.9 |
| RF_METRICS_WINDOW_SF | 32 | **proposed** | 2a.10.3 |
| DENSITY_PER_BONUS_PERMILLE | 100 | **proposed** | 2a.10.3 |
| DENSITY_RSSI_BONUS_DBM | -90 | **proposed** | 2a.10.3 |
| INTERFERENCE_ESCAPE_TENTHS | 1000 | **proposed** | 2a.10.4 |

## Implementation Status

- Python simulator, Rust gateway, Zephyr `lichen/subsys/lichen` validate against `test/vectors/ccp16.json`, `ccp_tdma.json`, `link_frame.json`, `l2_payload.json`.
- Kconfig options for CCP16, TDMA_SLOTS, integration with RPL/SCHC/TDMA complete. SCHC Rule 0x08 for TDMA beacon implemented.
- Adaptive SF, desync FSM, channel plans, Multi-RX gateway support implemented and tested.
- All codereview passes closed. Capacity gains verified in simulation per independent oracles.

## References

### Normative References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997, <https://www.rfc-editor.org/info/rfc2119>.

- `test/vectors/ccp_sfn_wrap_slot_hash.json`, `ccp16.json`, `ccp15.json`, `ccp-interference.json`, `ccp_ema_update_integer.json`, `ccp16_utilization.json`, `ccp16-desync.json`, `ccp_tdma.json`, `link_frame.json`, `l2_payload.json` (authoritative for TDMA beacon format, CDDL, byte layout, slot/hash, join flows, SFN wrap, desync FSM, CCA, interference score, density SF; MUST match exactly)

- `spec/drafts/draft-lichen-rpl-lora-00.md`
- `spec/drafts/draft-lichen-schc-lora-00.md`
- `spec/appendix-design-rationale.md`
- `spec/appendix-ccp12-hopping.md` (CCP-16/CCP-12 channel selection; FNV-1a32 definition)
- `spec/appendix-schc.md` (Rule 0x08=TDMA_BEACON)
- `spec/02-physical-link.md` Section 3.5 (adaptive SF; TX-time-based utilization measurement)
- `lichen/subsys/lichen/link*` (for `lichen_link_set_slot()`, `tdma_tx_allowed()`)
- `lichen/subsys/lichen/link/include/lichen/rf_health.h` and `rust/lichen-core/src/rf_health.rs` (CCP-15 constant sources)
- `docs/firmware-time-provider.md`
- `spec/drafts/draft-lichen-link-01.md` (L2 0x15 join frame)
- `spec/drafts/draft-lichen-schnorr-00.md` (Schnorr48 beacon signature)

[← Previous](02-physical-link.md) | [Index](README.md) | [Next →](03-adaptation.md)
