<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Coordinated Capacity Protocol (CCP)

## Abstract

The Coordinated Capacity Protocol (CCP) defines mechanisms for coordinated capacity management in LICHEN LoRa meshes. This includes TDMA slot assignment, channel agility via select_channel with density-aware fallback, adaptive spreading factor selection via adaptive_sf_select (incorporating EMA-smoothed SNR and load_factor), time synchronization via now(), CH0 control channel rules, signed rx_channel for CCP-9 da2q rendezvous, density/load rules, capability signaling in DIOs, and desynchronization recovery.

All implementations MUST produce identical output to the canonical test vectors in test/vectors/ccp*.json (ccp9.json, ccp9-rendezvous.json, ccp9_rendezvous.json, ccp13.json, ccp15.json, ccp16.json, ccp16-desync.json, ccp16-hop.json, ccp_load_balancing.json, ccp_tdma.json). These cover TDMA/hash slot computation, select_channel, adaptive_sf_select, EMA updates, unsigned SFN wraparound, rx_channel signing/rendezvous, density thresholds, load balancing, desync FSM transitions, and CCP-14 Multi-RX scheduling.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## Table of Contents

1. Abstract
2. Overview
3. TDMA Frame Structure, Slot Assignment, now(), and Desync Recovery
4. Regional Channel Plans and CH0 Rules
5. Channel Selection (select_channel)
6. Adaptive Spreading Factor Selection, EMA, and Density Rules
7. CCP-9 da2q Rendezvous with signed rx_channel
8. Capability DIO Signaling
9. References

## Overview

LICHEN networks operate under severe bandwidth and duty-cycle constraints. CCP coordinates access to the shared medium using hash-derived TDMA slots synchronized to a network epoch, density-aware adaptive SF selection, multi-channel operation (CH0 dedicated to control per SCHC-compressed beacons and RPL DIOs), deterministic channel agility, time synchronization, signed rx_channel announcements for rendezvous, per-neighbor EMA for RF metrics, and load/density signaling. The root advertises epoch and num_slots. Nodes suppress transmission outside assigned slots. All algorithms are deterministic.

## TDMA Frame Structure, Slot Assignment, now(), and Desync Recovery

Slot ID MUST be computed as fnv1a32(EUI64 XOR epoch) MOD num_slots (lichen_hash_32 primitive, basis 0x811c9dc5; see test/vectors/hash_32.json and all ccp*.json). Slot duration equals maximum airtime(current_SF) plus guard time. The link layer enforces this.

function now():
    RETURN current_sfn()  // monotonic unsigned 32-bit superframe/epoch counter (SFN_MODULUS = 2^32)
    // All subtractions, comparisons, and modulo operations MUST use unsigned 32-bit arithmetic to handle wraparound correctly.

A CCP-capable node is always in exactly one of these states:

| State    | Meaning                          | Channel Behavior          |
|----------|----------------------------------|---------------------------|
| UNJOINED | Never synchronized               | CH0 only; no hopping      |
| JOINED   | Clock trusted; normal operation  | Hop per schedule/select_channel |
| DRIFT    | Possible drift; monitoring       | Hop with extended RX windows |
| RECOVER  | Clock untrusted; seeking beacon  | CH0 only; no data TX      |

Transitions use unsigned SFN delta, epoch_floor validation, multi-root preference (highest epoch), and timers defined by test/vectors/ccp16-desync.json and ccp_tdma.json. RPL version changes reset relative to the new root. Drift > threshold moves to DRIFT or RECOVER. Nodes in RECOVER or UNJOINED MUST refrain from data transmissions.

## Regional Channel Plans and CH0 Rules

A regional channel plan MUST be provisioned locally. An over-the-air message MUST NOT expand the local plan, increase power, or relax regulatory limits. Each plan lists ordered channels (CH0 at index 0), frequencies, permitted SFs, coding rates, power, duty-cycle, dwell, and hardware mask. Unknown plan/version causes CH0 fallback.

CH0 is the control channel. All nodes MUST listen continuously on CH0 for DIOs, beacons, announces, DIS, and DAO messages. Control traffic (SCHC-compressed) uses CH0 exclusively. High density forces fallback to CH0 for data as well (interference mitigation and desync recovery). Data channels (1+) are used only when density permits and a valid rx_channel or select_channel result is available. Gateway Multi-RX (CCP-14) enables simultaneous reception across control + data channels.

## Channel Selection (select_channel)

function select_channel(eui64, epoch, density, n_channels):
    // CCP-12/16 synchronized hopping for frequency agility and interference mitigation.
    // Uses byte concatenation (EUI64 big-endian + epoch little-endian).
    data = eui64_to_bytes_big_endian(eui64) concatenated with u32_to_bytes_little_endian(epoch)
    hash = fnv1a32(data)
    IF density > 8 THEN
        RETURN 0  // CH0 control channel
    n = 3
    IF n_channels > 0 THEN
        n = n_channels
    RETURN 1 + (hash MOD n)

## Adaptive Spreading Factor Selection, EMA, and Density Rules

SF10 (or gateway-assigned SF via DIO) is the REQUIRED baseline. adaptive_sf_select overrides this only on explicit thresholds. Nodes MUST receive on all SF7-SF12. Per-neighbor state tracks EMA-smoothed SNR (and loss rate). Density is the count of unique neighbors (deduplicated by IID) heard in the recent window. load_factor incorporates utilization and pending traffic. These metrics plus current assigned SF are signaled in capability DIO options.

function ema_update(avg, sample):
    diff = sample - avg
    RETURN avg + (diff >> 2)  // alpha equivalent to 1/4

function adaptive_sf_select(density, snr_ema, load_factor):
    // Critical conditions evaluated first.
    IF (density > 20) OR (snr_ema < -5) THEN
        RETURN 12
    ELSE IF (density > 8) OR (snr_ema < 0) OR (load_factor > 0.8) THEN
        RETURN 11
    ELSE IF (density < 5) AND (snr_ema > 8) THEN
        RETURN 9
    ELSE
        RETURN 10

**Normative Density Rules Table:**

| Priority | Condition                              | SF | Rationale                     |
|----------|----------------------------------------|----|-------------------------------|
| Critical | density > 20 OR snr_ema < -5          | 12 | Extreme congestion or poor link |
| High     | density > 8 OR snr_ema < 0 OR load_factor > 0.8 | 11 | High density, marginal link, or overload |
| Capacity | density < 5 AND snr_ema > 8           | 9  | Low density + excellent link  |
| Default  | otherwise                              | 10 | Baseline                      |

Exact behavior, thresholds, and edge cases (including density=8) are defined by the pseudocode and produce identical output to test/vectors/ccp15.json, ccp16.json, ccp_load_balancing.json.

## CCP-9 da2q Rendezvous with signed rx_channel

Announce messages carry rx_channel (0-7; 0 denotes CH0 fallback). This value is packed in the flags byte (offset 1) and MUST be included in the Schnorr48 signed_data transcript:

signed_data = originator_iid(8) || pubkey(32) || seq_num(2) || rx_channel(1) || app_data

This binding (CCP-9) prevents tampering and enables secure da2q rendezvous. A sender uses the pinned rx_channel from a valid recent Announce when available (TOFU-style pinning); otherwise falls back to select_channel(hash result) or CH0. Hop count is not signed. See test/vectors/ccp9.json, ccp9-rendezvous.json, and ccp9_rendezvous.json for exact formats, signing oracles, L2 dispatch (0x15), round-trip, and rendezvous scheduling.

## Capability DIO Signaling

RPL DIOs on CH0 include a capability option (or extended DAG Metric Container) carrying density, EMA-derived SF recommendation, load_factor/utilization, current TX_SF, and per-neighbor RF metrics. This supports MRHOF parent selection, central rebalancing at the border router, and network-wide coordination. Nodes signal ASSIGNED_SF and metrics; gateways use them for Multi-RX scheduling (CCP-14). Exact option format and integration are defined in 05-routing.md; behavior MUST match test vectors.

## References

- test/vectors/ccp*.json (normative oracles for all algorithms, vectors[0-2] for TDMA/SF/channel/tx_allowed, vectors[3+] for Multi-RX/capacity metrics; independent FNV-1a + airtime + simulation oracles)
- RFC 2119
- 05-routing.md (Announce format, capability DIO details)
- draft-lichen-rpl-lora-00.md (RPL option integration)
- draft-lichen-schc-lora-00.md (CH0 usage)
