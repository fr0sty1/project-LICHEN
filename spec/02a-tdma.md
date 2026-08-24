# TDMA for LICHEN

**Spec section for PHY TDMA overlay (gateway-centric mode).**

## Introduction

TDMA eliminates collisions in gateway-centric deployments by assigning exclusive time slots to nodes. It is an optional overlay on top of ALOHA/CSMA (backwards compatible, no flag day).

**MUST** implement beacon sync mode. GPS-sync is RECOMMENDED when hardware available.

## Frame Structure

### Superframe

- Beacon slot: gateway TX (synchronization, slot map)
- N data slots: node TX (assigned nodes only)
- Contention slot(s): new nodes, retries, legacy ALOHA traffic

Slot duration MUST be at least `ceil(maximum permitted PHY-payload airtime in milliseconds) + guard_time` for the configured schedule profile. It MUST NOT be derived from a typical frame.

For the canonical SF10/125 kHz, CR 4/5 profile with an eight-symbol preamble, explicit header, PHY CRC, and the 255-byte maximum payload, airtime is 2,295.808 ms. With the mandatory 50 ms guard, the minimum slot is 2,346 ms. The data window starts at the slot boundary and the single guard occupies the final 50 ms; a node MUST NOT transmit during the guard.

Beacon content (normative wire format, SCHC-compressed on CH0):
- Type (1B): 0xBE (beacon)
- SFN (u32): superframe number for slot computation and wrap detection
- Timestamp (u32): reference time for drift compensation and stratum
- Stratum (u8): time source quality (0=GNSS, 1=mesh, per 09-packets-timing)
- N_slots (u8): default 8-32
- Slot bitmap or assigned list (variable)
- Next beacon delta (u16 ms)

Beacon uses distinct sync word (0x34 per spec) or LLSec flag. Old nodes MUST ignore (backwards compatible).

## Rendezvous

Priority order (per lichen_coordination_mechanism in link.h:106):
1. SCHEDULED: gateway-assigned slot from beacon/DIO (preferred for TDMA)
2. HASH_BASED: `slot = (hash_32(EUI64) + u32(SFN)) mod n_slots` (FNV-1a32 basis `0x811c9dc5`; addition wraps modulo 2^32; see `ccp_sfn_wrap_slot_hash.json`)
3. ANNOUNCE_DRIVEN: rx_channel from Announce (CCP-9, ccp9*.json)
4. FALLBACK: CH0 contention

Rendezvous enables predictable TX/RX windows without constant listening. Matches ccp9-rendezvous.json and ccp16-hop.json vectors exactly.

## Drift Compensation

Linear correction from beacon arrival:

```
delta_ms = local_rx_ms - expected_beacon_ms
drift_ppm = (delta_ms * 1000000) / beacon_interval_ms
correction_ms = drift_ppm * future_delta_ms / 1000000
adjusted_time = local_time + correction_ms
```

See ccp_tdma.json "drift_compensation" vector (local 123456, expected 123400, ppm=10, correction=56). Nodes MUST apply before slot calculation. GPS stratum improves clock accuracy but MUST NOT reduce the 50 ms guard. Threshold >5000ppm triggers desync (per ccp16-desync.json).

## Join Procedure (FSM)

See 09-packets-timing.md:14.8 and AGENTS.md init graph (lichen_link_init before tdma_init):

- **UNJOINED**: CH0 listen only, no TX. On power-on or reset.
- **ACQUIRING**: Valid beacon (signature verified, stratum >= current, ts >= epoch_floor) → adopt SFN/time, send DAO with slot request. Beacons with invalid or missing signatures MUST be silently discarded.
- **SYNCED**: DAO-ACK received, TX only in assigned slot, periodic beacon listen. Enforce tdma_tx_allowed().
- **DRIFTING**: >3 missed beacons or RPL version change or excessive drift → extended CH0 listen, suppress TDMA TX.
- **RECOVERING**: 3 consecutive valid beacons → re-SYNCED.

Rejoin timeout = 10 * superframe (Kconfig default 10s). All transitions, multi-root conflicts, SFN wrap (unsigned u32 per RFC 1982 semantics) covered by ccp_tdma.json and ccp16-desync.json. MUST follow lichen_node_init() ordering to avoid use-before-init.

## Multi-Root Beacon Conflict Handling

When a node hears beacons from multiple DODAG roots (same RPLInstanceID, different source IIDs):

- The beacon with the higher stratum (lower numerical value for the TimeStratum field) MUST be preferred.
- If strata are equal, a node MUST prefer the beacon from the root with the lowest IID (treated as a 64-bit unsigned integer).
- A node MUST verify the Schnorr signature on every beacon before considering any field. Beacons with invalid or missing signatures MUST be silently discarded regardless of stratum or IID.
- The overlap between two valid beacons at equal stratum with different IIDs is resolved deterministically by the lowest-IID rule above. This ensures all nodes converge on the same root without oscillation.
- After switching roots, the node MUST send a new DAO with the new parent and reset its SFN relative to the new root's epoch.
- A node that was SYNCED and encounters a beacon with a higher stratum (indicating a better time source) SHOULD re-evaluate its root preference but MUST NOT switch roots more than once per superframe to prevent flapping.
- While DRIFTING, a node MUST NOT adopt beacons from a different root unless the beacon's stratum is lower (better) than the previous root's stratum. At equal stratum, the node MUST remain with its current root.

## Test Vectors

All MUST match test/vectors/ccp_tdma.json (slot hash, guard boundaries, drift), ccp_load_balancing.json, ccp9*.json exactly. Independent oracles (external arithmetic, no code-under-test).

## Appendix A: Constants

- GUARD_TIME_MS = 50
- SLOT_DURATION_MS (SF10 profile maximum) = 2346
- A 60-second superframe can contain at most 25 whole 2346 ms slots before reserving beacon and contention time.
- HASH_BASIS = 0x811c9dc5 (FNV-1a32)
- slot_adjust_ticks = 8 (scheduler tolerance for predictive wakeup; matches ccp_load_balancing.json vector)

(Updated per project-LICHEN-frdz: beacon format, rendezvous priority, drift formula, FSM join procedure.)

---
[← Coordinated Capacity](02a-coordinated-capacity.md) | [Index](README.md)
