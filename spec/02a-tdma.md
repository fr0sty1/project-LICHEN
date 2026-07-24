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

Slot duration = max_packet_airtime + guard_time.

At SF10/125kHz, 60-byte packet ~200 ms airtime + 50 ms guard = 250 ms slot (4 slots/sec, 240 slots/min for 60 s superframe).

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
2. HASH_BASED: slot = hash_32(EUI64 + SFN.to_bytes(4, "little")) % n_slots (lichen_hash_32, FNV-1a32 basis 0x811c9dc5; see ccp_tdma.json)
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

See ccp_tdma.json "drift_compensation" vector (local 123456, expected 123400, ppm=10, correction=56). Nodes MUST apply before slot calculation. GPS stratum reduces guard from 50ms. Threshold >5000ppm triggers desync (per ccp16-desync.json).

## Join Procedure (FSM)

See 09-packets-timing.md:14.8 and AGENTS.md init graph (lichen_link_init before tdma_init):

- **UNJOINED**: CH0 listen only, no TX. On power-on or reset.
- **ACQUIRING**: Valid beacon (stratum >= current, ts >= epoch_floor) → adopt SFN/time, send DAO with slot request.
- **SYNCED**: DAO-ACK received, TX only in assigned slot, periodic beacon listen. Enforce tdma_tx_allowed().
- **DRIFTING**: >3 missed beacons or RPL version change or excessive drift → extended CH0 listen, suppress TDMA TX.
- **RECOVERING**: 3 consecutive valid beacons → re-SYNCED.

Rejoin timeout = 10 * superframe (Kconfig default 10s). All transitions, multi-root conflicts, SFN wrap (unsigned u32 per RFC 1982 semantics) covered by ccp_tdma.json and ccp16-desync.json. MUST follow lichen_node_init() ordering to avoid use-before-init.

## Test Vectors

All MUST match test/vectors/ccp_tdma.json (slot hash, guard boundaries, drift), ccp_load_balancing.json, ccp9*.json exactly. Independent oracles (external arithmetic, no code-under-test).

## Appendix A: Constants

- GUARD_TIME_MS = 50
- SLOT_DURATION_MS (SF10) = 250
- SUPERFRAME_SLOTS = 240 (for 60s at 250ms)
- HASH_BASIS = 0x811c9dc5 (FNV-1a32)

(Updated per project-LICHEN-frdz: beacon format, rendezvous priority, drift formula, FSM join procedure.)

---
[← Coordinated Capacity](02a-coordinated-capacity.md) | [Index](README.md)
