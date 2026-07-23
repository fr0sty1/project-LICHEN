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

Beacon content:
- Superframe number (for sync)
- Slot assignments (compressed bitmap or list)
- Next beacon time

Beacon frame type MUST be distinguishable (different sync word or header flag). Old nodes MUST ignore unknown frame types.

## Slot Assignment

### Static (hash-based)

Node IID hash mod N_SLOTS. Simple, no coordination. Collisions possible if hash collision (rare with good hash).

### Dynamic (gateway-assigned)

Gateway tracks active nodes, assigns in beacon or DIO option. Reassigns on join/leave. Preferred for load balancing.

## Guard Time

50 ms guard compensates for ~1% clock drift over 5 s superframe. GPS-equipped nodes use absolute time to reduce guard.

## Backwards Compatibility

No flag day required.

- Old nodes: ignore beacons, use ALOHA/CSMA.
- New nodes: sync to beacon, use assigned slots.
- Mixed: contention slot for old nodes and new-node fallback.
- Gateway receives during all slots + contention.
- More old nodes = more contention usage = less TDMA benefit, but never worse than pure ALOHA.

**Degradation graceful.**

## Signaling

Announce/DIO includes current SF and slot info. Per-neighbor SF tracking (project-LICHEN-zrh2) integrates with TDMA slot map.

## Test Vectors

See test/vectors/tdma-timing.json and ccp_load_balancing.json for exact slot calculation, beacon parsing, and interop with ALOHA nodes.

All implementations MUST produce identical output for vectors.

## Appendix A: Constants

- GUARD_TIME_MS = 50
- SLOT_DURATION_MS (SF10) = 250
- SUPERFRAME_SLOTS = 240
- HASH_MOD = N_SLOTS

(Updated from parent project-LICHEN-i9r0.)

---
[← Coordinated Capacity](02a-coordinated-capacity.md) | [Index](README.md)
