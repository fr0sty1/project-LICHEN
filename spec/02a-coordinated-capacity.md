<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Coordinated Capacity Profile (CCP)

## CCP-12: Synchronized Hopping

Nodes in a LICHEN mesh MUST follow a shared pseudo-random frequency hopping sequence synchronized via SFN (from beacons) or GPS time to maximize capacity while enabling rendezvous.

**Hop Sequence:**
- Control channel: fixed frequency (e.g. 868.1 MHz).
- Data channels: N channels selected by `channel = hash_32(sfn.to_be_bytes() ^ seed) % N` where `hash_32` is the keyed CRC32 defined in `test/vectors/hash_32.json` (key=`LICHEN`).
- SFN is 32-bit unsigned from beacon sfn field or GPS (see 09-packets-timing.md:263 for SFN_delta, epoch_floor, and rx_valid_until_sfn rules; beacon SFN computation cross-ref).
- Nodes MUST listen on control channel for beacons/DIOs and compute current data channel for TX/RX.

**Rendezvous:**
- Beacons and DIOs MUST include current SFN, rx_channel, and rendezvous timestamp (MUST).
- Receiving nodes SHOULD switch to announced rx_channel for the rendezvous window (SHOULD).
- This enables nodes to find each other without continuous multi-channel listening.

**Frequency Selection:**
- Use `hash_32` for deterministic, collision-resistant channel selection (RFC2119 MUST).
- Seed can be network-wide or per-DODAG (from root beacon).

**Test Vectors:**
See `test/vectors/ccp16-hop.json` and `test/vectors/ccp16-rendezvous.json` for independent oracles (CRC32 based, not derived from sim code). All impls (Python sim, Rust, Zephyr) MUST match.

**Implementation Status:**
- Spec: complete.
- Python sim: implemented in `python/src/lichen/sim/medium.py`, `node.py`, `protocol.py`.
- Test vectors: added.
- C/Zephyr/Rust: pending (see da2q.12 children).

## CCP-13: Adaptive Duty Cycle (density>8=5permille, <3=20permille)

Nodes MUST adapt duty cycle limit based on local density estimate (unique neighbors via RPL/announces in 1h window, dedup via hash_32(EUI64, key="LICHEN") per test/vectors/hash_32.json for independent oracle).

**Per-Region Tables (RFC2119 MUST):**

| Density | EU868 (permille) | US915 (permille) | Notes |
|---------|------------------|------------------|-------|
| > 8     | 5 (0.5%)        | 10 (1.0%)       | High density congestion control |
| 3-8     | 10 (1.0%)       | 20 (2.0%)       | Nominal per standards |
| < 3     | 20 (2.0%)       | 50 (5.0%)       | Low density, higher utilization allowed |

**Pseudocode (MUST match):**
```c
uint16_t adaptive_duty_permille(uint8_t density, uint8_t region) {
    if (density > 8) return (region == EU868 ? 5 : 10);
    if (density < 3) return (region == EU868 ? 20 : 50);
    return (region == EU868 ? 10 : 20);
}
```

MAX_TX_MS MUST be computed as `(WINDOW_MS * duty_permille) / 1000` from current value (not hardcoded DEFAULT_DUTY_PERMILLE). Nodes MUST respect this for all TX (CoAP, RPL, announces). Report in LCI status.

**Test Vectors:** ccp_tdma.json and hash_32.json (precomputed via external Python+crc32 oracle for density hash, not derived from code). All impls MUST match. No test weakening.

**Implementation Status:** Zephyr lora_l2.c:implemented (adaptive_duty_permille), Rust duty_cycle updated for dynamic MAX_TX_MS, spec+CCP-13 complete. See da2q.13.5/qsr0/vpu8/q0yt.

**Pseudocode Conventions (for CCP-15 frequency agility and all sections):**
- `now()`: current monotonic time in milliseconds (u64, from boot or GNSS epoch).
- `clamp(x, lo, hi)`: `max(lo, min(x, hi))` for numeric x (prevents wraparound).
- Floating point thresholds (e.g. interference scores): MUST use exact values 0.1 (low), 0.5 (medium), 0.8 (high) for interoperability. Normative per §2.

See parent epic da2q.13 and da2q.13.5 for full CCP. Frequency agility pseudocode (mitigate_and_transmit, channel selection with history scores) fixed per codereview wlb0.
