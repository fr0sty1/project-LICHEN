<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Appendix B: RPL Configuration

RPL is used for border router traffic only. See Section 8 for details.
For peer-to-peer traffic, see Appendix B2 (LOADng).

## B.1. Objective Function

**MRHOF (Minimum Rank with Hysteresis Objective Function):**

```
ETX(link) = transmissions / successes
PathETX = sum(ETX(link)) for all links to root
Rank = (PathETX * 128) + MinHopRankIncrease
```

## B.2. Configuration Option Values

| Parameter | Value |
|-----------|-------|
| RPLInstanceID | 0 (default instance) |
| Mode of Operation | Non-Storing (MOP=1) |
| MinHopRankIncrease | 256 |
| MaxRankIncrease | 2048 |
| Default Lifetime | 30 minutes |
| Lifetime Unit | 60 seconds |

## B.3. Trickle Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Imin | 4096 ms | ~4 seconds |
| Imax | 20 | 2^20 ms = ~17 minutes |
| k | 10 | Redundancy constant |

## B.4. CCP-16 Load Balancing Extensions

See `rust/lichen-rpl/src/lib.rs` and `test/vectors/ccp_load_balancing.json` for:
- TDMA slot computation via `hash_32(sfn, key)`
- Adaptive SF and density metrics in DIO options
- Multi-channel rendezvous via `compute_rendezvous_channel`
- CoordinationMechanism enum for hash/scheduled/announce-driven modes

Python reference impl is authoritative. All changes validated against vectors.

---

[← Previous: Appendix A](appendix-schc.md) | [Index](README.md) | [Next: Appendix B2 →](appendix-loadng.md)
