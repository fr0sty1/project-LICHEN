<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# RPL Configuration for LoRa Mesh Networks

```
Internet-Draft                                              LICHEN Project
draft-lichen-rpl-lora-00                                        May 2026
Intended status: Experimental
Expires: November 2026
```

## Status of This Document

**PRELIMINARY DRAFT — WORK IN PROGRESS**

This document is an early draft developed alongside a reference implementation.
It will be updated as implementation experience is gained. Coding agents with
human oversight may modify this specification as needed.

This Internet-Draft is submitted in full conformance with the provisions of
BCP 78 and BCP 79.

## Abstract

This document specifies RPL (IPv6 Routing Protocol for Low-Power and Lossy
Networks) configuration parameters optimized for LoRa mesh networks. It
addresses the unique characteristics of LoRa: very low data rates, high
latency, duty cycle restrictions, and long-range links. The profile modifies
Trickle timer parameters, defines a LoRa-specific objective function, and
specifies link-layer security integration.

## Table of Contents

1. Introduction
2. Terminology
3. LoRa Network Characteristics
4. RPL Mode of Operation
5. Objective Function
6. Trickle Timer Parameters
7. DAO and Downward Routes
8. Security
9. DIO Options
10. Implementation Considerations
11. Security Considerations
12. IANA Considerations
13. References

## 1. Introduction

RPL (RFC 6550) was designed for Low-Power and Lossy Networks (LLNs) such
as IEEE 802.15.4-based networks. LoRa networks share some characteristics
with these networks but differ significantly in:

- **Data rate:** LoRa is 10-100x slower than 802.15.4
- **Latency:** LoRa round-trip times are seconds, not milliseconds
- **Range:** LoRa links can span kilometers, not meters
- **Duty cycle:** LoRa is heavily duty-cycle restricted (1-10%)

This document specifies RPL parameters tuned for these characteristics.

### 1.1. Design Goals

- **Stable routing:** Minimize route oscillation in high-latency environment
- **Efficient control plane:** Reduce DIO/DAO overhead to preserve duty cycle
- **Long-range awareness:** Prefer shorter paths over marginally better links
- **Security:** Integrate with link-layer signature-based authentication

### 1.2. Applicability

This profile applies to LoRa mesh networks using:
- LoRa PHY (SX126x, SX127x, or similar)
- SF7-SF12, BW 125-500 kHz
- Mesh topology (not star/LoRaWAN)
- IPv6 with SCHC compression

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

- **DODAG:** Destination-Oriented Directed Acyclic Graph
- **DIO:** DODAG Information Object (downward advertisement)
- **DAO:** Destination Advertisement Object (upward registration)
- **DIS:** DODAG Information Solicitation
- **OF:** Objective Function (route selection algorithm)
- **MRHOF:** Minimum Rank with Hysteresis Objective Function
- **ETX:** Expected Transmission Count

## 3. LoRa Network Characteristics

### 3.1. Data Rate and Latency

| Spreading Factor | Bit Rate | Airtime (50B) | Typical RTT |
|------------------|----------|---------------|-------------|
| SF7 | 5470 bps | 72 ms | 200-500 ms |
| SF9 | 1760 bps | 206 ms | 500-1500 ms |
| SF12 | 293 bps | 1319 ms | 3-10 s |

Multi-hop RTT can exceed 30 seconds at SF12 with 3+ hops.

### 3.2. Duty Cycle

| Region | Band | Duty Cycle |
|--------|------|------------|
| EU | 868 MHz (g1) | 1% |
| EU | 868 MHz (g3) | 10% |
| US | 915 MHz | None (FCC) |
| AU | 915 MHz | None |

At 1% duty cycle with 200ms packets, maximum is 36 packets/hour.

### 3.3. Link Asymmetry

LoRa links may be asymmetric due to:
- Different TX power configurations
- Antenna placement
- Environmental factors
- Interference patterns

RPL MUST use bidirectional link verification.

## 4. RPL Mode of Operation

### 4.1. Mode Selection

This profile uses **Non-Storing Mode** exclusively:

| Aspect | Storing Mode | Non-Storing Mode |
|--------|--------------|------------------|
| Routing state | At each router | At root only |
| Downward routing | Hop-by-hop | Source routing |
| RAM required | O(network) | O(parents) |
| Root burden | Low | Higher |

Rationale: LoRa nodes are often memory-constrained. Non-storing mode
minimizes RAM requirements at routers.

### 4.2. DODAG Configuration

| Parameter | Value | Rationale | Source |
|-----------|-------|-----------|--------|
| RPLInstanceID | 0 | Single instance | constants.toml:46, lichen-core::constants::RPL_INSTANCE_ID |
| Mode | Non-Storing (MOP=1) | Memory efficiency (root holds routes) | constants.toml:47, RPL_MODE_OF_OPERATION |
| Grounded | Yes (if BR) | Internet connectivity via 6LBR | draft-lichen-border-router |
| DAG Metric Container | Yes | Required for MRHOF ETX | RFC 6550 |

### 4.3. Multiple DODAGs

When multiple border routers exist:
- Each BR MAY form its own DODAG
- Nodes choose DODAG based on objective function
- Nodes MAY join multiple DODAGs (memory permitting)

## 5. Objective Function

### 5.1. MRHOF Adaptation

This profile uses MRHOF (RFC 6719) with LoRa-specific adaptations.

**Rank calculation:**

```
Rank = Rank(parent) + Step
Step = MinHopRankIncrease × (1 + ETX_factor × ETX + Latency_factor × RTT)
```

**Parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| MinHopRankIncrease | 256 | Standard |
| ETX_factor | 0.5 | Reduce ETX sensitivity |
| Latency_factor | 0.1 | Mild preference for lower latency |
| PARENT_SWITCH_THRESHOLD | 384 | ~1.5 hops hysteresis |
| MAX_RANK_INCREASE | 1024 | Limit rank inflation |

### 5.2. Link Metrics

**ETX calculation:**

```
ETX = 1 / (forward_delivery × reverse_delivery)

forward_delivery = packets_acked / packets_sent
reverse_delivery = estimated from ACK reception
```

**RTT estimation:**

```
RTT_smoothed = 0.875 × RTT_smoothed + 0.125 × RTT_sample
```

### 5.3. Parent Selection

A node SHOULD switch to a new preferred parent if:

```
Rank(new_parent) + Step(new_parent) + THRESHOLD < Rank(current_parent)
```

This hysteresis prevents oscillation in noisy environments.

### 5.4. Bidirectional Verification

Before selecting a parent, verify bidirectionality:
1. Receive DIO from candidate parent
2. Send DAO to candidate parent
3. If DAO-ACK received within timeout: link is bidirectional
4. If not: mark link as unidirectional, do not use as parent

## 6. Trickle Timer Parameters

### 6.1. Standard Trickle

Trickle algorithm (RFC 6206) controls DIO transmission rate.

**Parameters:**

| Parameter | Symbol | Value | Rationale |
|-----------|--------|-------|-----------|
| Minimum interval | Imin | 4 seconds | Allow network to stabilize |
| Maximum interval | Imax | 17.5 minutes | 2^8 × Imin, reduce steady-state |
| Redundancy constant | k | 10 | High k = more suppression |

### 6.2. Interval Calculation

```
Imin = 4 s = 4000 ms
Imax = 2^8 × Imin = 256 × 4 s = 1024 s ≈ 17 minutes
```

**Behavior:**

| Network state | DIO interval |
|---------------|--------------|
| Startup/inconsistency | 4-8 seconds |
| Stabilizing | 8-64 seconds |
| Stable | 4-17 minutes |

### 6.3. Trickle Reset Triggers

Reset Trickle timer (back to Imin) on:
- DODAG version change
- Rank change
- DIO configuration change
- Loop detected

Do NOT reset on:
- New node joining (handled by DIS)
- Metric updates (allow settling)

### 6.4. DIS Handling

When a node sends DIS (solicit):
- Targeted DIS: unicast response with DIO
- Multicast DIS: reset Trickle, respond probabilistically

To prevent DIS storms:
- Rate limit DIS transmission (max 1 per 10 seconds)
- Ignore rapid DIS from same source

## 7. DAO and Downward Routes

### 7.1. DAO Timing

| Event | Timing |
|-------|--------|
| Initial DAO | Random 0-2s after parent selection |
| DAO retry | 4, 8, 16 seconds (exponential backoff) |
| DAO refresh | Every 30 minutes (before lifetime expires) |
| DAO on parent change | Immediate (with jitter 0-500ms) |

**DAO Source Address Model:** DAO packets use routable ULA source (DODAG-root derived prefix) for multi-hop forwarding. Relays preserve the original IPv6 source end-to-end (see spec/04-network.md and SCHC Rule 4). This satisfies security requirements for source binding.

### 7.2. DAO Lifetime

```
Lifetime = DAO_LIFETIME_UNIT × DAO_LIFETIME
         = 60 seconds × 60
         = 3600 seconds = 1 hour
```

Nodes MUST refresh DAO before lifetime expires (recommend 50% of lifetime).

### 7.3. DAO-ACK

Root MUST send DAO-ACK for every DAO received:
- Confirms receipt
- Provides feedback (accept/reject)
- Triggers bidirectional verification

### 7.4. Source Routing Header

In non-storing mode, root inserts source routing header:

```
IPv6 header:
  Source: root
  Destination: final (via source route)

Routing Header (type 3, RFC 6554):
  Segments Left: N
  Address[1]: hop 1
  Address[2]: hop 2
  ...
  Address[N]: final destination
```

Maximum path length: 8 hops (header size constraint).

## 8. Security

### 8.1. Security Model

This profile relies on **link-layer signatures** as the primary
security mechanism, not RPL's built-in security modes.

| RPL Security Mode | Usage |
|-------------------|-------|
| Unsecured | DEFAULT — link-layer sigs provide auth |
| Preinstalled | OPTIONAL — additional defense-in-depth |
| Authenticated | NOT RECOMMENDED — requires KDC |

### 8.2. Link-Layer Signature Protection

All RPL control messages (DIO, DAO, DIS) are link-layer frames that MUST carry Schnorr signatures per draft-lichen-link-01:4.2 (unsigned RPL control frames MUST be rejected by receivers; permissive mode is test-only). See spec/06-security.md:8.10 for full requirements.

This provides:
- Sender authentication
- Message integrity
- Replay protection (via epoch + sequence number)

### 8.3. Optional Preinstalled Mode

For high-security deployments:
- Configure network-wide PSK
- Enable RPL preinstalled mode
- PSK authenticates control plane
- Defense-in-depth against compromised nodes

### 8.4. Root Verification

Nodes SHOULD verify root legitimacy:
- Root's public key should be pre-provisioned or TOFU-pinned
- Unexpected root changes should alert operator
- Multiple roots with different keys may indicate attack

## 9. DIO Options

### 9.1. Mandatory Options

| Option | When |
|--------|------|
| DODAG Configuration | Every DIO |
| Prefix Information | When advertising prefix |
| DAG Metric Container | When using MRHOF |

### 9.2. LICHEN-Specific Options

**SCHC Rule Version Option:**

```
+--------+--------+--------+
| Type   | Length | Version|
+--------+--------+--------+
  TBD      1        1 (uint8)
```

Advertises SCHC rule set version for compression compatibility.

**Time Synchronization Option:**

```
+--------+--------+--------+--------+--------+--------+
| Type   | Length | Stratum| Reserved| Timestamp (4B)  |
+--------+--------+--------+--------+--------+--------+
  TBD      1        1        1           4 (Unix epoch)
```

Provides time synchronization for replay protection.

**Congestion Level Option:**

```
+--------+--------+--------+
| Type   | Length | Level  |
+--------+--------+--------+
  TBD      1        1 (0-3)
```

Advertises node congestion for routing decisions.

<<<<<<< HEAD
**ASSIGNED_SF and RF Metrics Option (CCP-16):** MUST be carried in RPL DIO options per CCP-16. Nodes MUST compute TX_SF via pseudocode in physical-link:3.4 and 02a:2a.3. Includes per-neighbor EMA, density, utilization. Test vectors ccp16.json MUST validate interop.
=======
**Adaptive SF Recommendation:**

The DAG Metric Container MUST include current SF per-neighbor EMA-derived recommendation per CCP-16 in spec/02a-coordinated-capacity.md section 4.2. Thresholds and EMA update are normative there. DIOs on control channel provide the announcement. RX scanning on CH0 is REQUIRED.
>>>>>>> origin/integration/worker11-20260722

### 9.3. Prefix Information Option

When DODAG root advertises prefix:

```
+--------+--------+--------+--------+
| Type   | Length |  Flags |PrefLen |
+--------+--------+--------+--------+
|            Valid Lifetime         |
+--------+--------+--------+--------+
|          Preferred Lifetime       |
+--------+--------+--------+--------+
|              Reserved             |
+--------+--------+--------+--------+
|                                   |
|            Prefix (16 bytes)      |
|                                   |
|                                   |
+--------+--------+--------+--------+
```

## 10. Implementation Considerations

### 10.1. Memory Requirements

| Component | RAM | Notes |
|-----------|-----|-------|
| DODAG state | ~100 bytes | Version, rank, etc. |
| Parent table | ~50 bytes/parent | Typically 2-4 parents |
| Trickle state | ~20 bytes | Timers, counters |
| DAO retry state | ~20 bytes | Pending DAOs |
| **Total** | **~300 bytes** | Minimal footprint |

### 10.2. Timers

| Timer | Resolution | Notes |
|-------|------------|-------|
| Trickle | 1 second | Coarse is acceptable |
| DAO retry | 1 second | Exponential backoff |
| DAO lifetime | 1 minute | Refresh at 50% |
| Link timeout | 10 seconds | Neighbor unreachable |

### 10.3. Recommended Defaults

```c
#define RPL_INSTANCE_ID          0
#define RPL_MOP                  RPL_MOP_NON_STORING
#define RPL_TRICKLE_IMIN         (4 * 1000)    // 4 seconds
#define RPL_TRICKLE_IMAX         8             // 2^8 doublings
#define RPL_TRICKLE_K            10            // redundancy constant
#define RPL_DAO_LIFETIME_UNIT    60            // seconds
#define RPL_DAO_LIFETIME         60            // 1 hour
#define RPL_DEFAULT_PARENT_COUNT 3             // max parents to track
#define RPL_MRHOF_THRESHOLD      384           // parent switch hysteresis
```

## 11. Security Considerations

### 11.1. Routing Attacks

| Attack | Mitigation |
|--------|------------|
| DIO spoofing | Link-layer signatures |
| Rank manipulation | Hysteresis, neighbor validation |
| DAO flooding | Rate limiting, lifetime enforcement |
| DODAG partition | Root demotion protocol |

### 11.2. Sybil Attacks

An attacker with multiple identities could:
- Create fake routes
- Attract traffic to black hole
- Disrupt routing

Mitigation: EUI-64 bound to public key prevents identity forging.

### 11.3. Wormhole Attacks

Attacker relays DIO across mesh, advertising false proximity.

Partial mitigation:
- RTT-based rank calculation penalizes high-latency links
- Geographic verification (if GPS available)

Full mitigation requires secure localization, out of scope.

## 12. IANA Considerations

This document requests allocation of:

- RPL DIO Option Types for:
  - SCHC Rule Version
  - Time Synchronization
  - Congestion Level

Specific values TBD.

## 13. References

### 13.1. Normative References

- [RFC 2119] Key words for use in RFCs
- [RFC 6550] RPL: IPv6 Routing Protocol for LLNs
- [RFC 6206] The Trickle Algorithm
- [RFC 6719] MRHOF for RPL

### 13.2. Informative References

- [RFC 6551] RPL Metrics
- [RFC 6554] RPL Source Routing Header
- [LICHEN] LICHEN Protocol Specification

## Appendix A. Sample DODAG Configuration

```
RPLInstanceID: 0
DODAGID: 0200:1234:5678:9abc::1
Version: 1
Rank: 256 (root)
Mode: Non-Storing
Grounded: Yes
DTSN: 0
Flags: 0

Trickle:
  Imin: 4s
  Imax: 8 doublings (17 min)
  k: 10

# No prefix advertisement (02xx addresses are self-derived from key)
Valid Lifetime: 86400s (1 day)
Preferred Lifetime: 43200s (12 hours)
```

## Appendix B. Parent Selection Example

**TODO:** Add worked example of parent selection with MRHOF.

## Authors' Address

LICHEN Project
https://github.com/MarkAtwood/project-LICHEN
