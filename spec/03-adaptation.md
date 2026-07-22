<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Adaptation Layer

## 5. Adaptation Layer

### 5.1. Design Choice: SCHC, Not 6LoWPAN IPHC

Traditional 6LoWPAN (RFC 4944, 6282) was designed for IEEE 802.15.4 networks.
LICHEN uses **SCHC (RFC 8724) instead** because:

| Aspect | 6LoWPAN IPHC | SCHC |
|--------|--------------|------|
| Designed for | 802.15.4 | **LPWAN (LoRa, Sigfox, NB-IoT)** |
| Compression | Fixed encoding | **Flexible rules** |
| Fragmentation | Tied to 802.15.4 | **LPWAN-optimized (ACK-on-Error)** |
| CoAP compression | Separate (RFC 8824) | **Integrated** |
| MTU assumption | 127 bytes | **Variable** |

**LICHEN stack (no 802.15.4):**

```
┌─────────────────────────────────┐
│  IPv6 / UDP / ICMPv6 / CoAP    │
├─────────────────────────────────┤
│  SCHC (RFC 8724)               │
│  - Compression (replaces IPHC) │
│  - Fragmentation               │
├─────────────────────────────────┤
│  LICHEN Link Layer             │
│  - Custom framing              │
│  - Schnorr signatures          │
├─────────────────────────────────┤
│  LoRa PHY                      │
└─────────────────────────────────┘
```

**Zephyr integration:** Requires custom L2 driver or network interface.
Cannot use `CONFIG_NET_L2_IEEE802154`.

### 5.2. SCHC Overview (RFC 8724)

Static Context Header Compression uses pre-shared "rules" to compress
headers. Both sender and receiver store identical rule sets; packets
carry only a Rule ID and residue (changed fields).

### 5.3. Compression Gains

| Headers | Uncompressed | SCHC Compressed |
|---------|--------------|-----------------|
| IPv6 | 40 bytes | 1-2 bytes (link-local) |
| IPv6 + UDP | 48 bytes | 3-6 bytes |
| IPv6 + UDP + CoAP | 60+ bytes | 6-12 bytes |

### 5.4. Rule Structure

Each rule specifies, for each header field:
- **TV (Target Value):** Expected value
- **MO (Matching Operator):** equal, ignore, MSB(n), etc.
- **CDA (Compression/Decompression Action):** not-sent, value-sent, LSB(n), etc.

### 5.5. Default Rules

Rule IDs 0-127 are for compression rules. Rule ID 255 is reserved for
uncompressed fallback (see 5.7).

**Rule 0: Link-local IPv6 + UDP (most common)**

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.Version | 6 | equal | not-sent |
| IPv6.TrafficClass | 0 | equal | not-sent |
| IPv6.FlowLabel | 0 | equal | not-sent |
| IPv6.PayloadLength | - | ignore | compute |
| IPv6.NextHeader | 17 (UDP) | equal | not-sent |
| IPv6.HopLimit | 64 | ignore | not-sent |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent |
| IPv6.SrcIID | - | equal | not-sent (from L2) |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent |
| IPv6.DstIID | - | equal | not-sent (from L2) |
| UDP.SrcPort | 5683 | MSB(12) | LSB(4) |
| UDP.DstPort | 5683 | MSB(12) | LSB(4) |
| UDP.Length | - | ignore | compute |
| UDP.Checksum | - | ignore | compute |

**Compressed size: 2 bytes** (Rule ID + 2x 4-bit port residue)

**Rule 1: Global IPv6 + UDP (internet-routable)**

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.SrcPrefix | mesh_prefix/64 | equal | not-sent |
| IPv6.DstPrefix | 0 | ignore | value-sent (64 bits) |
| (other fields as Rule 0) | | | |

**Compressed size: 10 bytes** (includes full destination prefix)

**Rule 2: Link-local IPv6 + UDP + MQTT-SN**

MQTT-SN uses port 10883, which lies outside the 5680-5695 range compressed
by Rules 0 and 1. Rule 2 provides equivalent compression for MQTT-SN traffic.

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.Version | 6 | equal | not-sent |
| IPv6.TrafficClass | 0 | equal | not-sent |
| IPv6.FlowLabel | 0 | equal | not-sent |
| IPv6.PayloadLength | - | ignore | compute |
| IPv6.NextHeader | 17 (UDP) | equal | not-sent |
| IPv6.HopLimit | 64 | ignore | not-sent |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent |
| IPv6.SrcIID | - | equal | not-sent (from L2) |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent |
| IPv6.DstIID | - | equal | not-sent (from L2) |
| UDP.SrcPort | 10883 | equal | not-sent |
| UDP.DstPort | 10883 | equal | not-sent |
| UDP.Length | - | ignore | compute |
| UDP.Checksum | - | ignore | compute |

**Compressed size: 1 byte** (Rule ID only; both ports exactly match)

**Port Compression Note:**

Rules 0 and 1 use MSB(12)/LSB(4) matching on port 5683, compressing any port
in the range 5680-5695 to a 4-bit residue. This range covers CoAP (5683),
compact CoT (5681), SenML (5682), Cayenne LPP (5685), APRS-IS (5686), and
NMEA (5687). See Section 9.1 for the complete port allocation.

**Rule 3/4: RPL DIO/DAO over link-local ICMPv6 (RFC 6550)**

Rule 3 for DIO (code=1), Rule 4 for DAO with D=1 (kd_flags bit 6 set, DODAGID present; common non-storing case). DAOs without DODAGID fall back to Rule 255. kd_flags byte: bit7=K (ACK req), bit6=D, lower bits flags. Matches Python _DAO_BASE_FIELDS, Rust RPL_DAO_RULE and codec (now fully synced at rules.py:290).

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6 (link-local as Rule 0) | ... | ... | ... |
| ICMPv6.type | 155 | equal | not-sent |
| ICMPv6.code | 1/2 | equal | not-sent |
| ICMPv6.checksum | - | ignore | compute |
| RPL.instance | - | ignore | value-sent |
| RPL.kd_flags | - | ignore | value-sent |
| RPL.reserved | 0 | equal | not-sent |
| RPL.seq (or dtsn/gmop/rank for DIO) | - | ignore | value-sent |
| RPL.dodagid | - | ignore | value-sent |

**Compressed size:** 6-10 bytes (RuleID + hop/IID residue + RPL fields).

### 5.6. Fragmentation

Packets exceeding L2 MTU are fragmented per RFC 8724 Section 8:

**Fragment Header:**
```
+--------+--------+--------+
| RuleID | W | FCN | (MIC) |
+--------+--------+--------+
```

- **W (Window):** 1-bit window indicator
- **FCN (Fragment Counter):** 6 bits, counts down from N to 0
- **MIC:** Message Integrity Check on final fragment

**ACK-on-Error mode** recommended for LoRa: receiver only sends NACK
for missing fragments.

### 5.7. Rule Versioning and Interoperability

SCHC requires identical rule sets on sender and receiver. To ensure
interoperability across firmware versions:

**Rule Set Version:**

Each LICHEN release defines a rule set version (8-bit unsigned integer).
Version increments when rules are added, removed, or modified.

| Version | Description |
|---------|-------------|
| 0 | Reserved (uncompressed fallback) |
| 1 | Initial LICHEN release |
| 2+ | Future versions |

**DIO Rule Version Option (Type TBD):** PIO proposal for RPL options (incl. potential PIO) at python/src/lichen/schc/rules.py:272 and 03-adaptation.md:184 (cross-ref 04-network.md:52 no-PIO in no-ULA model per 06-security.md:128).

DODAG roots advertise their rule set version in DIO messages:

```
+--------+--------+--------+
| Type   | Length | Version|
+--------+--------+--------+
   1B       1B       1B
```

Nodes SHOULD only join a DODAG if their rule set version matches the
advertised version. Version mismatch indicates firmware incompatibility.

**Fallback Rule (Rule ID 255): No Compression**

Rule 255 is reserved for uncompressed packets. All implementations MUST
support Rule 255 regardless of version:

```
Rule 255 packet:
+----------+-----------------+
| RuleID   | Full IPv6 packet|
| (1 byte) | (40+ bytes)     |
+----------+-----------------+
```

**When to use Rule 255:**
- Decompression failure (unknown rule ID)
- Version mismatch detected
- Debugging / diagnostics
- Communicating with legacy nodes

**Decompression Failure Handling:**

| Scenario | Action |
|----------|--------|
| Unknown Rule ID | Drop packet, log warning |
| Decompression produces invalid IPv6 | Drop packet, log warning |
| Repeated failures from same source | Assume version mismatch, notify operator |

**Version Negotiation:**

Explicit version negotiation is NOT required. The DIO advertisement
provides passive discovery. Nodes with mismatched versions:
1. Cannot join the same DODAG (DIO filter)
2. Can still communicate via Rule 255 (degraded performance)
3. Should be upgraded to matching firmware

**Backward Compatibility:**

When updating firmware:
1. New rules SHOULD be added with new Rule IDs (don't reuse)
2. Old rules SHOULD remain supported for one version cycle
3. Version number MUST increment on any rule change

---

[← Previous: Physical and Link Layers](02-physical-link.md) | [Index](README.md) | [Next: Network Layer →](04-network.md)
