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
| Link-local IPv6 + UDP | 48 bytes | 18 bytes |
| Native IPv6 + UDP | 48 bytes | 32-33 bytes |
| Native IPv6 + UDP + common CoAP | 60+ bytes | About 41 bytes |

### 5.4. Rule Structure

Each rule specifies, for each header field:
- **TV (Target Value):** Expected value
- **MO (Matching Operator):** equal, ignore, MSB(n), etc.
- **CDA (Compression/Decompression Action):** not-sent, value-sent, LSB(n), etc.

### 5.5. Default Rules

Rule IDs 0-127 are for compression rules. Rule ID 255 is reserved for
uncompressed fallback (see 5.7).

**Rule 0: Link-local IPv6 + UDP**

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.Version | 6 | equal | not-sent |
| IPv6.TrafficClass | 0 | equal | not-sent |
| IPv6.FlowLabel | 0 | equal | not-sent |
| IPv6.PayloadLength | - | ignore | compute |
| IPv6.NextHeader | 17 (UDP) | equal | not-sent |
| IPv6.HopLimit | 64 | equal | not-sent |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent |
| IPv6.SrcIID | - | ignore | value-sent (64 bits) |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent |
| IPv6.DstIID | - | ignore | value-sent (64 bits) |
| UDP.SrcPort | 5683 | MSB(12) | LSB(4) |
| UDP.DstPort | 5683 | MSB(12) | LSB(4) |
| UDP.Length | - | ignore | compute |
| UDP.Checksum | - | ignore | compute |

**Compressed size: 18 bytes** (Rule ID, two IIDs, and port residue)

**Rule 1: Native Yggdrasil IPv6 + UDP**

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.HopLimit | - | ignore | value-sent (8 bits) |
| IPv6.SrcAddr | 0200::/8 | MSB(8) | LSB(120) |
| IPv6.DstAddr | 0200::/8 | MSB(8) | LSB(120) |
| (UDP fields as Rule 0) | | | |

Native addresses are flat `/128` identifiers, not a shared prefix plus IID.
Only the fixed `0x02` byte can be elided without synchronized key context.
**Compressed size: 33 bytes** (Rule ID, Hop Limit, two 120-bit address
residues, and port residues).

A deployment-specific rule MAY derive an address from a public-key context,
but only when every forwarding node on the path has that authenticated SCHC
context. The baseline does not define context distribution and MUST fall back
to Rule 1 or Rule 255 instead of assuming that an IID identifies a key.

**Rule 2: Native Yggdrasil IPv6 + UDP + MQTT-SN**

MQTT-SN uses port 10883, which lies outside the 5680-5695 range compressed
by Rules 0 and 1. Rule 2 provides equivalent compression for MQTT-SN traffic.

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.Version | 6 | equal | not-sent |
| IPv6.TrafficClass | 0 | equal | not-sent |
| IPv6.FlowLabel | 0 | equal | not-sent |
| IPv6.PayloadLength | - | ignore | compute |
| IPv6.NextHeader | 17 (UDP) | equal | not-sent |
| IPv6.HopLimit | - | ignore | value-sent (8 bits) |
| IPv6.SrcAddr | 0200::/8 | MSB(8) | LSB(120) |
| IPv6.DstAddr | 0200::/8 | MSB(8) | LSB(120) |
| UDP.SrcPort | 10883 | equal | not-sent |
| UDP.DstPort | 10883 | equal | not-sent |
| UDP.Length | - | ignore | compute |
| UDP.Checksum | - | ignore | compute |

**Compressed size: 32 bytes** (Rule ID, Hop Limit, and two address residues;
both ports exactly match)

**Port Compression Note:**

Rules 0 and 1 use MSB(12)/LSB(4) matching on port 5683, compressing any port
in the range 5680-5695 to a 4-bit residue. This range covers CoAP (5683),
compact CoT (5681), SenML (5682), Cayenne LPP (5685), APRS-IS (5686), and
NMEA (5687). See Section 9.1 for the complete port allocation.

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
| 1 | Legacy shared-prefix rules |
| 2 | Native Yggdrasil address rules in this specification |
| 3+ | Future versions |

Version 1 wire vectors MUST NOT be interpreted using the version 2 tables.

**DIO Rule Version Option (provisional Type 0xF0):**

DODAG roots advertise their rule set version in DIO messages:

```
+--------+--------+--------+
| 0xF0   | Length | Version|
+--------+--------+--------+
   1B       1B       1B
```

Nodes MUST join a DODAG only when their rule set version matches the advertised
version. An absent or mismatched version is firmware incompatibility.

**Fallback Rule (Rule ID 255): No Compression**

Rule 255 is reserved for packets that do not match another rule within a
matching rule-set version. All implementations MUST support it, but it does
not permit joining a DODAG with an absent or mismatched version:

```
Rule 255 packet:
+----------+-----------------+
| RuleID   | Full IPv6 packet|
| (1 byte) | (40+ bytes)     |
+----------+-----------------+
```

**When to use Rule 255:**
- A sender has a packet that matches no compression rule
- Debugging or diagnostics within a matching rule-set version

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
2. Cannot exchange SCHC packets, including Rule 255, in that DODAG
3. Should be upgraded to matching firmware

**Backward Compatibility:**

When updating firmware:
1. New rules SHOULD be added with new Rule IDs (don't reuse)
2. Old rules SHOULD remain supported for one version cycle
3. Version number MUST increment on any rule change

---

[← Previous: Coordinated Capacity Profile](02a-coordinated-capacity.md) | [Index](README.md) | [Next: Network Layer →](04-network.md)
