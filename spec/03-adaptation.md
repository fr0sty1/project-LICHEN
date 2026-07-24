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

### 5.5. Rule Registry

Full canonical rules (including CoAP fields, OSCORE variants, RPL control messages, exact CDA/MO/TV, residue calculations) are defined in `spec/appendix-schc.md` and implemented in `rust/lichen-schc/src/rules.rs` and `python/src/lichen/schc/rules.py`. Rule Set Version 2.

**Summary of key rules (see appendix for TV/MO/CDA tables):**
- Rule 0: Link-local IPv6+UDP+CoAP (26B SCHC header)
- Rule 1: Global IPv6+UDP+CoAP (42B)
- Rule 2: ICMPv6 Echo
- Rule 3: RPL DIO
- Rule 4: RPL DAO (routable 02xx source per security requirements)
- Rules 5/6: OSCORE-protected CoAP variants
- Rule 7: MQTT-SN
- Rule 255: Uncompressed fallback (MUST implement)

Port compression uses MSB(12)/LSB(4) for CoAP range 5680-5695 in Rules 0/1 (covers CoAP, SenML, etc.; see port allocation in 09-packets-timing.md or apps). Hop limit is value-sent; src/dst use 64-bit prefix MSB match + LSB IID. MQTT-SN (Rule 7, port 10883 exact) and full CDA tables in appendix-schc.md:A.1-A.3.

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

**Compressed size: 19 bytes** (Rule ID + Hop Limit + endpoint IIDs + ports)

**Legacy Version 1 Rule 1: Global IPv6 + UDP**

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.SrcPrefix | 02xx-prefix/64 | equal | not-sent |
| IPv6.DstPrefix | 0 | ignore | value-sent (64 bits) |
| (other fields as Rule 0) | | | |

**Compressed size: 27 bytes** (Rule 0 fields plus full destination prefix)

**Rule 7: IPv6 + UDP + MQTT-SN (port 10883)**

MQTT-SN uses port 10883 (outside CoAP range compressed by Rules 0/1). Rule 7 supports both link-local and global addresses (via address-mode bit) and direction bit + residue for the non-10883 port. See draft-lichen-schc-lora-00.md §4 and Rust implementation for exact residue format. Updated to align with appendix A.1 (ICMP=Rule 2).

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.Version | 6 | equal | not-sent |
| IPv6.TrafficClass | 0 | equal | not-sent |
| IPv6.FlowLabel | 0 | equal | not-sent |
| IPv6.PayloadLength | - | ignore | compute |
| IPv6.NextHeader | 17 (UDP) | equal | not-sent |
| IPv6.HopLimit | - | ignore | value-sent |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent |
| IPv6.SrcIID | - | ignore | value-sent (64 bits) |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent |
| IPv6.DstIID | - | ignore | value-sent (64 bits) |
| UDP.SrcPort | 10883 | equal | not-sent |
| UDP.DstPort | 10883 | equal | not-sent |
| UDP.Length | - | ignore | compute |
| UDP.Checksum | - | ignore | compute |

**Compressed size: 18 bytes** (Rule ID + Hop Limit + endpoint IIDs)

**Port Compression Note:**

Rules 0 and 1 use MSB(12)/LSB(4) matching on port 5683, compressing any port
in the range 5680-5695 to a 4-bit residue. This range covers CoAP (5683),
compact CoT (5681), SenML (5682), Cayenne LPP (5685), APRS-IS (5686), and
NMEA (5687). See Section 9.1 for the complete port allocation.

### 5.6. Fragmentation

Packets exceeding L2 MTU are fragmented using the fixed ACK-on-Error profile
defined in Section 5 of `draft-lichen-schc-lora-00`:

The compression sublayer MUST zero-pad its compressed header through the next
octet boundary before the byte-aligned payload, so fragmentation always receives
an octet-aligned SCHC Packet.

**Fragment Header:**
```
+--------+---+--------+----------------------+---------+
| RuleID | W |  FCN   | RCS and/or tile bits | Padding |
+--------+---+--------+----------------------+---------+
   8 bit  1b   6 bit        variable           variable
```

- **Rule IDs:** 0x78 canonical endpoint A-to-B data, 0x79 B-to-A data
- **W:** absolute window 0 or 1; no wrapping within a packet
- **FCN:** regular tile indices 62 down to 0; 63 is All-1
- **WINDOW_SIZE:** 63 tiles; maximum 126 tiles across two windows
- **Tile size:** 187 bytes, except the non-empty final tile may be shorter
- **RCS:** CRC-32/ISO-HDLC, carried before the final tile in All-1
- **Packing:** MSB-first, bit-contiguous, with zero padding only at message end

The receiver sends no ACK for All-0. It MUST respond to All-1 or ACK REQ with
C=1 after successful whole-packet verification, or C=0 plus the RFC 8724
compressed received-tile bitmap. Bitmap 1 means received and 0 means missing.
The initial All-1 plus at most three retries gives MAX_ACK_REQUESTS=4.

Receivers MUST support 1281-byte SCHC Packets, allowing a 1280-byte IPv6 packet
plus the uncompressed fallback Rule ID. Larger buffers are optional up
to the 23,562-byte profile ceiling. With T=0, only one fragmented packet per
signed link and data Rule ID may be active. Fragmentation is hop-by-hop;
routers reassemble and decompress before IPv6 forwarding.

### 5.7. Rule Versioning and Interoperability

SCHC requires identical rule sets on sender and receiver. To ensure
interoperability across firmware versions:

**Rule Set Version:**

Each LICHEN release defines a rule set version (8-bit unsigned integer).
Version increments when rules are added, removed, or modified.

| Version | Description |
|---------|-------------|
| 0 | Reserved (uncompressed fallback) |
| 1 | Legacy experimental fragmentation formats; not interoperable |
| 2 | RFC 8724 fragmentation profile defined in Section 5.6 |
| 3+ | Future versions |

**DIO Rule Version Option (Type TBD):** PIO proposal for RPL options (incl. potential PIO) at python/src/lichen/schc/rules.py:262, spec/drafts/draft-lichen-schc-lora-00.md:228 (table/calc) and 03-adaptation.md:184 (cross-ref 04-network.md:52 no-PIO in no-ULA model per 06-security.md:128).

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
- Compression-rule version mismatch when the packet fits one link frame
- Debugging / diagnostics
- Communicating unfragmented packets with legacy nodes

Rule 255 does not provide fragmentation compatibility. If the Rule 255 SCHC
Packet exceeds one link frame, both peers MUST support the same fragmentation
Rule Set Version or the packet cannot be sent.

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
2. Can communicate unfragmented packets via Rule 255 (degraded performance)
3. Should be upgraded to matching firmware

**Backward Compatibility:**

When updating firmware:
1. New rules SHOULD be added with new Rule IDs (don't reuse)
2. Old rules SHOULD remain supported for one version cycle
3. Version number MUST increment on any rule change

---

[← Previous: Physical and Link Layers](02-physical-link.md) | [Index](README.md) | [Next: Network Layer →](04-network.md)
