<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# SCHC Profile for LoRa Mesh Networks

```
Internet-Draft                                              LICHEN Project
draft-lichen-schc-lora-00                                       July 2026
Intended status: Experimental
Expires: January 2027
```

## Status of This Document

**PRELIMINARY DRAFT — WORK IN PROGRESS**

This document is an early draft developed alongside a reference implementation.
It will be updated as implementation experience is gained. Coding agents with
human oversight may modify this specification as needed.

This Internet-Draft is submitted in full conformance with the provisions of
BCP 78 and BCP 79.

## Abstract

This document defines a Static Context Header Compression (SCHC) profile for
LoRa mesh networks. It specifies compression rules for IPv6, UDP, and CoAP
headers optimized for the LICHEN protocol, along with fragmentation parameters
suitable for LoRa's characteristics. The profile enables efficient transmission
of IPv6 packets over LoRa links with typical payloads of 50-200 bytes.

## Table of Contents

1. Introduction
2. Terminology
3. SCHC Architecture for LoRa Mesh
4. Compression Rules
5. Fragmentation Profile
6. Implementation Considerations
7. Security Considerations
8. IANA Considerations
9. References

(Note: Rule versioning is defined in spec/03-adaptation.md:5.7 to avoid duplication.)

## 1. Introduction

LoRa (Long Range) is a spread-spectrum modulation technique enabling
long-range, low-power wireless communication. LoRa networks typically
operate at low data rates (300 bps to 27 kbps) with small MTUs (50-250
bytes depending on spreading factor).

SCHC (Static Context Header Compression), specified in RFC 8724, provides
header compression and fragmentation for LPWAN technologies. This document
defines a SCHC profile tailored for LoRa mesh networks running IPv6 with
CoAP application traffic.

### 1.1. Design Goals

- **Aggressive compression:** Reduce IPv6+UDP+CoAP headers from 60+ bytes
  to 6-12 bytes for common cases
- **Efficient fragmentation:** Use ACK-on-Error mode to minimize overhead
- **Mesh-friendly:** Support multi-hop routing without per-hop decompression
- **Versioned rules:** Enable firmware updates without breaking interoperability

### 1.2. Relationship to Other Specifications

This profile is designed for use with:
- LICHEN link layer (draft-lichen-link)
- RPL routing (RFC 6550, with LoRa tuning per draft-lichen-rpl-lora)
- CoAP (RFC 7252) and OSCORE (RFC 8613)

This profile does NOT use IEEE 802.15.4 or 6LoWPAN IPHC (RFC 6282). SCHC
replaces 6LoWPAN for both compression and fragmentation.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

- **Rule:** A SCHC compression/decompression rule
- **Rule ID:** Identifier for a rule (variable length in SCHC, fixed 8-bit here)
- **TV:** Target Value in a rule entry
- **MO:** Matching Operator (equal, ignore, MSB, etc.)
- **CDA:** Compression/Decompression Action (not-sent, value-sent, etc.)
- **FCN:** Fragment Counter Number
- **DTAG:** Datagram Tag (identifies fragments of same packet)

## 3. SCHC Architecture for LoRa Mesh

### 3.1. Protocol Stack

```
+----------------------------------+
|  Application (CoAP + OSCORE)     |
+----------------------------------+
|  Transport (UDP)                 |
+----------------------------------+
|  Network (IPv6)                  |
+----------------------------------+
|  SCHC Compression/Fragmentation  |  <-- This profile
+----------------------------------+
|  LICHEN Link Layer               |
+----------------------------------+
|  LoRa PHY                        |
+----------------------------------+
```

### 3.2. Compression Point

SCHC compression/decompression occurs at:
- **Origin:** Compress before transmission
- **Destination:** Decompress after reception

Intermediate routers (relays) forward compressed packets without
decompression. This requires end-to-end rule synchronization.

### 3.3. Context Provisioning

SCHC contexts (rule sets) are provisioned statically:
- Built into firmware at compile time
- Identified by Rule Set Version (see spec/03-adaptation.md:5.7)
- Synchronized via DIO advertisement

Dynamic rule negotiation is NOT supported in this profile.

## 4. Compression Rules

### 4.1. Rule ID Format

Rule IDs are 8 bits (1 byte):

| Range | Usage |
|-------|-------|
| 0-127 | Compression rules |
| 128-254 | Reserved for future use |
| 255 | No compression (uncompressed fallback) |

### 4.2. Rule 0: Link-Local IPv6 + UDP + CoAP

Most common case for intra-mesh traffic.

**Rule Definition:** (matches spec/03-adaptation.md:5.5 and appendix-schc.md)

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.Version | 6 | equal | not-sent |
| IPv6.TrafficClass | 0 | equal | not-sent |
| IPv6.FlowLabel | 0 | equal | not-sent |
| IPv6.PayloadLength | - | ignore | compute |
| IPv6.NextHeader | 17 | equal | not-sent |
| IPv6.HopLimit | 64 | ignore | not-sent |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent |
| IPv6.SrcIID | - | equal | not-sent (L2 derived) |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent |
| IPv6.DstIID | - | equal | not-sent (L2 derived) |
| UDP.SrcPort | 5683 | MSB(12) | LSB(4) |
| UDP.DstPort | 5683 | MSB(12) | LSB(4) |
| UDP.Length | - | ignore | compute |
| UDP.Checksum | - | ignore | compute |

**Compressed size:** 4-6 bytes (Rule ID + 4-bit port residues)

### 4.3. Rule 1: Global IPv6 + UDP + CoAP

For traffic using ULA or GUA addresses.

**Rule Definition:** (aligned with appendix-schc.md and 03-adaptation.md:5.5)

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.Version | 6 | equal | not-sent |
| IPv6.TrafficClass | 0 | equal | not-sent |
| IPv6.FlowLabel | 0 | equal | not-sent |
| IPv6.PayloadLength | - | ignore | compute |
| IPv6.NextHeader | 17 | equal | not-sent |
| IPv6.HopLimit | 64 | ignore | not-sent |
| IPv6.SrcPrefix | mesh_prefix/64 | equal | not-sent |
| IPv6.SrcIID | - | equal | not-sent (L2 derived) |
| IPv6.DstPrefix | - | ignore | value-sent (64 bits) |
| IPv6.DstIID | - | ignore | value-sent (64 bits) |
| UDP.SrcPort | 5683 | MSB(12) | LSB(4) |
| UDP.DstPort | 5683 | MSB(12) | LSB(4) |
| UDP.Length | - | ignore | compute |
| UDP.Checksum | - | ignore | compute |

**Compressed size:** 12-14 bytes

### 4.4. Rule 2: ICMPv6 Echo

For diagnostic and reachability testing.

**Rule Definition:** (aligned to appendix-schc.md)

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.Version | 6 | equal | not-sent |
| IPv6.TrafficClass | 0 | equal | not-sent |
| IPv6.FlowLabel | 0 | equal | not-sent |
| IPv6.PayloadLength | - | ignore | compute |
| IPv6.NextHeader | 58 | equal | not-sent |
| IPv6.HopLimit | 64 | ignore | not-sent |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent |
| IPv6.SrcIID | - | equal | not-sent (L2) |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent |
| IPv6.DstIID | - | equal | not-sent (L2) |
| ICMPv6.Type | 128 or 129 | equal | not-sent |
| ICMPv6.Code | 0 | equal | not-sent |
| ICMPv6.Checksum | - | ignore | compute |

**Compressed size:** 3 bytes

### 4.5. Rule 3: RPL DIO with PIO (link-local)

For DODAG formation, maintenance, and prefix distribution via PIO (Prefix Information Option).

**Rule Definition:** (aligned with appendix-schc.md and rules.py:272 RPL_DIO_RULE)

Includes specific PIO compression using match-mapping for common types (0=Pad1, 3=PIO with LICHEN lifetimes per draft-rpl-lora).

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.Version | 6 | equal | not-sent |
| IPv6.NextHeader | 58 | equal | not-sent |
| ICMPv6.Type | 155 | equal | not-sent |
| RPL.Base | - | ignore | value-sent |
| PIO.Type | 3 | match-mapping | mapping-sent (2 bits) |
| PIO.Lifetime | specific | equal | not-sent |
| RPL.options | specific | MSB(8) | LSB(8) |

**Compressed size:** 8 bytes (base + PIO residue)

For DODAG formation and maintenance.

**Rule Definition:** (aligned with appendix-schc.md)

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.Version | 6 | equal | not-sent |
| IPv6.NextHeader | 58 | equal | not-sent |
| ICMPv6.Type | 155 | equal | not-sent |
| RPL options | specific | MSB/LSB | compressed |

**Compressed size:** 8 bytes

### 4.6. Rule 4: RPL DAO (routable multi-hop)

Uses routable ULA source (fd00::/8 from DODAG) for end-to-end source preservation across relays (per RPL and security specs). Link-local forbidden for forwarded DAO.

**Compressed size:** 6 bytes

### 4.7. Rules 5-6: OSCORE-protected CoAP

Rule 5: Link-local IPv6 + UDP + OSCORE (matches LINK_LOCAL_OSCORE_RULE)

Rule 6: Global IPv6 + UDP + OSCORE (matches GLOBAL_OSCORE_RULE)

Uses base fields from Rules 0/1 with additional OSCORE option compression. Encrypted payload travels as tail.

**Compressed size:** ~20+ bytes residue + tail (Rule 5); ~40+ bytes residue + tail (Rule 6)

### 4.8. Rule 255: No Compression (Fallback)

When no rule matches, for version mismatch, or interoperability fallback. All implementations MUST support Rule 255 (see spec/03-adaptation.md:5.7 for details).

### 4.9. CoAP Compression

See Appendix A for the CoAP compression table (Version, Type, TKL, Code, MID, Token using standard CDA from RFC 8824). CoAP compression is OPTIONAL.

## 5. Fragmentation Profile

### 5.1. Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Mode | ACK-on-Error | Minimize ACK overhead |
| FCN size | 6 bits | 63 fragments per window |
| DTAG size | 0 bits | Single packet in flight |
| Window size | 1 bit | 2 windows max |
| Tile size | L2 MTU - header | Maximize per-fragment payload |
| Retransmission timer | 10 seconds | LoRa latency tolerance |
| Max retries | 3 | Balance reliability/efficiency |
| Inactivity timer | 60 seconds | Clean up stale state |

### 5.2. ACK-on-Error Mode

In ACK-on-Error mode:
1. Sender transmits all fragments without waiting for ACKs
2. Receiver tracks received fragments via bitmap
3. After final fragment, receiver sends ACK only if fragments missing
4. Sender retransmits missing fragments
5. Repeat until complete or max retries exceeded

This minimizes overhead for the common case (no loss).

### 5.3. Fragment Format

**Regular Fragment:**
```
+--------+---+--------+------------------+
| RuleID | W |  FCN   |     Tile         |
+--------+---+--------+------------------+
   8 bit  1b   6 bit      variable
```

**All-1 Fragment (final):**
```
+--------+---+--------+--------+---------+
| RuleID | W | 111111 |  RCS   |  Tile   |
+--------+---+--------+--------+---------+
   8 bit  1b   6 bit   32 bit   variable
```

- **W:** Window bit (alternates 0/1)
- **FCN:** Fragment Counter (63 down to 0, then All-1)
- **RCS:** Reassembly Check Sequence (CRC-32)

### 5.4. ACK Format

```
+--------+---+--------+
| RuleID | W | Bitmap |
+--------+---+--------+
   8 bit  1b  variable
```

Bitmap indicates missing fragments (1 = missing, 0 = received).

### 5.5. Maximum Packet Size

With 63 fragments per window × 2 windows × ~200 bytes per fragment:
- Maximum packet size: ~25 KB
- Practical limit: ~12 KB (single window recommended)

Packets exceeding this MUST be chunked at application layer.

## 6. Implementation Considerations

### 6.1. Memory Requirements

| Component | RAM | Flash |
|-----------|-----|-------|
| Rule storage | ~500 bytes | ~2 KB |
| Fragmentation state | ~200 bytes per packet | - |
| Reassembly buffer | L2 MTU × 63 | - |

Total: ~1-2 KB RAM, ~2-3 KB Flash

### 6.2. Processing Requirements

- Compression: O(n) where n = number of rules (typically <10)
- Decompression: O(1) after rule lookup
- Fragmentation: O(1) per fragment
- Reassembly: O(fragments) for bitmap management

### 6.3. Existing Implementations

- **libschc:** C library, MIT license (recommended)
- **openschc:** Python reference, BSD license
- **Custom:** May be needed for constrained targets

## 7. Security Considerations

### 7.1. Compression Oracle Attacks

SCHC compression does not introduce compression oracle vulnerabilities
because rule selection is based on header fields, not encrypted content.

### 7.2. Fragmentation Attacks

**Resource exhaustion:** Attackers may send partial fragment sequences
to exhaust reassembly buffers. Mitigations:
- Inactivity timer (60s) to garbage collect stale state
- Limit concurrent reassembly sessions (e.g., 4 per neighbor)
- Authenticate fragments at link layer

**Fragment injection:** Attackers may inject fragments into ongoing
reassembly. Mitigations:
- RCS (CRC-32) validates complete packet
- Link-layer signatures authenticate sender

### 7.3. Rule Mismatch

Rule mismatch between sender and receiver causes packet loss or
corruption. Version advertisement in DIO prevents this for nodes
in the same DODAG.

## 8. IANA Considerations

This document requests no IANA allocations. SCHC registry coordination with LPWAN WG required.

Any future SCHC Context ID registry MUST coordinate with the IETF LPWAN WG to prevent namespace fragmentation.

Future versions may request:
- DIO Option Type for Rule Version advertisement
- Rule ID registry for standardized rules

## 9. References

### 9.1. Normative References

- [RFC 2119] Key words for use in RFCs
- [RFC 8724] SCHC: Generic Framework for Static Context Header
  Compression and Fragmentation
- [RFC 8824] SCHC for CoAP

### 9.2. Informative References

- [RFC 6550] RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks
- [RFC 7252] The Constrained Application Protocol (CoAP)
- [LICHEN] LICHEN Protocol Specification

## Appendix A. Complete Rule Set

| Rule ID | Use Case | Compressed Size | Notes |
|---------|----------|-----------------|-------|
| 0 | Link-local IPv6 + UDP + CoAP | 4-6 bytes | MSB(64) IIDs; ports via MSB(12)/LSB(4) for 5680-5695 range (CoAP/SenML/etc.) |
| 1 | Global IPv6 + UDP + CoAP | 12-14 bytes | ULA/GUA source, full dst where needed |
| 2 | ICMPv6 Echo | 3 bytes | |
| 3 | RPL DIO (link-local) | 8 bytes | |
| 4 | RPL DAO (routable ULA) | 6 bytes | Multi-hop source preservation |
| 5 | Link-local IPv6 + UDP + OSCORE | ~20+ bytes + OSCORE tail | Full ports, hop_limit value-sent |
| 6 | Global IPv6 + UDP + OSCORE | ~40+ bytes + OSCORE tail | |
| 255 | No compression | Full headers | Version mismatch or unknown rule fallback |

CoAP compression details (RFC 8824):

| Field | TV | MO | CDA |
|-------|----|----|-----|
| Version | 1 | equal | not-sent |
| Type | - | ignore | value-sent (2 bits) |
| TKL | - | ignore | value-sent (4 bits) |
| Code | - | ignore | value-sent (8 bits) |
| MID | - | ignore | value-sent (16 bits) |
| Token | - | ignore | value-sent (TKL bytes) |

Rule versioning and interoperability (including DIO advertisement of rule set version) are defined in spec/03-adaptation.md section 5.7. This document avoids duplication.

## Appendix B. Compression Examples

See test/vectors/schc-rules.json and test/vectors/schc-fragment.json for canonical test vectors. These are the independent oracle for interop validation between Rust, C, and Python implementations. All compression and fragmentation paths MUST match these vectors bit-exactly.

## Authors' Address

LICHEN Project
https://github.com/MarkAtwood/project-LICHEN
