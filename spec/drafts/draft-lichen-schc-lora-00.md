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
- **MO:** Matching Operator: `equal` (exact match), `ignore` (always match), `MSB(k)` (match most-significant k bits), `match-mapping` (value must be in the `mapping` list per FieldDescriptor; see `python/src/lichen/schc/rules.py:32`, equivalent in rules.rs:15). Example: `FieldDescriptor("M", 8, MO.MATCH_MAPPING, CDA.MAPPING_SENT, mapping=(0x10, 0x20))` (cross-ref: appendix-schc.md:A.1, test/vectors/schc_compression.json for PIO vectors).
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
- Identified by Rule Set Version (see 03-adaptation.md §5.7)
- Synchronized via DIO advertisement

Dynamic rule negotiation is NOT supported in this profile.

## 4. Compression Rules

See spec/03-adaptation.md §5.5, spec/appendix-schc.md, and test/vectors/ for canonical rule set (version 2).

**Rule ID Format (8 bits):**
- 0-127: Compression rules (0=CoAP link-local, 1=global, 2=ICMPv6, 3=RPL DIO, 4=DAO, 5/6=OSCORE, 7=MQTT-SN)
- 255: No-compression fallback (MUST implement)

| Range | Usage |
|-------|-------|
| 0-4 | Compression rules |
| 5-254 | Reserved for future use |
| 255 | No compression (uncompressed fallback) |

### 4.2. Rule 0: Link-local IPv6 + UDP + CoAP

See appendix-schc.md:A.1 (Rule Set) and A.2 (CoAP Compression) for authoritative tables. Matches LINK_LOCAL_COAP_RULE in rust/lichen-schc/src/rules.rs:62 and python/src/lichen/schc/rules.py:244. Compressed size ~4-6 bytes (Rule ID + hop limit + 16B IIDs + CoAP residue). OSCORE rules 5/6 (RFC 8613) use analogous structure with OSCORE option (#9) in residue.

### 4.3. Remaining Rules and CoAP/OSCORE Compression

All rules (including global IPv6 rule 1, ICMPv6 rule 2, RPL rules 3/4, uncompressed rule 255, MQTT-SN, and OSCORE rules 5/6) are defined in appendix-schc.md:A.1-A.3 and implemented in rust/lichen-schc/src/rules.rs and python/src/lichen/schc/rules.py (RPL_DIO_RULE at rules.py:272). See also spec/03-adaptation.md and test/vectors/. No duplication; appendix is single source of truth.

### 4.4. RPL Option Compression Proposal (Aligned)

**Compressed size:** 4-6 bytes

**Mapping table (common RPL options per RFC6550):**
- 0x01: Pad1
- 0x02: PadN
- 0x03: PIO
- 0x04: Route Information
- 0x05: DODAG Configuration
- 0x07: RPL Target

### 4.3. Rule 1: Global IPv6 + UDP + CoAP

For traffic to/from internet via border router.

**Applicability:**
- IPv6 source is mesh (ULA or GUA)
- IPv6 destination is global (2000::/3) or vice versa

**Rule Definition:**

| Field | TV | MO | CDA | Sent |
|-------|----|----|-----|------|
| IPv6.Version | 6 | equal | not-sent | 0 |
| IPv6.TrafficClass | 0 | ignore | value-sent | 8 bits |
| IPv6.FlowLabel | 0 | ignore | value-sent | 20 bits |
| IPv6.PayloadLength | - | ignore | compute | 0 |
| IPv6.NextHeader | 17 | equal | not-sent | 0 |
| IPv6.HopLimit | - | ignore | value-sent | 8 bits |
| IPv6.SrcAddr | - | ignore | value-sent | 128 bits |
| IPv6.DstAddr | - | ignore | value-sent | 128 bits |
| UDP.SrcPort | - | ignore | value-sent | 16 bits |
| UDP.DstPort | - | ignore | value-sent | 16 bits |
| UDP.Length | - | ignore | compute | 0 |
| UDP.Checksum | - | ignore | compute | 0 |

**Compressed size:** 41 bytes

### 4.4. Rule 2: ICMPv6 Echo

For ICMPv6 echo request and reply.

**Applicability:**
- Next header is ICMPv6 (58)
- ICMPv6 type is 128 or 129

**Rule Definition:**

| Field | TV | MO | CDA | Sent |
|-------|----|----|-----|------|
| IPv6.Version | 6 | equal | not-sent | 0 |
| IPv6.TrafficClass | 0 | equal | not-sent | 0 |
| IPv6.FlowLabel | 0 | equal | not-sent | 0 |
| IPv6.PayloadLength | - | ignore | compute | 0 |
| IPv6.NextHeader | 58 | equal | not-sent | 0 |
| IPv6.HopLimit | 64 | ignore | not-sent | 0 |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.SrcIID | - | ignore | deviid | 0 |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.DstIID | - | ignore | deviid | 0 |
| ICMPv6.Type | - | ignore | value-sent | 8 bits |
| ICMPv6.Code | - | ignore | value-sent | 8 bits |
| ICMPv6.Checksum | - | ignore | compute | 0 |

**Compressed size:** 3 bytes

### 4.5. Rule 3: RPL DIO

For RPL DODAG Information Object (code 1).

**Applicability:**
- Next header is ICMPv6 (58)
- ICMPv6 type is RPL (155)
- ICMPv6 code is 1

**Rule Definition:**

| Field | TV | MO | CDA | Sent |
|-------|----|----|-----|------|
| IPv6.Version | 6 | equal | not-sent | 0 |
| IPv6.TrafficClass | 0 | equal | not-sent | 0 |
| IPv6.FlowLabel | 0 | equal | not-sent | 0 |
| IPv6.PayloadLength | - | ignore | compute | 0 |
| IPv6.NextHeader | 58 | equal | not-sent | 0 |
| IPv6.HopLimit | 255 | equal | not-sent | 0 |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.SrcIID | - | ignore | deviid | 0 |
| IPv6.DstAddr | ff02::1a | equal | not-sent | 0 |
| ICMPv6.Type | 155 | equal | not-sent | 0 |
| ICMPv6.Code | 1 | equal | not-sent | 0 |
| ICMPv6.Checksum | - | ignore | compute | 0 |

**Compressed size:** 8 bytes

### 4.6. Rule 4: RPL DAO

For RPL Destination Advertisement Object (code 2).

**Applicability:**
- Next header is ICMPv6 (58)
- ICMPv6 type is RPL (155)
- ICMPv6 code is 2

**Rule Definition:**

| Field | TV | MO | CDA | Sent |
|-------|----|----|-----|------|
| IPv6.Version | 6 | equal | not-sent | 0 |
| IPv6.TrafficClass | 0 | equal | not-sent | 0 |
| IPv6.FlowLabel | 0 | equal | not-sent | 0 |
| IPv6.PayloadLength | - | ignore | compute | 0 |
| IPv6.NextHeader | 58 | equal | not-sent | 0 |
| IPv6.HopLimit | 255 | equal | not-sent | 0 |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.SrcIID | - | ignore | deviid | 0 |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.DstIID | - | ignore | deviid | 0 |
| ICMPv6.Type | 155 | equal | not-sent | 0 |
| ICMPv6.Code | 2 | equal | not-sent | 0 |
| ICMPv6.Checksum | - | ignore | compute | 0 |

**Compressed size:** 6 bytes

### 4.7. Rule 5: Link-local IPv6 + UDP + MQTT-SN

For MQTT-SN traffic (port 10883) per adaptation rules.

**Applicability:**
- IPv6 source and destination are link-local (fe80::/10)
- Next header is UDP
- UDP ports are 10883

**Rule Definition:**

| Field | TV | MO | CDA | Sent |
|-------|----|----|-----|------|
| IPv6.Version | 6 | equal | not-sent | 0 |
| IPv6.TrafficClass | 0 | equal | not-sent | 0 |
| IPv6.FlowLabel | 0 | equal | not-sent | 0 |
| IPv6.PayloadLength | - | ignore | compute | 0 |
| IPv6.NextHeader | 17 | equal | not-sent | 0 |
| IPv6.HopLimit | 64 | ignore | not-sent | 0 |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.SrcIID | - | ignore | deviid | 0 |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.DstIID | - | ignore | deviid | 0 |
| UDP.SrcPort | 10883 | equal | not-sent | 0 |
| UDP.DstPort | 10883 | equal | not-sent | 0 |
| UDP.Length | - | ignore | compute | 0 |
| UDP.Checksum | - | ignore | compute | 0 |

**Compressed size:** 1 byte (Rule ID only)

### 4.8. CoAP Compression

CoAP header compression MAY be applied after IPv6/UDP compression using
SCHC for CoAP (RFC 8824). This profile does not mandate CoAP compression
but provides guidance:

| CoAP Field | TV | MO | CDA |
|------------|----|----|-----|
| Version | 1 | equal | not-sent |
| Type | - | ignore | value-sent |
| TKL | - | ignore | value-sent |
| Code | - | ignore | value-sent |
| MID | - | ignore | value-sent |
| Token | - | ignore | value-sent |
| Options | - | ignore | value-sent |

CoAP compression is OPTIONAL and implementation-dependent.

## 5. Fragmentation Profile

### 5.1. Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Mode | ACK-on-Error | Minimize ACK overhead |
| M (window bits) | 1 | W field size |
| N (FCN bits) | 6 | 63 possible FCN values (All-1 = 0b111111) |
| T (DTAG bits) | 0 | Single datagram in flight per context |
| WINDOW_SIZE | 32 | Practical tiles per window (configurable) |
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

This document requests no IANA allocations.

Note: SCHC Context ID registry entries (if any future versions request them) MUST be coordinated with the IETF LPWAN WG to ensure no conflicts with other LPWAN SCHC profiles (RFC 9011 and successors).

Future versions may request:
- DIO Option Type for Rule Version advertisement
- Rule ID registry for standardized rules

## 9. References

### 9.1. Normative References

- [RFC 2119] Key words for use in RFCs
- [RFC 8724] SCHC: Generic Framework for Static Context Header
  Compression and Fragmentation
- [RFC 8824] SCHC for CoAP
- [RFC 8613] OSCORE: Object Security for Constrained RESTful Environments

### 9.2. Informative References

- [RFC 6550] RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks
- [RFC 7252] The Constrained Application Protocol (CoAP)
- [LICHEN] LICHEN Protocol Specification


## Appendix A. Complete Rule Set

**Rule Set Version: 2** (advertised via RPL DIO Option per spec/03-adaptation.md:5.7 and draft-lichen-rpl-lora-00.md).

Rule 0: Link-local IPv6 + UDP + CoAP (4-6 bytes compressed)
Rule 1: Global IPv6 + UDP + CoAP (41 bytes compressed)
Rule 2: ICMPv6 Echo (3 bytes compressed)
Rule 3: RPL DIO (8 bytes compressed)
Rule 4: RPL DAO (6 bytes compressed)
Rule 5: Link-local IPv6 + UDP + MQTT-SN (1 byte compressed)
Rule 255: No compression (fallback)
```

## Appendix B. Compression Examples

Worked examples of packet compression/decompression appear in `test/vectors/schc_compression.json` (and related schc*.json vectors).

## Authors' Address

LICHEN Project
https://github.com/MarkAtwood/project-LICHEN
