<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# SCHC Profile for LoRa Mesh Networks

```
Internet-Draft                                              LICHEN Project
draft-lichen-schc-lora-00                                       May 2026
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
6. Rule Versioning
7. Implementation Considerations
8. Security Considerations
9. IANA Considerations
10. References

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
- Identified by Rule Set Version (see Section 6)
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

See appendix-schc.md:A.1 (Rule Set) and A.2 (CoAP Compression) for authoritative tables. Matches LINK_LOCAL_COAP_RULE in rust/lichen-schc/src/rules.rs:62 and python/src/lichen/schc/rules.py:244. Compressed size ~4-6 bytes (Rule ID + hop limit + 16B IIDs + CoAP residue). OSCORE rules 5/6 (RFC 8613) use analogous structure with OSCORE option (#9) in residue.

### 4.3. Remaining Rules and CoAP/OSCORE Compression

All rules (including global IPv6 rule 1, ICMPv6 rule 2, RPL rules 3/4, uncompressed rule 255, MQTT-SN, and OSCORE rules 5/6) are defined in appendix-schc.md:A.1-A.3 and implemented in rust/lichen-schc/src/rules.rs and python/src/lichen/schc/rules.py (RPL_DIO_RULE at rules.py:272). See also spec/03-adaptation.md and test/vectors/. No duplication; appendix is single source of truth.

### 4.4. RPL Option Compression Proposal (Aligned)

RPL DIO/DAO options (RFC6550 §6.7) use SCHC MATCH_MAPPING (rules.py:32 MO.MATCH_MAPPING, FieldDescriptor.mapping tuple, CDA.MAPPING_SENT, mapping_bits()=(len(mapping)-1).bit_length() at rules.py:81; RFC8724 §7.4). For PIO (type=3 per RFC6550 §6.7.1):

**Mapping table (common RPL options per RFC6550):**
- 0x01: Pad1
- 0x02: PadN
- 0x03: PIO
- 0x04: Route Information
- 0x05: DODAG Configuration
- 0x07: RPL Target

6 values → 3-bit index ( (6-1).bit_length() = 3 ). Type field: 8→3 bits reduction. Length for PIO=30 can be NOT_SENT or matched. Extends RPL_DIO_RULE without breaking base 8-byte size (options in residue only when present). Rust MatchMapping (rules.rs:15, context.rs:74) to be completed to match. Size calc verified against Python codec.

See appendix-schc.md for updated tables.

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

## 6. Rule Versioning

### 6.1. Rule Set Version

Each firmware release defines a Rule Set Version (8-bit integer):

| Version | Meaning |
|---------|---------|
| 0 | Reserved |
| 1 | Initial LICHEN release |
| 2+ | Future versions |

### 6.2. DIO Advertisement

DODAG roots advertise Rule Set Version in DIO messages:

```
DIO Rule Version Option (Type TBD):
+--------+--------+--------+
| Type   | Length | Version|
+--------+--------+--------+
   1B       1B       1B
```

### 6.3. Version Compatibility

- Nodes SHOULD only join DODAG if Rule Set Version matches
- Mismatched nodes MAY communicate via Rule 255 (no compression)
- Version changes require coordinated firmware update

### 6.4. Adding Rules

When adding new rules:
1. Assign new Rule ID (do not reuse)
2. Increment Rule Set Version
3. Maintain old rules for one version cycle
4. Document changes in release notes

## 7. Implementation Considerations

### 7.1. Memory Requirements

| Component | RAM | Flash |
|-----------|-----|-------|
| Rule storage | ~500 bytes | ~2 KB |
| Fragmentation state | ~200 bytes per packet | - |
| Reassembly buffer | L2 MTU × 63 | - |

Total: ~1-2 KB RAM, ~2-3 KB Flash

### 7.2. Processing Requirements

- Compression: O(n) where n = number of rules (typically <10)
- Decompression: O(1) after rule lookup
- Fragmentation: O(1) per fragment
- Reassembly: O(fragments) for bitmap management

### 7.3. Existing Implementations

- **libschc:** C library, MIT license (recommended)
- **openschc:** Python reference, BSD license
- **Custom:** May be needed for constrained targets

## 8. Security Considerations

### 8.1. Compression Oracle Attacks

SCHC compression does not introduce compression oracle vulnerabilities
because rule selection is based on header fields, not encrypted content.

### 8.2. Fragmentation Attacks

**Resource exhaustion:** Attackers may send partial fragment sequences
to exhaust reassembly buffers. Mitigations:
- Inactivity timer (60s) to garbage collect stale state
- Limit concurrent reassembly sessions (e.g., 4 per neighbor)
- Authenticate fragments at link layer

**Fragment injection:** Attackers may inject fragments into ongoing
reassembly. Mitigations:
- RCS (CRC-32) validates complete packet
- Link-layer signatures authenticate sender

### 8.3. Rule Mismatch

Rule mismatch between sender and receiver causes packet loss or
corruption. Version advertisement in DIO prevents this for nodes
in the same DODAG.

## 9. IANA Considerations

This document requests no IANA allocations.

Future versions may request:
- DIO Option Type for Rule Version advertisement
- Rule ID registry for standardized rules

## 10. References

### 10.1. Normative References

- [RFC 2119] Key words for use in RFCs
- [RFC 8724] SCHC: Generic Framework for Static Context Header
  Compression and Fragmentation
- [RFC 8824] SCHC for CoAP

### 10.2. Informative References

- [RFC 6550] RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks
- [RFC 7252] The Constrained Application Protocol (CoAP)
- [LICHEN] LICHEN Protocol Specification

## Appendix A. Complete Rule Set

```
Rule Set Version: 1

Rule 0: Link-local IPv6 + UDP (2 bytes compressed)
Rule 1: Mesh-local IPv6 + UDP (10 bytes compressed)
Rule 2: Global IPv6 + UDP (41 bytes compressed)
Rule 3: ICMPv6 RPL control (2 bytes compressed)
Rule 255: No compression (fallback)
```

## Appendix B. Compression Examples

**TODO:** Add worked examples showing compression of sample packets.

## Authors' Address

LICHEN Project
https://github.com/MarkAtwood/project-LICHEN
