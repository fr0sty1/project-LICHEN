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
- Identified by Rule Set Version (see 03-adaptation.md §5.7)
- Synchronized via DIO advertisement

Dynamic rule negotiation is NOT supported in this profile.

## 4. Compression Rules

See spec/03-adaptation.md §5.5, spec/appendix-schc.md, and test/vectors/ for canonical rule set (version 2).

**Rule ID Format (8 bits):**
- 0-127: Compression rules (0=CoAP link-local, 1=global, 2=ICMPv6, 3=RPL DIO, 4=DAO, 5/6=OSCORE, 7=MQTT-SN)
- 255: No-compression fallback (MUST implement)

**Key Rules (per appendix-schc.md and rules.rs):**

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

The authoritative rule set, TV/MO/CDA tables, sizes, and test vectors are in `spec/appendix-schc.md` (which matches `rust/lichen-schc/src/rules.rs:LINK_LOCAL_COAP_RULE` etc and Python `rules.py`). The I-D reproduces key summary here for readability; changes must sync both.

### A.1. Rule Summary

| Rule ID | Use Case | SCHC Header (bytes) | Test Vector (bytes) | Notes |
|---------|----------|---------------------|---------------------|-------|
| 0 | Link-local IPv6+UDP+CoAP | 26 | 33 | fe80::/10 + compressed ports; residue ~25B + RuleID |
| 1 | Global/ULA IPv6+UDP+CoAP | 42 | 49 | Full addresses |
| 2 | ICMPv6 Echo Request/Reply | 23 | 27 | + ICMP fields |
| 3 | RPL DIO (link-local) | 40 | 40 | ICMP Code=1 with MO=equal; base RPL + options in residue |
| 4 | RPL DAO (routable ULA src) | 53 | 53 | ICMP Code=2 with MO=equal; preserves src; base RPL + options |
| 5 | OSCORE (link-local) | 26 | tbd | See A.3 |
| 6 | OSCORE (global) | 42 | tbd | See A.3 |
| 7 | MQTT-SN | tbd | tbd | Port 1883/10883 exact |
| 255 | No compression | 1 | full | Fallback rule |

**RPL Rules 3/4 note:** Per RFC 6550 §6, DIO uses Code=1, DAO uses Code=2. Rules use MO=equal + CDA=not-sent on both ICMPv6.Type (155) and Code to select distinct rule (see rules.rs:128-129,129 and Python _icmpv6_rpl_fields). This fixes previous value-sent overlap. RPL options compressed as residue for simplicity (adds ~20-40B). Proposal for per-option rules using match-mapping (see new §A.5 below): for common Prefix Info (type=3) use MO=match-mapping on option type with mapping=[0=PAD1,1=PADN,3=PIO,...], CDA=mapping-sent (4-bit index); for PIO follow with equal/not-sent for standard DODAG prefix (len=4,prefix_len=64,LA=0xC0,lifetimes=0xffffffff) + MSB(64) on prefix. Reduces PIO from ~32B to ~2-5B. Update rules.rs and codec to support.

### A.2. CoAP Compression (all rules)

| Field | Target Value | Matching Operator | Compression Action |
|-------|--------------|-------------------|--------------------|
| Version | 1 | equal | not-sent |
| Type | - | ignore | value-sent (2 bits) |
| TKL | - | ignore | value-sent (4 bits) |
| Code | - | ignore | value-sent (8 bits) |
| Message ID | - | ignore | value-sent (16 bits) |
| Token | - | ignore | value-sent (variable) |

### A.3. OSCORE Compression (Rules 5 and 6)

Rules 5/6 follow the same IPv6/UDP/CoAP structure as 0/1 but use distinct Rule IDs to signal OSCORE protection (RFC 8613). The OSCORE option (number 9) and encrypted payload are carried in the SCHC residue after the compressed CoAP header (no dedicated FieldDescriptor yet; treated as tail per current codec). PIV and other fields are inside the protected payload. Full details and vectors in appendix-schc.md:A.3. Future work: explicit OSCORE option compression (MSB on ID, etc.).

### A.4. RPL Compression (Rules 3 and 4)

Rules distinguish via MO=equal on ICMPv6.Code (target=1 for DIO Rule 3, target=2 for DAO Rule 4) + Type=155 not-sent, next_header=58, with link-local or ULA src as appropriate. Checksum is computed. Base RPL fields use mix of equal/not-sent and value-sent. RPL options compressed via residue (future: dedicated rules per option type as in appendix-rpl.md §9 and RFC 6550 §6.7). See rules.rs:117 and Python rules.py:272 for exact FieldDescriptors; test/vectors/schc_compression.json for vectors.

**Example for Rule 3 (DIO):**
| Field | Target Value | Matching Operator | Compression Action | Notes |
|-------|--------------|-------------------|--------------------|-------|
| IPv6.next_header | 58 | equal | not-sent | ICMPv6 |
| IPv6.src | fe80::/10 | msb(64) | lsb | Link-local |
| IPv6.dst | fe80::/10 | msb(64) | lsb | All-RPL-nodes |
| ICMPv6.type | 155 | equal | not-sent | RPL |
| ICMPv6.code | 1 | equal | not-sent | DIO |
| ICMPv6.checksum | - | ignore | compute | |
| RPL.instance | - | ignore | value-sent | |
| RPL.version/rank/gmop/dtsn | - | ignore | value-sent | Variable |
| RPL.flags/reserved | 0 | equal | not-sent | |
| RPL.dodagid | - | ignore | value-sent | 128b |

(Similar structure for Rule 4 with Code=2, ULA src, kd_flags/seq.)

### A.5. RPL Option Compression using match-mapping (new)

Common RPL options (RFC 6550 §6.7) add significant residue bytes. Use per-option FieldDescriptors with MO=MATCH_MAPPING on RPL.Option.Type and CDA=MAPPING_SENT (small index, e.g. 3 bits for 8 common types).

**Specific rule for Prefix Info Option (type 3):**

| Field | Target Value | MO | CDA | Notes |
|-------|--------------|----|-----|-------|
| RPL.Option.Type | [0,1,3,5,7,...] | match-mapping | mapping-sent | 3-bit index; 3=PIO |
| RPL.Option.Len | 4 | equal | not-sent | For /64 PIO |
| PIO.PrefixLen | 64 | equal | not-sent | Standard |
| PIO.L A flags | 0xC0 | equal | not-sent | L=1 A=1 (on-link, autonomous) |
| PIO.Valid Lifetime | 0xFFFFFFFF | equal | not-sent | Infinite |
| PIO.Preferred Lifetime | 0xFFFFFFFF | equal | not-sent | Infinite |
| PIO.Reserved | 0 | equal | not-sent | |
| PIO.Prefix | DODAG prefix | msb(64) | lsb | Matches DODAGID; saves 64b |

This reduces typical PIO (~32B) to ~1 byte (index) + 8B IID if needed. Extend RPL_DIO_RULE with these fields (after dodagid). Update Rust rules.rs FieldDescriptor to support mapping: tuple like Python. Add to test vectors. See codec.rs for MATCH_MAPPING impl (partial in context.rs).

See test/vectors/schc_compression.json and appendix-schc.md for authoritative sizes/vectors.

See test/vectors/schc_compression.json for cross-impl validation (Rust/Python must match bit-exactly).

## Appendix B. Compression Examples

Canonical examples and vectors are in `test/vectors/schc_compression.json`. Rust tests in `lichen-schc/tests/shared_vectors.rs`; Python in `python/tests/coap/test_schc_channel.py`. All implementations MUST match these vectors.

## Authors' Address

LICHEN Project
https://github.com/MarkAtwood/project-LICHEN
