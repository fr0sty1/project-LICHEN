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
A. Complete Rule Set
B. Compression Examples

(Note: Full rule details, versioning (Rule Set Version in DIO), and constants are defined in spec/03-adaptation.md:5.7, appendix-schc.md, rust/lichen-schc/src/rules.rs, and constants.toml to avoid duplication.)

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

**Rule Definition:** (matches `ICMPV6_ECHO_RULE` in `rust/lichen-schc/src/rules.rs:462`; see appendix-schc.md)

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.Version | 6 | equal | not-sent |
| IPv6.TrafficClass | 0 | equal | not-sent |
| IPv6.FlowLabel | 0 | equal | not-sent |
| IPv6.PayloadLength | - | ignore | compute |
| IPv6.NextHeader | 58 | equal | not-sent |
| IPv6.HopLimit | - | ignore | value-sent |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent |
| IPv6.SrcIID | - | msb(64) | lsb(64) |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent |
| IPv6.DstIID | - | msb(64) | lsb(64) |
| ICMPv6.Type | - | ignore | value-sent |
| ICMPv6.Code | 0 | equal | not-sent |
| ICMPv6.Checksum | - | ignore | compute |

**Compressed size:** ~20 bytes residue + data tail (optimized per rules.rs:237 and codec.rs:331; aligns with appendix-schc.md:14)

### 4.5. Rule 3: RPL DIO (link-local)

For DODAG formation, maintenance, and prefix distribution (including PIO). Matches `RPL_DIO_RULE` in `rust/lichen-schc/src/rules.rs:480` and `constants.toml:32` (ICMPv6 type=155, code=1). See appendix-schc.md §A.4 for RPL options (TLV) compression details and FieldDescriptor examples (e.g. Pad1 per RFC 8724 §10).

**Compressed size:** 8 bytes residue + options tail

### 4.6. Rule 4: RPL DAO (routable multi-hop)

Uses ULA source (fd00::/8) for end-to-end preservation across relays (RPL Non-Storing mode). Link-local forbidden for forwarded DAO. Matches `RPL_DAO_RULE`. See appendix-schc.md §A.4 for options handling.

**Compressed size:** 6 bytes residue + options tail

### 4.7. Rule 7: MQTT-SN

IPv6 + UDP to port 10883 (exact). Matches `RULE_MQTT_SN`. See appendix-schc.md and rules.rs.

**Compressed size:** ~6 bytes

### 4.8. Rules 5-6: OSCORE-protected CoAP

Rule 5 (link-local) and Rule 6 (global) reuse base fields from Rules 0/1 plus OSCORE option. Encrypted payload as tail. Matches `LINK_LOCAL_OSCORE_RULE` / `GLOBAL_OSCORE_RULE`.

**Compressed size:** ~6-14 bytes residue + OSCORE tail (per appendix-schc.md)

### 4.9. Rule 255: No Compression (Fallback)

When no rule matches, version mismatch, or for interoperability. All implementations MUST support Rule 255 (see spec/03-adaptation.md:5.7 and appendix-schc.md).

### 4.10. CoAP Compression Details

See Appendix A and RFC 8824. CoAP compression (Version=1 not-sent, Type/MID/Token value-sent) is used in Rules 0/1/5/6/7. OPTIONAL for non-CoAP traffic.

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

Rule 255 is REQUIRED for unknown packets, version mismatches, or as fallback. It ensures interoperability during rule set transitions. CoAP header compression (RFC 8824) is OPTIONAL.

RPL options compression uses MATCH_MAPPING on Type field (see rust/lichen-schc/src/rules.rs, appendix-schc.md, test/vectors/schc_compression.json). Full rule set and mapping table in appendix-schc.md and test vectors (canonical oracle for all implementations).

**Parameters (current constants):** See constants.toml, lichen-schc, and test/vectors/schc*.json for normative values (m=1, n=6, RCS=CRC-32, timeouts, etc.). All impls MUST match vectors exactly. (Merge conflicts from worker5 resolved; duplicates removed; test vector xrefs added. CC-BY-4.0)

- **W:** Window bit (alternates 0/1)
- **FCN:** Fragment Counter (63 down to 0, then All-1)
### 5.4. ACK Format and Operation

ACK: RuleID(8) + control(8) + n(8) + bitmap (MSB-first, 1=missing). Sender uses FCN countdown per window, sends All-1 with RCS (CRC-32). Receiver uses bitmap for NACKs, verifies RCS on reassembly. Parameters (m=1, n=6, timeouts 10s/60s, etc.) per constants.toml and lichen-schc. Max practical ~12KB; chunk larger packets at application layer. 

## 6. Rule Versioning

Rule Set Version (8-bit) advertised in DIO per spec/03-adaptation.md §5.7 (authoritative). Version 1 initial release. DODAG roots advertise in DIOs. Full details, rule tables (0-7, 255), mapping, and bit-exact test vectors in appendix-schc.md, rust/lichen-schc/src/rules.rs, test/vectors/schc_compression.json and schc_fragment.json. All implementations (Rust, C, Python) MUST produce identical output to these independent oracles. (Merge conflicts and notes from worker5 resolved; test vector xrefs and interop requirements consolidated. CC-BY-4.0)

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

This document has no IANA actions.

This SCHC profile for LoRa mesh uses pre-provisioned rules with 8-bit Rule IDs (no dynamic Context ID negotiation per RFC 8724). Future extensions that register SCHC Context IDs or standardized Rule IDs for LoRa MUST coordinate with the IETF LPWAN WG to prevent namespace fragmentation and ensure interoperability with other LPWAN SCHC profiles.

Future versions of this document may request:
- A dedicated SCHC Context ID range for LoRa (if negotiated rules are added)
- An IANA registry for standardized LoRa SCHC rules
- A CoAP Option or RPL Option Type for rule version advertisement

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

## Appendix A. SCHC Rule Set

Complete SCHC rules, Field Descriptors, constants, test vectors, and implementation details are maintained in `spec/appendix-schc.md` (canonical reference), `constants.toml`, `rust/lichen-schc/src/rules.rs`, `lichen/subsys/lichen/schc/`, and `test/vectors/schc_compression.json` / `schc_fragment.json`. Rule 255 REQUIRED for fallback. All implementations MUST match these bit-exact oracles for interop. Rule versioning via DIO per spec/03-adaptation.md §5.7. This document avoids duplicating the full table per I-D best practices. CoAP/OSCORE rules follow RFC 8824/8613.

## Appendix B. Compression Examples

See `test/vectors/schc*.json`, `test/vectors/README.md`, `test/vectors/generate.py` for canonical validation. **All Rust, C, and Python implementations MUST produce identical output.** (Merge conflicts from worker5 and worker8 resolved; inline table and TODOs removed; test vector xrefs and interop requirements consolidated. CC-BY-4.0)

## Authors' Address

LICHEN Project
https://github.com/MarkAtwood/project-LICHEN
