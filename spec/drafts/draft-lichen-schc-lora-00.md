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

1.  Introduction
2.  Terminology
3.  SCHC Architecture for LoRa Mesh
4.  Compression Rules
5.  Fragmentation Profile
6.  Rule Versioning
7.  Implementation Considerations
8.  Security Considerations
9.  IANA Considerations
10. References

Appendix A.  Complete Rule Set
Appendix B.  Compression Examples

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

Rule IDs are fixed 8-bit values synchronized with `lichen-core::constants.rs` and `constants.toml`. Current set (MUST match all implementations and test vectors):

| Rule ID | Constant                  | Use Case                              |
|---------|---------------------------|---------------------------------------|
| 0       | RULE_LINK_LOCAL_COAP      | Link-local IPv6 + UDP + CoAP          |
| 1       | RULE_GLOBAL_COAP          | Global IPv6 + UDP + CoAP              |
| 2       | RULE_ICMPV6_ECHO          | ICMPv6 Echo (type: value-sent; code=0: equal/not-sent) |
| 3       | RULE_RPL_DIO              | RPL DIO over link-local ICMPv6        |
| 4       | RULE_RPL_DAO              | RPL DAO with DODAGID                  |
| 5       | RULE_LINK_LOCAL_OSCORE    | Link-local IPv6 + UDP + OSCORE CoAP   |
| 6       | RULE_GLOBAL_OSCORE        | Global IPv6 + UDP + OSCORE CoAP       |
| 7       | RULE_MQTT_SN              | IPv6 + UDP + MQTT-SN (port 10883)     |
| 255     | RULE_UNCOMPRESSED         | No compression fallback               |

Rules are tried in ascending ID order. Unknown packets fall back to Rule 255. All implementations MUST produce identical output for `test/vectors/schc_compression.json`.

### 4.2. Rule Field Descriptors

Field descriptors (TV, MO, CDA per RFC 8724 §7) are defined in `rust/lichen-schc/src/rules.rs` (with matching implementations in C and Python). See Appendix A for the current rule set summary. CoAP compression follows RFC 8824 and is applied after IPv6/UDP where used. OSCORE is compressed as opaque payload.

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
| UDP.SrcPort | 5683 | MSB(12) | LSB | 4 bits |
| UDP.DstPort | 5683 | MSB(12) | LSB | 4 bits |
| UDP.Length | - | ignore | compute | 0 |
| UDP.Checksum | - | ignore | compute | 0 |
| CoAP.Version | 1 | equal | not-sent | 0 |
| CoAP.Type | - | ignore | value-sent | 2 bits |
| CoAP.TKL | - | ignore | value-sent | 4 bits |
| CoAP.Code | - | ignore | value-sent | 8 bits |
| CoAP.MID | - | ignore | value-sent | 16 bits |
| CoAP.Token | - | ignore | value-sent | variable |

**Compressed size:** 4-6 bytes (Rule ID + port residues + CoAP fields)

**deviid:** Derive IID from link-layer address (EUI-64 or short address).

### 4.3. Rule 1: Mesh-Local IPv6 + UDP

For ULA (mesh-routable) traffic where source is local, destination is
within mesh.

**Applicability:**
- IPv6 source is mesh ULA (fd00::/8)
- IPv6 destination is mesh ULA (fd00::/8)
- Same mesh prefix (known from DODAG)

**Rule Definition:**

| Field | TV | MO | CDA | Sent |
|-------|----|----|-----|------|
| IPv6.Version | 6 | equal | not-sent | 0 |
| IPv6.TrafficClass | 0 | equal | not-sent | 0 |
| IPv6.FlowLabel | 0 | equal | not-sent | 0 |
| IPv6.PayloadLength | - | ignore | compute | 0 |
| IPv6.NextHeader | 17 | equal | not-sent | 0 |
| IPv6.HopLimit | - | ignore | value-sent | 8 bits |
| IPv6.SrcPrefix | <mesh-prefix> | equal | not-sent | 0 |
| IPv6.SrcIID | - | ignore | deviid | 0 |
| IPv6.DstPrefix | <mesh-prefix> | equal | not-sent | 0 |
| IPv6.DstIID | - | ignore | value-sent | 64 bits |
| UDP.SrcPort | 5683 | MSB(12) | LSB | 4 bits |
| UDP.DstPort | 5683 | MSB(12) | LSB | 4 bits |
| UDP.Length | - | ignore | compute | 0 |
| UDP.Checksum | - | ignore | compute | 0 |
| CoAP.Version | 1 | equal | not-sent | 0 |
| CoAP.Type | - | ignore | value-sent | 2 bits |
| CoAP.TKL | - | ignore | value-sent | 4 bits |
| CoAP.Code | - | ignore | value-sent | 8 bits |
| CoAP.MID | - | ignore | value-sent | 16 bits |
| CoAP.Token | - | ignore | value-sent | variable |

**Compressed size:** 12-14 bytes (Rule ID + HopLimit + DstIID + ports + CoAP)

### 4.4. Rule 2: Link-local IPv6 + UDP + MQTT-SN

For MQTT-SN traffic (port 10883) outside CoAP range used by Rules 0/1 (per adaptation.md and appendix A.2). Global traffic falls to Rule 1 or 255.

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

**Compressed size:** 41 bytes (minimal compression for global traffic)

### 4.5. Rule 3: ICMPv6 RPL DIO (link-local)

For RPL DIO control messages.

**Applicability:**
- Next header is ICMPv6 (58)
- ICMPv6 type is RPL (155)
- Code indicates DIO

**Rule Definition:** (as above, SrcPrefix=fe80::/64)

**Compressed size:** 2 bytes (Rule ID + code)

### 4.6. Rule 4: RPL DAO (routable multi-hop)

Uses routable ULA source (fd00::/8 from DODAG) for end-to-end source preservation across relays (per RPL §6 and security spec). Link-local forbidden for forwarded DAO.

**Applicability:** Same as rule 3 but SrcPrefix = mesh ULA, Dst may be root ULA.

**Compressed size:** 6 bytes

### 4.7. Rules 5-6: OSCORE-protected CoAP

Rule 5: Link-local IPv6 + UDP + OSCORE (matches CoAP option delta=9)

Rule 6: Global IPv6 + UDP + OSCORE

Field descriptors mirror rules 0/1 with additional OSCORE option matching (equal on critical bits, value-sent for nonce/ID). Encrypted payload as tail.

**Compressed size:** 6/14 bytes

### 4.8. Rule 255: No Compression (Fallback)

### 4.6. Rule 255: No Compression (Fallback)

When no rule matches or for interoperability fallback.

```
SCHC datagram = [rule_id=0xFF] + original IPv6 packet
```

Rule 255 is REQUIRED for unknown packets, version mismatches, or as fallback. It ensures interoperability during rule set transitions.

CoAP header compression (RFC 8824) is OPTIONAL in this profile.

### 4.4. RPL Options Compression

RPL options (per RFC 6550 §6.7) follow the compressed base fields in RPL rules. The option Type field uses the MATCH_MAPPING matching operator (see `python/src/lichen/schc/rules.py:32` for the constant and `rust/lichen-schc/src/rules.rs:15` for `Mo::MatchMapping`; handling in codec.py:151 and context.py:42). A 2-bit index is sent via MAPPING_SENT CDA. The mapping prioritizes common DIO options. See appendix-schc.md §A.1 for the full current rule set.

**Mapping Table:**

| Index (2b) | Option Type | Use Case                     | RFC Reference                  |
|------------|-------------|------------------------------|--------------------------------|
| 0          | 0           | Pad1                         | RFC 6550 §6.7.1                |
| 1          | 1           | PadN                         | RFC 6550 §6.7.2                |
| 2          | 3           | Prefix Information (PIO)     | RFC 6550 §6.7.6 / RFC 4861 §4.6.2 |
| 3          | 2           | DAG Metric Container         | RFC 6550 §6.7.3                |

Example PIO FieldDescriptor (index 2, for RPL.Option.Type):

```python
# python/src/lichen/schc/rules.py style
FieldDescriptor(
    "RPL.Option.Type", 8, MO.MATCH_MAPPING, CDA.MAPPING_SENT,
    mapping=(0, 1, 3, 2),  # type -> compressed 2b index
)
```

Equivalent struct in `rust/lichen-schc/src/rules.rs` near RPL_DIO_FIELDS (lines 108-117). For PIO fields: Length=NotSent (value=4), PrefixLen=NotSent (64), Flags=MSB(common L/A/R), Lifetimes=MSB(0)/context, Prefix=LSB(64) or elided for DODAG-derived addresses. Full TLV parsing by upper layer post-decompression. See appendix-schc.md §A.1, rules.rs:108, rules.py:262 (_DIO_BASE_FIELDS), and test/vectors/schc_compression.json.

### 5.1. Parameters (current constants)

| Parameter                  | Value          | Reference                          |
|----------------------------|----------------|------------------------------------|
| m (window bits)            | 1              | constants.toml [schc.fragment]     |
| n (FCN bits)               | 6              | constants.toml [schc.fragment]     |
| t (DTAG bits)              | 0              | constants.toml [schc.fragment]     |
| Rule ID                    | 8 bits (0-7,255) | §4.1, lichen-core::constants.rs  |
| RCS                        | CRC-32, 4 bytes| constants.toml, fragment.rs:21     |
| retransmission_timeout_s   | 10s            | constants.toml, fragment.rs:24     |
| max_ack_requests           | 3              | constants.toml, fragment.rs:25     |
| inactivity_timeout_s       | 60s            | constants.toml, fragment.rs:26     |
| bitmap_msb_first           | true           | constants.toml                     |

### 5.2. Formats

Regular fragment: RuleID(8) + W(1) + FCN(6) + Tile

All-1: RuleID(8) + W(1) + 0b111111 + RCS(32) + Tile

ACK: RuleID(8) + control(8) + n(8) + bitmap-bytes (MSB-first, 1=missing)

### 5.3. Operation

Sender tiles with window_size from constants, uses FCN countdown per window, sends All-1 with RCS. Receiver uses bitmap for NACKs, verifies RCS on reassembly. Max ~12KB/datagram; larger use app chunking.

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

- **Rust lichen-schc:** rules.rs codec defines FieldDescriptor Mo/Cda enums static Rule registry for LINK_LOCAL_COAP GLOBAL_COAP RPL_DIO etc; test/vectors/schc_compression.json updated for codec and RPL option parsing impact
- **libschc:** C library, MIT license (recommended)
- **openschc:** Python reference, BSD license

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

[RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
           Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119,
           March 1997, <https://www.rfc-editor.org/info/rfc2119>.

[RFC8724]  Minaburo, A., Toutain, L., Gomez, C., Barthel, D., and JC.
           Zuniga, "SCHC: Static Context Header Compression and
           Fragmentation for LPWAN", RFC 8724, DOI 10.17487/RFC8724,
           April 2020, <https://www.rfc-editor.org/info/rfc8724>.

[RFC8824]  Minaburo, A., Toutain, L., and R. Andreasen, "Static Context
           Header Compression (SCHC) for the Constrained Application
           Protocol (CoAP)", RFC 8824, DOI 10.17487/RFC8824, June 2021,
           <https://www.rfc-editor.org/info/rfc8824>.

### 9.2. Informative References

[RFC6550]  Winter, T., Ed., Thubert, P., Ed., Brandt, A., Hui, J.,
           Kelsey, R., Levis, P., Pister, K., Struik, R., Vasseur, JP.,
           and R. Alexander, "RPL: IPv6 Routing Protocol for Low-Power
           and Lossy Networks", RFC 6550, DOI 10.17487/RFC6550, March 2012,
           <https://www.rfc-editor.org/info/rfc6550>.

[RFC7252]  Shelby, Z., Hartke, K., and C. Bormann, "The Constrained
           Application Protocol (CoAP)", RFC 7252, DOI 10.17487/RFC7252,
           June 2014, <https://www.rfc-editor.org/info/rfc7252>.

[LICHEN]   LICHEN Project, "LICHEN Protocol Specification",
           <https://github.com/MarkAtwood/project-LICHEN>.

## Appendix A. Complete Rule Set (Version 1)

Rule Set Version: 1 (see Section 6). Full descriptors are maintained in
`rust/lichen-schc/src/rules.rs`, the C implementation in `lichen/subsys/lichen/schc/`, and test vectors. See `test/vectors/schc_compression.json` for canonical examples.

- 0: RULE_LINK_LOCAL_COAP (link-local IPv6/UDP/CoAP)
- 1: RULE_GLOBAL_COAP (global IPv6/UDP/CoAP)
- 2: RULE_ICMPV6_ECHO
- 3: RULE_RPL_DIO
- 4: RULE_RPL_DAO
- 5: RULE_LINK_LOCAL_OSCORE
- 6: RULE_GLOBAL_OSCORE
- 7: RULE_MQTT_SN
- 255: RULE_UNCOMPRESSED

## Appendix B. Compression Examples

See `test/vectors/schc_compression.json` for machine-readable test vectors covering all rules. Human-readable examples are maintained in `spec/appendix-schc.md` and will be expanded in future revisions.

## Authors' Address

LICHEN Project
<https://github.com/MarkAtwood/project-LICHEN>
