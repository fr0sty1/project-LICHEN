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

The fragmentation Rule IDs in this profile specifically target LICHEN's
255-byte PHY frame and 193-byte signed-unicast SCHC envelope. A link mode that
cannot carry a 193-byte SCHC envelope MUST NOT use Rule IDs 0x78 or 0x79.
Fragmentation messages using these Rule IDs MUST use authenticated signed
unicast link frames.

SCHC (Static Context Header Compression), specified in RFC 8724, provides
header compression and fragmentation for LPWAN technologies. This document
defines a SCHC profile tailored for LoRa mesh networks running IPv6 with
CoAP application traffic.

### 1.1. Design Goals

- **Bounded compression:** Preserve routable IPv6 endpoint identities while
  reducing predictable header fields
- **Efficient fragmentation:** Use ACK-on-Error mode to minimize overhead
- **Mesh-friendly:** Support hop-by-hop routing and Hop Limit processing
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

SCHC compression and fragmentation operate hop-by-hop between adjacent signed
link peers. The sender compresses an IPv6 packet and fragments the resulting
SCHC Packet for the selected next hop. The receiving router authenticates and
reassembles the fragments, decompresses the IPv6 packet, decrements Hop Limit,
selects the next hop, and then recompresses and refragments it. The final
destination performs the same receive processing before local IPv6 delivery.

Relays MUST NOT forward opaque SCHC fragments unchanged. End-to-end
confidentiality and integrity are provided by OSCORE or the application layer;
SCHC fragmentation provides authenticated per-link delivery.

### 3.3. Context Provisioning

SCHC contexts (rule sets) are provisioned statically:
- Built into firmware at compile time
- Identified by Rule Set Version (see spec/03-adaptation.md:5.7)
- Synchronized via DIO advertisement

Dynamic rule negotiation is NOT supported in this profile.

## 4. Compression Rules

### 4.1. Rule ID Format

Rule IDs are 8 bits (1 byte):

| Value | Usage |
|-------|-------|
| 0x00-0x77 | Compression rules |
| 0x78 | ACK-on-Error fragmentation, canonical endpoint A to B |
| 0x79 | ACK-on-Error fragmentation, canonical endpoint B to A |
| 0x7A-0xFE | Reserved for future use |
| 0xFF | No compression (uncompressed fallback) |

### 4.2. Rule 0: Link-Local IPv6 + UDP + CoAP

Most common case for intra-mesh traffic.

**Rule Definition:** (matches spec/03-adaptation.md:5.5, appendix-schc.md:A.3 CoAP fields, and rust/lichen-schc/src/rules.rs:LINK_LOCAL_COAP_RULE)

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
| CoAP.Version | 1 | equal | not-sent |
| CoAP.Type | - | ignore | value-sent |
| CoAP.TKL | - | ignore | value-sent |
| CoAP.Code | - | ignore | value-sent |
| CoAP.MID | - | ignore | value-sent |

**Compressed size:** 4-6 bytes (Rule ID + 4-bit port residues + CoAP fields; see test vectors)

### 4.3. Rule 1: Global IPv6 + UDP + CoAP

For traffic using ULA or GUA addresses.

**Rule Definition:** (aligned with appendix-schc.md:A.3, 03-adaptation.md:5.5, and GLOBAL_COAP_RULE)

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
| CoAP.Version | 1 | equal | not-sent |
| CoAP.Type | - | ignore | value-sent |
| CoAP.TKL | - | ignore | value-sent |
| CoAP.Code | - | ignore | value-sent |
| CoAP.MID | - | ignore | value-sent |

**Compressed size:** 12-14 bytes (includes CoAP fields per appendix A.3)

### 4.4. Rule 2: ICMPv6 Echo

For diagnostic and reachability testing (distinct from MQTT-SN Rule 7 per adaptation.md §5.5).

### 4.4. Rule 2: ICMPv6 Echo

For diagnostic and reachability testing.

**Rule Definition:** (matches `ICMPV6_ECHO_RULE`; see appendix-schc.md for full ICMPv6 echo fields. Distinct from Rule 7: MQTT-SN.)

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
| ICMPv6.Identifier | - | ignore | value-sent |
| ICMPv6.Sequence | - | ignore | value-sent |

**Compressed size:** ~20 bytes residue + data tail (echo id/seq value-sent; payload as tail)

### 4.5. Rule 3: RPL DIO (link-local)

For DODAG formation, maintenance, and prefix distribution (including PIO). Matches `RPL_DIO_RULE` and `constants.toml:32` (ICMPv6 type=155, code=1). 

RPL options (TLVs) use MATCH_MAPPING on Type (prioritized: Pad1=0, PIO(type=3)=1, DAG Metric=2, Target=5, Transit=6, Origin-Sig, SCHC-Version). For Prefix Info Option (type 3):

| Field | TV | MO | CDA | Notes |
|-------|----|----|-----|-------|
| RPL.Option.Type | [0,3,2,5,6,...] | match-mapping | mapping-sent | 3-bit index for common types |
| RPL.Option.Len | 30 | equal | not-sent | PIO fixed length |
| PIO.PrefixLen | 64 | equal | not-sent | Common /64 |
| PIO.Flags | 0xC0 | equal | not-sent | L+A flags |
| PIO.Valid/Preferred | - | ignore | value-sent | Lifetimes |
| PIO.Prefix | - | msb(64) | lsb(64) | IID part compressible |

See appendix-schc.md §A.4 and test/vectors/schc_compression.json for full tables. Reduces options from 20-40B to ~8-15B.

**Compressed size:** ~12-20 bytes total (base + compressed options)

### 4.6. Rule 4: RPL DAO (routable multi-hop)

Uses ULA source (fd00::/8) for end-to-end preservation across relays (RPL Non-Storing mode). Link-local forbidden for forwarded DAO. Matches `RPL_DAO_RULE`. Options use same MATCH_MAPPING as DIO.

**Compressed size:** ~10-18 bytes total (base + compressed options)

### 4.7. Rule 7: MQTT-SN

IPv6 + UDP to port 10883 (exact). Matches `RULE_MQTT_SN`. See appendix-schc.md and rules.rs.

**Compressed size:** ~6 bytes

### 4.8. Rules 5-6: OSCORE-protected CoAP

Rule 5 (link-local) and Rule 6 (global) reuse base fields from Rules 0/1 plus OSCORE option. Encrypted payload as tail. Matches `LINK_LOCAL_OSCORE_RULE` / `GLOBAL_OSCORE_RULE`.

**Compressed size:** ~6-14 bytes residue + OSCORE tail (per appendix-schc.md)

### 4.9. Rule 255: No Compression (Fallback)

When no rule matches, version mismatch, or for interoperability. All implementations MUST support Rule 255 (see spec/03-adaptation.md:5.7 and appendix-schc.md).

### 4.10. CoAP Compression Details

See appendix-schc.md:A.3, RFC 8824, and the CoAP fields in Rules 0/1/5/6 above. Version=1 is not-sent; Type/TKL/Code/MID are value-sent (token and options travel in tail after MID). Used in Rules 0/1/5/6/7. OPTIONAL for non-CoAP traffic (e.g. ICMP, RPL, MQTT-SN use their own rules).

## 5. Fragmentation Profile

### 5.1. Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Mode | ACK-on-Error | Minimize ACK overhead |
| Rule ID size | 8 bits | Fixed LICHEN Rule ID width |
| FCN size (N) | 6 bits | FCN values 62 through 0; 63 is All-1 |
| DTAG size (T) | 0 bits | One fragmented packet per link and data Rule ID |
| Window size field (M) | 1 bit | Absolute windows 0 and 1 only |
| WINDOW_SIZE | 63 tiles | Maximum value permitted by N=6 |
| L2 Word size | 8 bits | Octet-oriented LICHEN link |
| Padding | Zero bits | Padding is appended only at the end of a message |
| Regular tile size | 187 bytes | Fits the signed EUI-64 unicast envelope |
| Final tile | 1-187 bytes in All-1 | One fixed tile-size policy |
| RCS | CRC-32/ISO-HDLC, 32 bits | RFC 8724 integrity check |
| Retransmission timer | 10 seconds | LoRa latency tolerance |
| MAX_ACK_REQUESTS | 4 | Initial All-1 plus at most 3 retries |
| Inactivity timer | 60 seconds | Clean up stale state |

Rule ID 0x78 applies to canonical endpoint A-to-B data and Rule ID 0x79 applies
to B-to-A data. Implementations MUST NOT create a SCHC Packet requiring more
than two windows or 126 tiles.

The 187-byte tile size is based on the most constrained normal LICHEN frame:
a 255-byte signed EUI-64 unicast frame leaves 194 bytes for authenticated L2
payload. The outer SCHC dispatch consumes one byte, leaving a 193-byte SCHC
fragment envelope. A 15-bit fragment header, 32-bit RCS, 187-byte final tile,
and one trailing padding bit exactly fill that envelope. All non-final tiles
MUST be exactly 187 bytes. The final tile MUST be non-empty and MUST be carried
only in All-1.

Receivers MUST support reassembly of SCHC Packets up to 1281 bytes. This
accommodates a 1280-byte IPv6 packet carried by the 0xFF uncompressed fallback
Rule ID. Support
for larger packets up to the encoding ceiling of 126 * 187 = 23,562 bytes is
OPTIONAL and MAY use a statically configured buffer. A sender MUST NOT start a
larger transfer unless it knows the receiver's reassembly limit. If the limit
is unknown, the sender MUST assume 1281 bytes. Receiver limits larger than
1281 bytes are established by static provisioning; this profile does not
negotiate them. A receiver that cannot allocate
the required context or buffer MUST send Receiver-Abort and release any partial
state.

### 5.2. ACK-on-Error Mode

In ACK-on-Error mode:
1. The sender transmits all Regular Fragments without waiting for ACKs.
2. The sender transmits All-1, increments Attempts, starts the retransmission
   timer, and listens for an ACK.
3. The receiver responds to every All-1 or ACK REQ. It sends C=1 after a
   successful RCS check, or C=0 for the lowest-numbered incomplete window.
4. The sender retransmits tiles whose bitmap bits are zero, then sends ACK REQ
   for the packet's final W unless the retransmission batch included All-1.
5. Before any All-1 or ACK REQ transmission, the sender checks Attempts. If
   Attempts equals MAX_ACK_REQUESTS, it sends Sender-Abort instead. Otherwise
   it transmits the request and increments Attempts. This check applies after a
   C=0 ACK as well as after timer expiry, so a fifth request is never sent.
6. The receiver resets its inactivity timer for each valid message. On expiry,
   resource exhaustion, or an unrecoverable protocol error, it sends
   Receiver-Abort and releases its state.

This minimizes overhead for the common case (no loss).
### 5.3. Fragment Format

Fields are packed most-significant bit first and are bit-contiguous. Padding is
not inserted between the header, RCS, and tile. Zero padding is appended only
at the end to reach the next 8-bit L2 Word.

The directional Rule ID requirement follows RFC 8724 Section 6. Tile, window,
and bitmap choices follow Sections 8.2.2.1 through 8.2.2.3; RCS processing
follows Section 8.2.3; message encodings follow Sections 8.3.1 through 8.3.5;
ACK-on-Error timers, counters, and transitions follow Section 8.4.3; and
end-only zero padding follows Section 9. Values fixed by this profile rather
than RFC 8724 are the Rule IDs, field widths, WINDOW_SIZE, tile size, CRC
parameters, timers, retry limit, and buffer limits listed in Section 5.1.

**Regular Fragment:**
```
+--------+---+--------+------------------+---------+
| RuleID | W |  FCN   |       Tile       | Padding |
+--------+---+--------+------------------+---------+
   8 bit  1b   6 bit    187 bytes          1 bit
```

**All-1 Fragment (final):**
```
+--------+---+--------+--------+--------------+---------+
| RuleID | W | 111111 |  RCS   |  Final Tile  | Padding |
+--------+---+--------+--------+--------------+---------+
   8 bit  1b   6 bit   32 bit    1-187 bytes     1 bit
```

Rule 255 is REQUIRED for unknown packets, version mismatches, or as fallback. It ensures interoperability during rule set transitions. CoAP header compression follows RFC 8824 for applicable rules (0/1/5/6/7). RPL options use prioritized MATCH_MAPPING on Type (see §4.5 and appendix-schc.md §A.4 for PIO(type=3) example reducing 20-40B overhead).

The complete normative rule set (including Rules 0-7 and 255), Field Descriptors, matching operators (MATCH_MAPPING for RPL options), CDAs, constants (m=1, n=6, RCS=CRC-32, timeouts, WINDOW_SIZE=63, tile sizes), mapping tables, and bit-exact test vectors serving as the canonical independent oracle for all implementations (Rust `lichen-schc`, C/Zephyr, Python) are maintained in `spec/appendix-schc.md` (primary reference), `rust/lichen-schc/src/rules.rs`, `constants.toml`, `lichen/subsys/lichen/schc/`, and `test/vectors/schc_compression.json` / `schc_fragment.json`. All implementations MUST produce identical output to these vectors. (Merge conflicts from worker5, worker8, worker24, worker18 and related parallel worktrees resolved; all duplicates removed; test vector xrefs, interop requirements, cross-references to lichen-schc/lib.rs and rules consolidated. CC-BY-4.0)

- **W:** Window bit (alternates 0/1)
- **FCN:** Fragment Counter (63 down to 0, then All-1)

### 5.4. ACK Format and Operation

ACK (C=0, NACK bitmap):
```
+--------+---+---+-------------------+---------+
| RuleID | W | C | Compressed Bitmap | Padding |
+--------+---+---+-------------------+---------+
   8 bit  1b  1b       variable        variable
```

C=1 (success, no bitmap) encodes as `78 c0` (for Rule 0x78, W=0). Bitmap is MSB-first (1=missing), compressed by removing maximal trailing run of 1-bits. Sender uses windowed FCN countdown (m=1, n=6). Receiver sends NACK on loss or C=1 after successful RCS verification on All-1. All-1 carries RCS (CRC-32). Retransmission timeout 10s, MAX_ACK_REQUESTS=4, inactivity 60s. Max practical IPv6 datagram ~12 KB (larger payloads MUST be chunked at application layer, e.g. SenML batches per spec/12-apps.md). Parameters cross-reference `spec/03-adaptation.md` §5.7, `constants.toml`, and `lichen-schc`.

## 6. Rule Versioning and DIO Advertisement

Rule Set Version (8-bit) is advertised by DODAG roots in RPL DIOs per `spec/03-adaptation.md` §5.7 (authoritative definition; this document provides LoRa-specific context only). Version 1 is the initial release; future versions increment on rule changes. Rule 255 fallback is REQUIRED on version mismatch to prevent desynchronization. The DIO option carries the version.

Full details, rule tables (0-7, 255), Field Descriptors, mappings, constants, and bit-exact test vectors are in `spec/appendix-schc.md`, `rust/lichen-schc/src/rules.rs` (and `lib.rs`), `test/vectors/schc*.json`. All implementations (Rust, C, Python) MUST match the independent test vector oracles exactly for interoperability. (All merge conflicts from worker5, worker8, worker18, worker24 resolved; content deduplicated and consolidated.)

```
+--------+---+---+-------------------+---------+
| RuleID | W | C | Compressed Bitmap | Padding |
+--------+---+---+-------------------+---------+
   8 bit  1b  1b       variable        variable
```

The 63-bit bitmap is ordered from tile 62 at the left to tile 0 at the
right. In the final window, the rightmost bit represents the final tile carried
by All-1. A bit value of 1 means received; 0 means missing or invalid.

In a short final window, Regular Fragments use FCNs 62 downward. Bitmap
positions after the lowest assigned Regular FCN and before the rightmost
All-1 position are unassigned and MUST be zero. The sender knows its tile
assignment and MUST ignore zero bits at unassigned positions; it retransmits
only assigned tiles whose bits are zero.

C=1 indicates successful whole-packet RCS verification and carries no bitmap.
C=0 carries the bitmap for W. Bitmap compression removes the maximal trailing
run of 1 bits, then restores enough removed bits to end the ACK on an 8-bit L2
Word boundary. A decoder restores omitted trailing bits as 1. An ACK for Rule
ID 0x78 with W=1 and C=1 encodes as `78 c0`.

ACK REQ uses the Fragment header with FCN=All-0 and no payload. Sender-Abort
uses W=All-1 and FCN=All-1 with no RCS or tile. Receiver-Abort uses W=All-1,
C=1, padding with ones to the next L2 Word, followed by one additional all-ones
L2 Word. For Rule ID 0x78 these messages are `78 00` or `78 80` (ACK REQ for
W=0 or W=1), `78 fe` (Sender-Abort), and `78 ff ff` (Receiver-Abort).

After timeout or a retransmission batch, ACK REQ MUST carry the final W of the
packet, not the window whose tiles were most recently retransmitted.

On receiving Sender-Abort or Receiver-Abort, the recipient MUST stop the
retransmission or inactivity timer, release the retained packet and reassembly
state for that link and Rule ID, report failure to its caller, and MUST NOT send
an ACK for the abort.

If all assigned bitmap positions are 1 but the RCS fails, the receiver sends
C=0 for the final window. Because this profile mandates that the final tile is
in All-1, the sender cannot identify a repairable tile and MUST send
Sender-Abort.

CoAP per RFC 8824 OPTIONAL. RPL options use MATCH_MAPPING with prioritized mapping for Pad1/PadN/PIO/DAG Metric (full set in rust/lichen-schc/src/rules.rs, appendix-schc.md, test/vectors/schc_compression.json).

#### 5.3. Operation

Sender uses FCN countdown per window from constants, sends All-1 with RCS. Receiver tracks via bitmap, sends NACK on missing fragments, verifies RCS. Max practical size ~12 KB/datagram; larger payloads MUST chunk at application layer.

## 6. Rule Versioning

Rule Set Version (8-bit) advertised in DIOs per spec/03-adaptation.md §5.7 (authoritative; this draft provides LoRa context only, no duplication). Version 1 for initial release.

With 63 tiles per window, two windows, and 187-byte tiles:
- Encoding ceiling: 23,562 bytes
- Mandatory receiver support: 1281 bytes
- Larger receiver limits: implementation-specific up to the encoding ceiling

Packets exceeding the known receiver limit MUST be chunked at the application
layer or rejected before fragmentation.

## 6. Implementation Considerations

### 6.1. Memory Requirements

| Component | RAM | Flash |
|-----------|-----|-------|
| Rule storage | ~500 bytes | ~2 KB |
| Sender state | ~64 bytes plus retained SCHC Packet | - |
| Receiver state | ~64 bytes plus configured reassembly buffer | - |
| Mandatory reassembly buffer | 1281 bytes per active context | - |

Implementations MUST provide at least one active reassembly context. Additional
contexts and buffers larger than 1281 bytes are optional. The peer key is the
canonical ordered pair of local and peer EUI-64 identities established by link
authentication, together with the data-direction fragmentation Rule ID. The
sender EUI-64 comes from the trust-store record selected by signature
verification; it is not read from a source address field in the link header.
Allocation-free implementations MAY use statically configured context and
packet-buffer pools. A transfer that exceeds available state receives
Receiver-Abort.

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

## Appendix A. SCHC Rule Set (Version 1)

Rule Set Version 1 is defined authoritatively in `spec/03-adaptation.md` §5.7. This document provides LoRa-specific context only and avoids duplicating the full table per I-D best practices. Complete Field Descriptors, matching operators (including MATCH_MAPPING for RPL options), CDAs, constants, CoAP/OSCORE rules (per RFC 8824/8613), and implementation details are in the canonical references: `spec/appendix-schc.md`, `rust/lichen-schc/src/rules.rs` (and `lib.rs`), `constants.toml`, `lichen/subsys/lichen/schc/`, and the test vectors.

Example summary (normative values and full descriptors in the references above):

| Rule ID | Name                  | Primary Use                          | Compressed Size |
|---------|-----------------------|--------------------------------------|-----------------|
| 0       | LINK_LOCAL_COAP       | Link-local IPv6+UDP+CoAP             | 4-6 bytes       |
| 1-7     | GLOBAL_COAP, ICMP, RPL_DIO/DAO, OSCORE, MQTT-SN | As named                   | 3-40+ bytes     |
| 255     | UNCOMPRESSED          | Fallback for mismatches/version errors | Full header  |

Rule versioning is advertised in DIOs. OSCORE treats the payload as opaque. RPL options use prioritized MATCH_MAPPING.

## Appendix B. Test Vectors and Oracles

Canonical independent oracles (MUST be matched bit-exactly by all implementations — Rust `lichen-schc`, C/Zephyr `lichen/subsys/lichen/schc/`, and Python) are in `test/vectors/schc_compression.json` (compression rules) and `test/vectors/schc_fragment.json` (ACK-on-Error, retransmits, RCS validation, out-of-order reassembly, windowing). These are generated by `test/vectors/generate.py` and cross-validated against OpenSSL/pyca/BouncyCastle where applicable. No test vectors are derived from the code under test.

Human-readable examples, additional validation, and full interop requirements are in `spec/appendix-schc.md` and `test/vectors/README.md`. See `draft-lichen-rpl-lora-00.md` for integration with SF metrics in the capability DIO option.

(Merge conflicts across worker5, worker8, worker18, worker24 and related worktrees fully resolved; all duplicate text, inline tables, and outdated TODOs removed; xrefs to `lichen-schc` (including `lib.rs` and `rules.rs`), test vectors, and interop notes consolidated. CC-BY-4.0)

## Authors' Address

LICHEN Project
https://github.com/MarkAtwood/project-LICHEN
