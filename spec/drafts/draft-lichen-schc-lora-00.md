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
- Identified by Rule Set Version (see Section 6)
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

For each signed link, endpoint A is the lexicographically smaller 8-byte EUI-64
identity and endpoint B is the larger EUI-64. The receiver obtains the sender's
EUI-64 from the trust-store entry selected by successful signature verification.
Data from A to B uses Rule ID 0x78; data from B to A uses Rule ID 0x79. This
mapping is independent of mesh root, route, and whether either endpoint
originated the IPv6 packet.

Fragmentation control messages retain the Rule ID of the data direction they
control. For example, B's ACK for A-to-B fragments uses Rule ID 0x78 while
traveling from B to A. The outer LICHEN L2 SCHC dispatch byte is not part of the
Rule ID.

LICHEN SCHC Packets are octet-aligned before they enter fragmentation. A
compression Rule whose Rule ID and residue are not octet-aligned MUST append
zero bits to the compressed header through the next octet boundary before the
byte-aligned payload. The decompressor derives and removes those bits from the
Rule. This fixed C/D profile behavior makes the fragmentation input and every
tile an integral number of octets.

The Rule Set Version 2 whole-packet registry is:

| Rule ID | Use |
|---------|-----|
| 0 | Link-local IPv6 + UDP + CoAP |
| 1 | Global IPv6 + UDP + CoAP |
| 2 | Link-local IPv6 + ICMPv6 Echo |
| 3 | Link-local IPv6 + RPL DIO |
| 4 | Link-local IPv6 + RPL DAO with DODAGID |
| 5 | Link-local IPv6 + UDP + OSCORE-protected CoAP |
| 6 | Global IPv6 + UDP + OSCORE-protected CoAP |

The detailed Rule 0-3 tables in Sections 4.2 through 4.5 describe the legacy
Version 1 design and are retained only as historical context. They MUST NOT be
used to encode or decode Rule Set Version 2 packets. Version 2 bit-exact
compression behavior is fixed by the shared compression vectors.

### 4.2. Legacy Version 1 Rule 0: Link-Local IPv6 + UDP

Most common case: link-local communication with CoAP.

**Applicability:**
- IPv6 source and destination are link-local (fe80::/10)
- Next header is UDP
- UDP ports are in CoAP range (5683 ± 15)

**Rule Definition:**

| Field | TV | MO | CDA | Sent |
|-------|----|----|-----|------|
| IPv6.Version | 6 | equal | not-sent | 0 |
| IPv6.TrafficClass | 0 | equal | not-sent | 0 |
| IPv6.FlowLabel | 0 | equal | not-sent | 0 |
| IPv6.PayloadLength | - | ignore | compute | 0 |
| IPv6.NextHeader | 17 | equal | not-sent | 0 |
| IPv6.HopLimit | - | ignore | value-sent | 8 bits |
| IPv6.SrcPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.SrcIID | - | ignore | value-sent | 64 bits |
| IPv6.DstPrefix | fe80::/64 | equal | not-sent | 0 |
| IPv6.DstIID | - | ignore | value-sent | 64 bits |
| UDP.SrcPort | 5683 | MSB(12) | LSB | 4 bits |
| UDP.DstPort | 5683 | MSB(12) | LSB | 4 bits |
| UDP.Length | - | ignore | compute | 0 |
| UDP.Checksum | - | ignore | compute | 0 |

**Compressed size:** 19 bytes (Rule ID + Hop Limit + endpoint IIDs + ports)

### 4.3. Legacy Version 1 Rule 1: Mesh-Local IPv6 + UDP

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
| IPv6.SrcIID | - | ignore | value-sent | 64 bits |
| IPv6.DstPrefix | <mesh-prefix> | equal | not-sent | 0 |
| IPv6.DstIID | - | ignore | value-sent | 64 bits |
| UDP.SrcPort | 5683 | MSB(12) | LSB | 4 bits |
| UDP.DstPort | 5683 | MSB(12) | LSB | 4 bits |
| UDP.Length | - | ignore | compute | 0 |
| UDP.Checksum | - | ignore | compute | 0 |

**Compressed size:** 19 bytes (Rule ID + Hop Limit + endpoint IIDs + ports)

### 4.4. Legacy Version 1 Rule 2: Global IPv6 + UDP

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

**Compressed size:** 42 bytes after octet alignment

### 4.5. Legacy Version 1 Rule 3: ICMPv6 (RPL Control)

For RPL control messages (DIO, DAO, DIS).

**Applicability:**
- Next header is ICMPv6 (58)
- ICMPv6 type is RPL (155)

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
| ICMPv6.Code | - | ignore | value-sent | 8 bits |
| ICMPv6.Checksum | - | ignore | compute | 0 |

**Compressed size:** 2 bytes (Rule ID + ICMPv6 code)

### 4.6. Rule 255: No Compression (Fallback)

When no rule matches or for interoperability fallback.

```
+----------+----------------------+
| Rule ID  | Full IPv6 Packet     |
| (1 byte) | (40+ bytes)          |
+----------+----------------------+
```

All implementations MUST support Rule 255.

### 4.7. CoAP Compression

CoAP header compression MAY be applied after IPv6/UDP compression using
SCHC for CoAP (RFC 8824). This profile does not mandate CoAP compression
but provides guidance:

| CoAP Field | Typical Handling |
|------------|------------------|
| Version | not-sent (always 1) |
| Type | value-sent (2 bits) |
| Token Length | value-sent (4 bits) |
| Code | value-sent (8 bits) |
| Message ID | value-sent (16 bits) |
| Token | value-sent (variable) |
| Options | value-sent (variable) |

CoAP compression is OPTIONAL and implementation-dependent.

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

On receiving C=1 whose Rule ID and W match the transaction and its final window,
the sender MUST stop the retransmission timer, release its retained SCHC Packet
and fragmentation state, and report successful delivery to its caller. It MUST
NOT send another All-1 or ACK REQ for that packet. The sender MUST ignore C=1
with a non-final W and continue its retransmission timer.

The receiver maintains its own Attempts counter. It increments Attempts each
time it sends an ACK. If Attempts exceeds MAX_ACK_REQUESTS, it sends
Receiver-Abort and releases the context.

After sending C=1, the receiver MUST deliver the reassembled SCHC Packet once
and release the context. It does not retain a completion cache because T=0
cannot distinguish a delayed fragment from a new packet. An All-1 received
without Regular Fragment state is treated as a one-tile packet: the receiver
verifies its RCS, delivers it on success, and sends C=1. If C=1 is lost, the
sender can retransmit all missing Regular Fragments and All-1, so any SCHC
Packet can be delivered more than once. CoAP Message IDs, OSCORE replay
protection, or application idempotency MUST suppress effects of duplicate
delivery where required.

An ACK REQ received without reassembly state creates an empty context and
returns C=0 for window 0 with an all-zero bitmap. A multi-tile All-1 received
without prior Regular Fragments likewise creates a context containing only its
final tile and RCS, then returns C=0 for window 0. These responses allow the
sender to retransmit the complete packet after a lost C=1.

Within an active context, a Regular Fragment whose W and FCN were already
received is idempotent only when its tile bits are identical. The receiver MUST
ignore an identical duplicate after resetting the inactivity timer. Different
tile bits for the same W and FCN are an unrecoverable protocol error: the
receiver sends Receiver-Abort and releases the context. An identical repeated
All-1 MUST re-run current ACK processing and send the resulting ACK. A repeated
All-1 with different RCS or final-tile bits is an unrecoverable protocol error.

The receiver does not ACK All-0. All-0 is a Regular Fragment carrying a tile;
ACK REQ has FCN=All-0 and no payload, so the two are distinguishable by length.
With T=0, only one fragmented SCHC Packet per signed link and data Rule ID may
be active.

On receiving a matching C=0 ACK, the sender MUST stop the current
retransmission timer before retransmitting tiles. The All-1 or ACK REQ sent
after that batch starts a fresh timer and increments Attempts as described
above.

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

- **W:** Absolute window number, 0 or 1. It does not wrap within a packet.
- **FCN:** Tile index. Regular values count from 62 down to 0; 63 is All-1.
- **All-0:** FCN 0 in a non-final window and carries a regular tile.
- **All-1:** Carries the RCS followed by the final tile.
- **RCS:** CRC-32/ISO-HDLC (polynomial 0x04C11DB7, reflected polynomial
  0xEDB88320, init 0xFFFFFFFF, refin/refout true, xorout 0xFFFFFFFF), serialized
  most-significant octet first.

The RCS input is the complete SCHC Packet followed by the one zero padding bit
of All-1. A byte-oriented CRC implementation MUST then zero-extend that bit
string to an octet boundary before computing the CRC. For this profile, this is
equivalent to computing CRC-32/ISO-HDLC over the SCHC Packet followed by one
zero octet.

For example, a valid Regular Fragment using Rule ID 0x78, W=0, FCN=62,
and a 187-byte all-zero tile starts with `78 7c` and is followed by 187 zero
octets. The low bit of 0x7c is the first tile bit; the final zero padding bit is
the last bit of the message.

### 5.4. ACK Format

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

### 5.5. Maximum Packet Size

With 63 tiles per window, two windows, and 187-byte tiles:
- Encoding ceiling: 23,562 bytes
- Mandatory receiver support: 1281 bytes
- Larger receiver limits: implementation-specific up to the encoding ceiling

Packets exceeding the known receiver limit MUST be chunked at the application
layer or rejected before fragmentation.

## 6. Rule Versioning

### 6.1. Rule Set Version

Each firmware release defines a Rule Set Version (8-bit integer):

| Version | Meaning |
|---------|---------|
| 0 | Reserved |
| 1 | Legacy experimental fragmentation formats; not interoperable |
| 2 | RFC 8724 fragmentation profile defined in this document |
| 3+ | Future versions |

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
- Mismatched nodes MAY communicate an unfragmented Rule 255 SCHC Packet only
  when it fits one link frame
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
Rule Set Version: 2

Rule 0: Link-local IPv6 + UDP + CoAP
Rule 1: Global IPv6 + UDP + CoAP
Rule 2: Link-local IPv6 + ICMPv6 Echo
Rule 3: Link-local IPv6 + RPL DIO
Rule 4: Link-local IPv6 + RPL DAO with DODAGID
Rule 5: Link-local IPv6 + UDP + OSCORE-protected CoAP
Rule 6: Global IPv6 + UDP + OSCORE-protected CoAP
Rule 0x78: ACK-on-Error fragmentation for canonical endpoint A-to-B data
Rule 0x79: ACK-on-Error fragmentation for canonical endpoint B-to-A data
Rule 255: No compression (fallback)
```

## Appendix B. Compression Examples

**TODO:** Add worked examples showing compression of sample packets.

## Authors' Address

LICHEN Project
https://github.com/MarkAtwood/project-LICHEN
