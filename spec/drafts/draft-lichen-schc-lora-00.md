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
255-byte PHY frame and 185-byte signed-unicast SCHC envelope. A link mode that
cannot carry a 185-byte SCHC envelope MUST NOT use Rule IDs 0x78 or 0x79.
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
| IPv6.HopLimit | - | ignore | value-sent |
| IPv6.SrcAddr | fe80::/64 | MSB(64) | LSB(64) |
| IPv6.DstAddr | fe80::/64 | MSB(64) | LSB(64) |
| UDP.SrcPort | 5683 | MSB(12) | LSB(4) |
| UDP.DstPort | 5683 | MSB(12) | LSB(4) |
| UDP.Length | - | ignore | compute |
| UDP.Checksum | - | ignore | compute |
| CoAP.Version | 1 | equal | not-sent |
| CoAP.Type | - | ignore | value-sent |
| CoAP.TKL | - | ignore | value-sent |
| CoAP.Code | - | ignore | value-sent |
| CoAP.MID | - | ignore | value-sent |

**Compressed size:** 23-byte fixed compressed header (Rule ID plus 174-bit
residue padded to 22 bytes), followed by the CoAP token, options, and payload
tail per RFC 8824.

### 4.3. Rule 1: Global IPv6 + UDP + CoAP

For traffic using canonical LICHEN Yggdrasil `0200::/8` addresses.

**Rule Definition:** (aligned with appendix-schc.md:A.3, 03-adaptation.md:5.5, and GLOBAL_COAP_RULE)

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.Version | 6 | equal | not-sent |
| IPv6.TrafficClass | 0 | equal | not-sent |
| IPv6.FlowLabel | 0 | equal | not-sent |
| IPv6.PayloadLength | - | ignore | compute |
| IPv6.NextHeader | 17 | equal | not-sent |
| IPv6.HopLimit | - | ignore | value-sent |
| IPv6.SrcAddr | 0200::/8 | MSB(8) | LSB(120) |
| IPv6.DstAddr | 0200::/8 | MSB(8) | LSB(120) |
| UDP.SrcPort | 5683 | MSB(12) | LSB(4) |
| UDP.DstPort | 5683 | MSB(12) | LSB(4) |
| UDP.Length | - | ignore | compute |
| UDP.Checksum | - | ignore | compute |
| CoAP.Version | 1 | equal | not-sent |
| CoAP.Type | - | ignore | value-sent |
| CoAP.TKL | - | ignore | value-sent |
| CoAP.Code | - | ignore | value-sent |
| CoAP.MID | - | ignore | value-sent |

**Compressed size:** 37-byte fixed compressed header (Rule ID plus 286-bit
residue padded to 36 bytes), followed by the CoAP token, options, and payload
tail.

### 4.4. Rule 2: ICMPv6 Echo

For diagnostic and reachability testing.

**Rule Definition:** (matches `ICMPV6_ECHO_RULE` in the ICMPv6 rule registry in `rust/lichen-schc/src/rules.rs`; see appendix-schc.md and that module's ICMPv6 field declarations for the complete field set. Distinct from Rule 7: MQTT-SN.)

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

**Compressed size:** 23-byte fixed compressed header: the one-byte Rule ID
followed by the 176-bit (22-byte) residue. The echo payload follows verbatim as
the data tail.

### 4.5. Rule 3: RPL DIO (link-local)

For DODAG formation and maintenance. Rule 3 matches link-local source and
destination addresses, ICMPv6 type 155/code 1, and the 24-byte DIO base object.
It carries Hop Limit, both 64-bit IIDs, and the variable DIO base fields.

Both endpoints MUST be in `fe80::/64`. Consequently the canonical multicast
DIO destination `ff02::1a` does not match Rule 3 and MUST use sender-selected,
validated Rule 255 in Rule Set Version 3. Implementations MUST NOT silently add
a multicast mode to Rule 3 or reconstruct `fe80::1a`; destination and scope
checks complete before routing-state mutation.

**Compressed size:** 40-byte fixed compressed header (Rule ID plus 39-byte
residue). Every RPL option after the DIO base object follows verbatim. Version
3 does not apply `MATCH_MAPPING` to option types. The RFC 6550 Prefix
Information Option is Type 8, and its complete TLV remains unchanged in the
tail, as do state-carrying options.

### 4.6. Rule 4: RPL DAO with DODAGID (link-local)

Rule 4 matches link-local source and destination addresses and ICMPv6 type
155/code 2. It requires the DAO D flag (bit 6 of `kd_flags`) and the resulting
20-byte base object containing the DODAGID. A DAO without the DODAGID, or with
a ULA, Yggdrasil, or other routable endpoint address, does not match Rule 4.

**Compressed size:** 37-byte fixed compressed header (Rule ID plus 36-byte
residue). Every RPL option after the DAO base object, including Destination
Advertisement Object Target and Transit Information state, follows verbatim.

### 4.7. Rule 7: MQTT-SN

IPv6 + UDP with at least one endpoint port equal to 10883.  Rule Set Version 3
uses the canonical specialized residue defined in `spec/03-adaptation.md`
Section 5.5 and `spec/appendix-schc.md` Section A.1: Hop Limit, AddressMode,
two link-local IIDs or two full IPv6 addresses, PortDirection, and OtherPort.
The fixed compressed header is 21 bytes in canonical `fe80::/64` mode or 37
bytes in full-address mode, including Rule ID and padding but excluding the
MQTT-SN payload.  Compressors validate all elided IPv6/UDP fields and checksum;
decoders reject noncanonical modes or padding and recompute the checksum.

**Compressed size:** 21 bytes in link-local mode or 37 bytes in full-address
mode, plus the unchanged MQTT-SN payload

### 4.8. Rules 5-6: OSCORE-protected CoAP

Rule 5 (link-local) and Rule 6 (global) reuse base fields from Rules 0/1 plus OSCORE option. Encrypted payload as tail. Matches `LINK_LOCAL_OSCORE_RULE` / `GLOBAL_OSCORE_RULE`.

**Compressed size:** 23 bytes (link-local) or 37 bytes (global) before the
OSCORE tail; Rules 5 and 6 reuse the Rule 0 and Rule 1 residues.

### 4.9. Rule 255: No Compression (Fallback)

Rule 255 is the sender-selected uncompressed representation for a structurally
valid, complete IPv6 packet.  It MUST NOT be used to reinterpret an unknown
received Rule ID.  On a rule-version mismatch it is available only as a
validated single-frame degraded mode outside the incompatible DODAG.  All
implementations MUST support Rule 255 (see spec/03-adaptation.md:5.7 and
appendix-schc.md).

### 4.10. CoAP Compression Details

See appendix-schc.md:A.3, RFC 8824, and the CoAP fields in Rules 0/1/5/6 above. Version=1 is not-sent; Type/TKL/Code/MID are value-sent (token and options travel in tail after MID). Used in Rules 0/1/5/6. OPTIONAL for non-CoAP traffic (e.g. ICMP, RPL, MQTT-SN use their own rules).

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
| Regular tile size | 179 bytes | Fits the signed EUI-64 unicast envelope including SIID |
| Final tile | 1-179 bytes in All-1 | One fixed tile-size policy |
| RCS | CRC-32/ISO-HDLC, 32 bits | RFC 8724 integrity check |
| Retransmission timer | 10 seconds | LoRa latency tolerance |
| MAX_ACK_REQUESTS | 4 | Initial All-1 plus at most 3 retries |
| Inactivity timer | 60 seconds | Clean up stale state |

Rule ID 0x78 applies to canonical endpoint A-to-B data and Rule ID 0x79 applies
to B-to-A data. Endpoint A is the endpoint with the lexicographically smaller
canonical 32-byte link-signing public key, compared as an unsigned octet
string; endpoint B has the larger key. Equal keys MUST be rejected as not
identifying a peer pair. Data fragments, ACK REQ, and Sender-Abort are sent in
the data direction. ACK and Receiver-Abort travel in the reverse direction but
retain the data transfer's Rule ID. Implementations MUST derive and validate
the Rule ID from authenticated full signer identities rather than an EUI-64,
untrusted address, or caller-selected default. Implementations MUST NOT create
a SCHC Packet requiring more than two windows or 126 tiles.

The 179-byte tile size is based on the most constrained normal LICHEN frame:
a 255-byte signed EUI-64 unicast frame, including the mandatory 8-byte signer
EUI-64 (SIID), leaves 186 bytes for authenticated L2 payload. The outer SCHC
dispatch consumes one byte, leaving a 185-byte SCHC fragment envelope. A
15-bit fragment header, 32-bit RCS, 179-byte final tile, and one trailing
padding bit exactly fill that envelope. All non-final tiles MUST be exactly
179 bytes. The final tile MUST be non-empty and MUST be carried
only in All-1.

Receivers MUST support reassembly of SCHC Packets up to 1281 bytes. This
accommodates a 1280-byte IPv6 packet carried by the 0xFF uncompressed fallback
Rule ID. Support
for larger packets up to the encoding ceiling of 126 * 179 = 22,554 bytes is
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
3. The receiver responds to each otherwise-valid All-1 or ACK REQ while its
   response counter is less than MAX_ACK_REQUESTS. It increments that counter
   when it generates an ACK, independently of link-layer radio delivery. It
   sends C=1 after a successful RCS check, or C=0 for the lowest-numbered
   incomplete window. If a fifth request would require another ACK, it sends
   Receiver-Abort instead and enters terminal hold-down.
4. The sender retransmits tiles whose bitmap bits are zero, then sends ACK REQ
   for the packet's final W unless the retransmission batch included All-1.
5. Before any All-1 or ACK REQ transmission, the sender checks Attempts. If
   Attempts equals MAX_ACK_REQUESTS, it sends Sender-Abort instead. Otherwise
   it transmits the request and increments Attempts. This check applies after a
   C=0 ACK as well as after timer expiry, so a fifth request is never sent.
   Attempts counts generated All-1 and ACK REQ outputs; radio delivery is a
   separate link-layer result and does not change the fragmentation counter.
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
   8 bit  1b   6 bit    179 bytes          1 bit
```

**All-1 Fragment (final):**
```
+--------+---+--------+--------+--------------+---------+
| RuleID | W | 111111 |  RCS   |  Final Tile  | Padding |
+--------+---+--------+--------+--------------+---------+
   8 bit  1b   6 bit   32 bit    1-179 bytes     1 bit
```

Rule 255 is REQUIRED as a sender-selected fallback for valid IPv6 packets that
match no compression rule.  Receivers MUST drop unknown Rule IDs; they MUST NOT
reinterpret those residues as Rule 255.  During a rule-version mismatch, a
node MUST NOT join the incompatible DODAG and MAY use Rule 255 only for a
validated packet that fits one link-layer frame outside that DODAG.  CoAP
header compression follows RFC 8824 for applicable rules (0/1/5/6). RPL
options after a Rule 3 or Rule 4 base object remain verbatim; in particular,
the Prefix Information Option is Type 8.

The complete normative rule set (including Rules 0-7 and 255), active Field
Descriptors, matching operators, CDAs, constants (m=1, n=6, RCS=CRC-32,
timeouts, WINDOW_SIZE=63, tile sizes), and bit-exact test vectors serving as
the canonical independent oracle for all implementations (Rust
`lichen-schc`, C/Zephyr, Python) are maintained in `spec/appendix-schc.md`
(primary reference), `rust/lichen-schc/src/rules.rs`, `constants.toml`,
`lichen/subsys/lichen/schc/`, `test/vectors/schc_compression.json`, and
`test/vectors/schc_fragmentation.json`. All implementations MUST produce
identical output to those fixed-profile vectors. The separate
`test/vectors/schc_fragment.json` exercises generic RFC 8724 codec machinery,
including deliberately non-profile parameters; it does not expand the LICHEN
production profile. RPL option mapping is not part of Rule Set Version 3.

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

C=1 (success, no bitmap) encodes as `78 c0` (for Rule 0x78, W=1). Bitmap is MSB-first (1=received, 0=missing), compressed by removing the maximal trailing run of 1-bits. Sender uses windowed FCN countdown (m=1, n=6). Receiver sends NACK on loss or C=1 after successful RCS verification on All-1. All-1 carries RCS (CRC-32). Retransmission timeout is 10 seconds, MAX_ACK_REQUESTS is 4, and inactivity timeout is 60 seconds. Receivers MUST support 1,281-byte SCHC Packets; statically provisioned receiver limits MAY extend to the 22,554-byte encoded SCHC Packet ceiling. The Rule ID counts toward that ceiling: Rule 255 carries at most 22,553 raw IPv6 octets, while a compressible raw IPv6 packet may be larger only when its final encoding remains at most 22,554 bytes. A sender MUST NOT exceed the known receiver limit, as specified in Section 5.1. Applications MAY still chunk larger payloads, for example SenML batches described by `spec/12-apps.md`. Parameters cross-reference `spec/03-adaptation.md` Section 5.6, `constants.toml`, and `lichen-schc`.

## 6. Rule Versioning and DIO Advertisement

Rule Set Version (8-bit) is originated by the DODAG root and advertised in
every authenticated RPL DIO usable for parent selection. Non-root routers
propagate the root-originated value unchanged using the exact three-octet
option defined by `spec/03-adaptation.md` §5.7 (authoritative definition; this
document provides LoRa-specific context only). A non-root parent-selectable
DIO serializer MUST fail if that root-originated value is unavailable; it MUST
NOT replace it with the node's local version.
Version 3 is the only operational registry and introduces the canonical
specialized Rule 7 residue.  A node receiving an absent, malformed,
unauthenticated, reserved, unsupported, or mismatched version MUST NOT join or
remain in that DODAG.  Outside the incompatible DODAG it MAY use Rule 255 only
for a validated IPv6 packet that fits one link-layer frame; it MUST NOT use
fragmentation or any compressed rule under the mismatch.

Full details, rule tables (0-7, 255), Field Descriptors, mappings, constants,
and bit-exact test vectors are in `spec/appendix-schc.md`,
`rust/lichen-schc/src/rules.rs` (and `lib.rs`), and `test/vectors/schc*.json`.
All implementations (Rust, C, Python) MUST match those cross-implementation
fixtures. A fixture emitted through an implementation codec is not by itself
an independent oracle; security-critical signatures, checksums, address
bindings, and policy verdicts require an additional spec-derived or external
verification that does not call the production path under test.

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
A two-octet ACK REQ can be bit-identical to a compressed C=0 ACK. Receivers
MUST classify that wire value from the authenticated sender role and the
directional Rule ID before invoking an ACK decoder or mutating sender state.

After timeout or a retransmission batch, ACK REQ MUST carry the final W of the
packet, not the window whose tiles were most recently retransmitted.

On receiving Sender-Abort or Receiver-Abort, the recipient MUST stop the
retransmission or inactivity timer, release the retained packet or tile-buffer
state for that authenticated peer pair and Rule ID, report failure to its
caller, retain the terminal tombstone defined below, and MUST NOT send an ACK
for the abort.

Every active context and terminal record is keyed by the ordered full local and
remote signer public keys, the opaque current remote trust-store key-generation
token, and the directional Rule ID. An implementation that supports live local-key
replacement MUST additionally bind its opaque current local key-generation
token. A fixed-local-key owner MAY persist state under the full local public key
because changing that key creates a new owner and invalidates all live
capabilities. SIID and address aliases are never state keys. Current-generation
validity MUST be rechecked before every mutation or control response. Revocation
or replacement atomically invalidates all active,
terminal, cached-response, and admission-floor state in the retired generation,
including reinstalling the same public key as a new generation.

Every terminal outcome (successful RCS verification, Sender-Abort,
Receiver-Abort, retry exhaustion, and inactivity timeout) MUST replace the
active packet or reassembly buffers with a tombstone keyed by the authenticated
peer pair and directional Rule ID. The tombstone MUST retain the session-wide
authenticated link-counter high-water mark, terminal outcome, and the final ACK
when one exists. Its hold-down duration is 60 seconds measured from the current
monotonic time at the terminal transition; clock regression MUST NOT shorten
that interval.

During hold-down, an otherwise-valid All-1 or ACK REQ carrying a strictly newer
authenticated counter receives the cached terminal ACK or abort response when
one exists. All other late fragments and controls are discarded. Every
authenticated late message in the same current generation nevertheless
advances the terminal high-water when newer. An inactivity timeout retains its
high-water mark and outcome but has no cached success ACK.

After response hold-down expires, the bounded durable high-water remains as a
generation-scoped admission floor. Only the canonical first Regular Fragment
(`W=0`, `FCN=62`) with a counter greater than that floor may open the next
session. Its opening counter is the immutable session-admission floor, and
every later admitted fragment/control counter MUST be greater. All-1 cannot
open a session because a one-tile packet fits the unfragmented profile. ACK
REQ, aborts, All-1, and other Regular FCNs MUST NOT create a session.

Tombstone and admission-floor storage MUST be bounded and persisted with trust
and replay state. Eviction or reclamation MUST NOT make a
still-live replacement session vulnerable to a late fragment from the prior
session. Link-key rotation invalidates active contexts and tombstones in the
retired key domain.

If all assigned bitmap positions are 1 but the RCS fails, the receiver sends
C=0 for the final window. Because this profile mandates that the final tile is
in All-1, the sender cannot identify a repairable tile and MUST send
Sender-Abort.

CoAP per RFC 8824 is OPTIONAL. RPL options are copied verbatim after the DIO or
DAO base object; Rule Set Version 3 defines no RPL option mapping compression.

## 7. Profile Limits

With 63 tiles per window, two windows, and 179-byte tiles:
- Encoding ceiling: 22,554 bytes
- Mandatory receiver support: 1281 bytes
- Larger receiver limits: implementation-specific up to the encoding ceiling

Packets exceeding the known receiver limit MUST be chunked at the application
layer or rejected before fragmentation.

## 8. Implementation Considerations

### 8.1. Memory Requirements

| Component | RAM | Flash |
|-----------|-----|-------|
| Rule storage | ~500 bytes | ~2 KB |
| Sender state | ~64 bytes plus retained SCHC Packet | - |
| Receiver state | ~64 bytes plus configured reassembly buffer | - |
| Mandatory reassembly buffer | 1281 bytes per active context | - |

Implementations MUST provide at least one active reassembly context. Additional
contexts and buffers larger than 1281 bytes are optional. The peer key is the
ordered tuple of the receiver's local link-signing identity, the remote full
signer identity established by link authentication, and the data-direction
fragmentation Rule ID. The sender EUI-64 used as the exact link destination
comes from the trust-store record selected by signature verification; it is not
read from a source address field in the link header and MUST NOT substitute for
the full signer identity when owning fragmentation state.
Allocation-free implementations MAY use statically configured context and
packet-buffer pools. A transfer that exceeds available state receives
Receiver-Abort.

### 8.2. Processing Requirements

- Compression: O(n) where n = number of rules (typically <10)
- Decompression: O(1) after rule lookup
- Fragmentation: O(1) per fragment
- Reassembly: O(fragments) for bitmap management

### 8.3. Existing Implementations

- **libschc:** C library, MIT license (recommended)
- **openschc:** Python reference, BSD license
- **Custom:** May be needed for constrained targets

## 9. Security Considerations

### 9.1. Compression Oracle Attacks

SCHC compression does not introduce compression oracle vulnerabilities
because rule selection is based on header fields, not encrypted content.

### 9.2. Fragmentation Attacks

**Resource exhaustion:** Attackers may send partial fragment sequences
to exhaust reassembly buffers. Mitigations:
- Inactivity timer (60s) to garbage collect stale state
- Limit concurrent reassembly sessions (e.g., 4 per neighbor)
- Authenticate fragments at link layer

**Fragment injection:** Attackers may inject fragments into ongoing
reassembly. Mitigations:
- RCS (CRC-32) validates complete packet
- Link-layer signatures authenticate sender

### 9.3. Rule Mismatch

Rule mismatch between sender and receiver causes packet loss or
corruption. Version advertisement in DIO prevents this for nodes
in the same DODAG.

## 10. IANA Considerations

This document has no IANA actions.

This SCHC profile for LoRa mesh uses pre-provisioned rules with 8-bit Rule IDs (no dynamic Context ID negotiation per RFC 8724). Future extensions that register SCHC Context IDs or standardized Rule IDs for LoRa MUST coordinate with the IETF LPWAN WG to prevent namespace fragmentation and ensure interoperability with other LPWAN SCHC profiles.

Future versions of this document may request:
- A dedicated SCHC Context ID range for LoRa (if negotiated rules are added)
- An IANA registry for standardized LoRa SCHC rules
- A CoAP Option or RPL Option Type for rule version advertisement

## 11. References

### 11.1. Normative References

- [RFC 2119] Key words for use in RFCs
- [RFC 8724] SCHC: Generic Framework for Static Context Header
  Compression and Fragmentation
- [RFC 8824] SCHC for CoAP

### 11.2. Informative References

- [RFC 6550] RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks
- [RFC 7252] The Constrained Application Protocol (CoAP)
- [LICHEN] LICHEN Protocol Specification

## Appendix A. SCHC Rule Set (Version 3)

Rule Set Version 3 is defined authoritatively in `spec/03-adaptation.md` §5.7.
This document provides LoRa-specific context only and avoids duplicating the
full table per I-D best practices. Complete active Field Descriptors, matching
operators, CDAs, constants, CoAP/OSCORE rules (per RFC 8824/8613), and
implementation details are in the canonical references:
`spec/appendix-schc.md`, `rust/lichen-schc/src/rules.rs` (and `lib.rs`),
`constants.toml`, `lichen/subsys/lichen/schc/`, and the test vectors. RPL
options are verbatim tails in this version; no `MATCH_MAPPING` option
descriptor is active.

Example summary (normative values and full descriptors in the references above):

| Rule ID | Name                  | Primary Use                          | Compressed Size |
|---------|-----------------------|--------------------------------------|-----------------|
| 0       | LINK_LOCAL_COAP       | Link-local IPv6+UDP+CoAP             | 23-byte fixed header |
| 1       | GLOBAL_COAP           | Yggdrasil IPv6+UDP+CoAP              | 37-byte fixed header |
| 3       | RPL_DIO               | Link-local RPL DIO                    | 40-byte fixed header + verbatim options |
| 4       | RPL_DAO               | Link-local RPL DAO with DODAGID       | 37-byte fixed header + verbatim options |
| 2, 5-7  | ICMP, OSCORE, MQTT-SN | As named                              | Rule-specific; see canonical appendix |
| 255     | UNCOMPRESSED          | Fallback for mismatches/version errors | Full header  |

Rule versioning is advertised in DIOs. OSCORE treats the payload as opaque.
RPL options remain verbatim after the compressed base object.

## Appendix B. Test Vectors and Oracles

Canonical cross-implementation fixtures (MUST be matched bit-exactly by Rust
`lichen-schc`, C/Zephyr `lichen/subsys/lichen/schc/`, and Python) are in
`test/vectors/schc_compression.json` and
`test/vectors/schc_fragmentation.json`. The generic
`test/vectors/schc_fragment.json` dataset separately tests reusable RFC 8724
codec machinery with non-profile parameters. Each dataset records its actual
provenance: independently hand-packed fields and standard-library CRC/SHA or
Schnorr group operations are independent oracles; output produced through a
production construction helper is labeled a regression fixture and receives a
separate independent wire/semantic verification.

Human-readable examples, additional validation, and full interop requirements are in `spec/appendix-schc.md` and `test/vectors/README.md`. See `draft-lichen-rpl-lora-00.md` for integration with SF metrics in the capability DIO option.

(Merge conflicts across worker5, worker8, worker18, worker24 and related worktrees fully resolved; all duplicate text, inline tables, and outdated TODOs removed; xrefs to `lichen-schc` (including `lib.rs` and `rules.rs`), test vectors, and interop notes consolidated. CC-BY-4.0)

## Authors' Address

LICHEN Project
https://github.com/MarkAtwood/project-LICHEN
