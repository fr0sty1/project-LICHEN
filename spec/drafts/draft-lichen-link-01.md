# LICHEN Link Layer Frame Format

```
Internet-Draft                                              LICHEN Project
draft-lichen-link-01                                            June 2026
Intended status: Experimental
Expires: December 2026
```

## Status of This Document

**PRELIMINARY DRAFT — WORK IN PROGRESS**

This document is an early draft developed alongside a reference implementation.
It will be updated as implementation experience is gained. Coding agents with
human oversight may modify this specification as needed.

## Abstract

This document specifies the LICHEN link-layer frame format for LoRa networks.
Frames carry SCHC-compressed IPv6 datagrams with per-packet authentication
via Schnorr signatures. The format is designed to fit within LoRa's practical
payload limit of approximately 200 bytes while providing strong sender
authentication and replay protection.

## 1. Introduction

The LICHEN link layer sits between the LoRa physical layer and the IPv6/SCHC
adaptation layer. Its responsibilities are:

1. Framing: delimit variable-length payloads on the LoRa channel.
2. Addressing: identify the destination node when needed.
3. Replay protection: prevent injection of replayed frames.
4. Authentication: prove the frame was sent by the claimed node.
5. Encryption: optional payload encryption (OSCORE handles this at a higher
   layer; the link layer provides a flag to indicate encrypted payloads).

The LICHEN link layer does **not** provide a source address field. The sender's
identity is established by the signature (when present), and the IPv6 source
address in the SCHC payload provides the network-layer source. This keeps the
overhead minimal for the common case of authenticated unicast.

### 1.1. Design Goals

- **Small overhead:** 5 bytes minimum header + optional address + MIC.
- **Replay-safe:** Epoch + sequence number support a sliding-window replay filter.
- **Flexible addressing:** Broadcast, 16-bit short, EUI-64, or address-elided modes.
- **Authentication optional:** Unsigned frames are valid for bootstrap/discovery.
- **Encryption optional:** Flag signals payload is opaque (OSCORE-encrypted CoAP).

### 1.2. Use Case

LICHEN is deployed on LoRa networks (SF10/125 kHz/CR 4/5) with practical
MTUs of 50-250 bytes. At LoRa's data rates, every byte of overhead matters.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

- **Frame:** The complete unit of data transmitted on the LoRa channel.
- **Payload:** The SCHC-compressed IPv6 datagram carried in the frame body.
- **MIC:** Message Integrity Code — the cryptographic authentication tag.
- **EUI-64:** An IEEE 64-bit extended unique identifier, typically derived
  from the LoRa module's hardware address.
- **Epoch:** A key generation counter used to invalidate old sequence numbers
  when a node reboots or rotates its link key.

## 3. Frame Format

### 3.1. Overall Structure

```
Octets: 1        1       1      2       var     var      var
       +--------+-------+------+-------+-------+--------+-----+
       | LENGTH | LLSec | EPO  | SEQ   |  DST  |  PLD   | MIC |
       +--------+-------+------+-------+-------+--------+-----+
```

- **LENGTH** (1 octet): Number of bytes in the frame body (everything after
  the LENGTH byte). Implementations MUST NOT transmit frames with LENGTH > 255.
  Receivers MUST discard frames where LENGTH exceeds the received byte count.

- **LLSec** (1 octet): Link-layer security flags. See Section 3.2.

- **EPO** (1 octet): Key epoch. Incremented when the node's link key changes
  (e.g. after a reboot or key rotation). Receivers use the (EPO, SEQ) tuple
  for replay detection. Wraps modulo 256.

- **SEQ** (2 octets, big-endian): Sequence number. Monotonically increasing
  within an epoch. Receivers MUST maintain a replay window per (peer, epoch)
  pair and MUST discard frames whose (EPO, SEQ) has already been accepted.
  Wraps modulo 65536; see Section 5.2 for epoch management on wrap.

- **DST** (0, 2, or 8 octets): Destination address. Present and length
  determined by AddrMode in LLSec. See Section 3.3.

- **PLD** (variable): SCHC-compressed IPv6 payload. Length derived as
  `LENGTH - fixed_header_size - DST_len - MIC_len`. MUST be at least 1 byte.

- **MIC** (4 or 8 octets): Message Integrity Code. Present and length
  determined by MicLength in LLSec. Absent when S=0. See Section 4.

### 3.2. LLSec Byte

```
  Bit:  7   6   5   4   3   2   1   0
       +---+---+---+---+---+---+---+---+
       | R | E | S |  MicLength  | AM  |
       +---+---+---+---+---+---+---+---+
```

- **Bits 1-0 (AM): AddrMode.** Destination address format:

  | Value | Name     | DST length | Meaning                                 |
  |-------|----------|------------|-----------------------------------------|
  | 0b00  | None     | 0 bytes    | Broadcast; no destination address present |
  | 0b01  | Short    | 2 bytes    | 16-bit short address                    |
  | 0b10  | Extended | 8 bytes    | EUI-64 extended address                 |
  | 0b11  | Elided   | 0 bytes    | Address elided; derived from PLD context |

- **Bits 4-2 (MicLength): MIC size.**

  | Value | MIC length | Security                              |
  |-------|------------|---------------------------------------|
  | 0b000 | 4 bytes    | 32-bit MIC                            |
  | 0b001 | 8 bytes    | 64-bit MIC                            |
  | 0b010–0b111 | —  | Reserved. Receivers MUST discard.    |

  When the S bit is 0 (no signature present), the MicLength field is
  RECOMMENDED to be 0b000. Receivers MUST NOT rely on MIC when S=0.

- **Bit 5 (S): Signature present.** When set, the MIC field contains a
  cryptographic signature over the frame. See Section 4.

- **Bit 6 (E): Encrypted.** Signals that PLD is an opaque encrypted blob
  (typically an OSCORE-protected CoAP message). Does not imply link-layer
  encryption; the link layer does not perform encryption.

- **Bit 7 (R): Reserved.** Senders MUST set to 0. Receivers MUST discard
  frames with R=1.

### 3.3. Destination Address

When AddrMode is Extended (0b10), DST is an 8-byte EUI-64 in network byte
order.

When AddrMode is Short (0b01), DST is a 2-byte short address assigned by the
DODAG root or derived from the lower 16 bits of the link-local IPv6 address.

When AddrMode is None (0b00), the frame is a broadcast. All nodes MUST
process the payload, subject to replay protection.

When AddrMode is Elided (0b11), the destination is recoverable from context
(e.g. the first IPv6 destination address in the SCHC payload). This mode is
OPTIONAL and SHOULD be used only when the overhead reduction justifies the
decoding complexity.

### 3.4. Source Address

The frame format intentionally omits a source address field. The sender's
identity is established by:

1. The Schnorr signature in MIC (Section 4), whose verification key is the
   sender's public key.
2. The IPv6 source address in the SCHC-decompressed payload, which is
   link-local and derived from the sender's EUI-64.

## 4. Authentication

### 4.1. MIC Field

When S=1, the MIC field contains a truncated Schnorr signature as defined in
[draft-lichen-schnorr-00]. The signature is computed over:

```
signed_data = LENGTH || LLSec || EPO || SEQ || DST || PLD
```

(All fields before the MIC, in wire order, excluding the MIC itself.)

The signing key is the sender's long-term Ed25519 private key. The
corresponding public key is distributed via the LICHEN announce protocol or
pre-provisioned in the trust store.

### 4.2. Unsigned Frames

When S=0, the MIC field is absent (length is 0 regardless of MicLength).
Unsigned frames SHOULD be limited to:

- Bootstrap messages (before a node has announced its key)
- Simulator and test traffic
- Frames where the payload itself carries authentication (OSCORE)

Nodes SHOULD NOT accept routing-affecting messages (RPL DIO/DAO) from
unsigned frames unless the node is in a permissive mode.

### 4.3. Key Lookup

Receivers identify the signing key by the sender's link-local IPv6 address
extracted from the SCHC-decompressed payload. The key material is maintained
in a local trust store indexed by EUI-64. See the LICHEN security architecture
for trust establishment procedures.

## 5. Replay Protection

### 5.1. Replay Window

Each node MUST maintain a per-peer replay window. For each known peer, the
node tracks:

- The highest accepted EPO value.
- The highest accepted SEQ value within that EPO.
- A bitmask of recently accepted SEQ values (sliding window).

The minimum window size is 64 frames. Implementations SHOULD use at least a
128-bit window.

A frame MUST be discarded if:

1. EPO < highest accepted EPO for this peer (old epoch).
2. EPO == highest accepted EPO and SEQ falls outside the window or has
   already been accepted.

### 5.2. Epoch Transitions

When SEQ reaches 0xFFFF, the sender MUST increment EPO and reset SEQ to 0
before sending further frames. Receivers MUST accept EPO increments even
without a signed epoch-change notification.

When a node reboots, it SHOULD increment EPO to invalidate old sequence
numbers. Receivers MUST accept EPO values higher than previously seen,
within the range [previous_EPO, previous_EPO + 4]. Larger EPO jumps require
out-of-band trust re-establishment.

## 6. Examples

### 6.1. Broadcast RPL DIO (No Signature)

```
  LENGTH = 0x1A  (26 bytes body)
  LLSec  = 0x00  (AddrMode=None, MicLength=0, S=0, E=0)
  EPO    = 0x03
  SEQ    = 0x00, 0x2C
  DST    = (absent, AddrMode=None)
  PLD    = <26 - 4 bytes of SCHC-compressed RPL DIO>
  MIC    = (absent, S=0)
```

Total frame: 27 bytes.

### 6.2. Unicast CoAP Request (Extended Address, 32-bit MIC)

```
  LENGTH = 0x1D  (29 bytes body)
  LLSec  = 0x22  (AddrMode=Extended, MicLength=0b000→4B, S=1, E=0)
            = 0b0010_0010
  EPO    = 0x01
  SEQ    = 0x00, 0x01
  DST    = 8 bytes EUI-64
  PLD    = <29 - 4 - 8 - 4 = 13 bytes SCHC-compressed CoAP>
  MIC    = 4 bytes Schnorr signature truncation
```

Total frame: 30 bytes.

### 6.3. Unicast OSCORE-Encrypted CoAP (64-bit MIC)

```
  LLSec  = 0x63  = 0b0110_0011
            (AddrMode=Extended, MicLength=0b001→8B, S=1, E=1)
```

## 7. IANA Considerations

This document has no IANA actions.

## 8. Security Considerations

### 8.1. No Link-Layer Confidentiality

The link layer provides authentication (MIC/signature) but not
confidentiality. Payload privacy is provided by OSCORE (RFC 8613) at the
CoAP layer, indicated by E=1 in LLSec. Observers on the LoRa channel can
see frame headers (LENGTH, LLSec, EPO, SEQ, DST) even when E=1.

### 8.2. Replay Attack Resistance

The (EPO, SEQ) tuple and the replay window (Section 5) prevent frame
injection via replay. An attacker who captures an authenticated frame cannot
replay it because the SEQ will fall within the window.

### 8.3. Broadcast Spoofing

Broadcast frames with S=0 are unauthenticated. Implementations MUST NOT
take security-relevant actions (key installation, routing table modification)
based solely on unsigned broadcast frames.

### 8.4. Signature Scheme

The MIC is produced by the truncated Schnorr scheme defined in
[draft-lichen-schnorr-00], which provides 128-bit security against forgery.
See that draft for a full security analysis.

## 9. References

- RFC 2119: Key Words for Use in RFCs (Bradner, 1997)
- RFC 8200: Internet Protocol Version 6 (IPv6) Specification (Deering & Hinden, 2017)
- RFC 8724: SCHC: Generic Framework for Static Context Header Compression (Minaburo et al., 2020)
- RFC 8613: Object Security for Constrained RESTful Environments (OSCORE) (Selander et al., 2019)
- [draft-lichen-schnorr-00]: Schnorr Signatures with Truncated Challenge for Constrained Networks

## Authors

LICHEN Project
