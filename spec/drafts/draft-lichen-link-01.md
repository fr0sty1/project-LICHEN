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
5. Encryption signaling: carry the encrypted-payload flag for format
   compatibility. Encrypted link frames are not currently supported.

The LICHEN link layer does **not** provide a source address field. The sender's
identity is established by the signature (when present), and the IPv6 source
address in the SCHC payload provides the network-layer source. This keeps the
overhead minimal for the common case of authenticated unicast.

### 1.1. Design Goals

  - **Small overhead:** 5 bytes minimum header + optional address + optional MIC.
- **Replay-safe:** Epoch + sequence number support a sliding-window replay filter.
- **Flexible addressing:** Broadcast, 16-bit short, EUI-64, or address-elided modes.
- **Authentication required for RPL:** All RPL control frames (DIO/DAO via dispatch 0x15 or SCHC rule 3/4) MUST set S=1 (link-layer Schnorr signature present). Unsigned permitted only for pure bootstrap/discovery not affecting routing state.
  - **Encryption unsupported:** Frames with encrypted payloads are not part of
    the current interoperable profile.

The current interoperable profile does not support encrypted payloads. Frames
with E=1 MUST NOT be transmitted and receivers MUST discard them. In
particular, frames MUST NOT set both S=1 and E=1; signed encrypted frames are
unsupported and MUST be rejected before signature processing.

### 1.2. Use Case

LICHEN is deployed on LoRa networks (SF10/125 kHz/CR 4/5) with practical
MTUs of 50-250 bytes. At LoRa's data rates, every byte of overhead matters.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

- **Frame:** The complete unit of data transmitted on the LoRa channel.
- **Payload (PLD):** The authenticated dispatch octet followed by the body in
  the selected namespace: `0x14` plus a SCHC Packet, or `0x15` plus a LICHEN
  routing/control message.
- **MIC:** Message Integrity Code — the cryptographic authentication tag.
- **EUI-64:** The canonical 64-bit link identifier in a peer record. For a
  key-derived LICHEN signing identity, it is recovered from the key-derived
  IPv6 IID by toggling the RFC 4291 universal/local bit exactly once. A radio
  hardware identifier is not substituted for that signer EUI-64.
- **Epoch:** The high-order octet of the finite 24-bit replay counter.

## 3. Frame Format

### 3.1. Overall Structure

```
Octets: 1        1       1      2       var     8      var      var
       +--------+-------+------+-------+-------+------+--------+-----+
       | LENGTH | LLSec | EPO  | SEQ   |  DST  | SIID |  PLD   | MIC |
       +--------+-------+------+-------+-------+------+--------+-----+
```

- **LENGTH** (1 octet): Number of bytes in the frame body (everything after
  the LENGTH byte). The complete frame MUST NOT exceed 255 octets, so LENGTH
  MUST NOT exceed 254. Receivers MUST discard frames with LENGTH=255 or when
  LENGTH does not equal the received frame size minus the LENGTH byte. The maximum
  unsigned broadcast PLD is 250 octets (254 minus the 4-octet fixed header).

- **LLSec** (1 octet): Link-layer security flags. See Section 3.2.

- **EPO** (1 octet): High-order octet of the replay counter. Receivers use the
  (EPO, SEQ) tuple for replay detection. EPO does not wrap; exhausting EPO and
  SEQ requires link-key rotation.

- **SEQ** (2 octets, big-endian): Sequence number. Monotonically increasing
  within an epoch. Receivers MUST maintain one replay window per authenticated
  `(SignerPublicKey, KeyGeneration)` and MUST discard frames whose (EPO, SEQ)
  has already been accepted in that signer-generation domain.
  After 0xFFFF, the next tuple uses the next EPO and SEQ zero. See Section 5.2.

- **DST** (0, 2, or 8 octets): Destination address. Present and length
   determined by AddrMode in LLSec. See Section 3.3.

- **SIID** (8 octets, conditional): Signer Identifier. Present when the SI bit
   (LLSec bit 7) is set. Contains the canonical EUI-64 of the signing
   node. MUST be present when S=1. See Section 3.4.

- **PLD** (variable): authenticated inner payload. The first octet is a
  dispatch value: `0x14` for SCHC, whose body begins with the SCHC rule ID, or
  `0x15` for LICHEN routing/control messages, whose body begins with the
  routing message type. Length derived as
  `LENGTH - fixed_header_size - DST_len - MIC_len`. Link framing permits an
  empty PLD; a PLD using a currently defined dispatch value MUST be at least
  2 bytes.

- **MIC** (0 or 48 octets): Message Integrity Code. When S=0, the MIC is
   absent regardless of MicLength. When S=1, the MIC is the full 48-byte
   Schnorr signature and MicLength is ignored. See Section 4.

   Because LENGTH excludes its own octet, the fixed frame-body header used to
   derive PLD length is 4 octets (LLSec + EPO + SEQ), plus 8 octets when SI is
   set. Thus `PLD_LEN = LENGTH - 4 - DST_LEN - SIID_LEN - MIC_LEN`.

### 3.2. LLSec Byte

```
  Bit:  7   6   5   4   3   2   1   0
       +---+---+---+---+---+---+---+---+
       | SI| E | S |  MicLength  | AM  |
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

   | Value | MIC length when S=0 | Meaning                              |
   |-------|---------------------|--------------------------------------|
   | 0b000 | 0 bytes             | No MIC                               |
   | 0b001 | 0 bytes             | No MIC; compatibility selector      |
   | 0b010–0b111 | —          | Reserved. Receivers MUST discard.    |

   When the S bit is 1, the MIC is always 48 bytes regardless of MicLength.
   When the S bit is 0 (no signature present), no MIC bytes are present.
   MicLength is retained only as a header selector for compatibility and does
   not affect parsing or serialization.

- **Bit 5 (S): Signature present.** When set, the MIC field contains a
  cryptographic signature over the frame. See Section 4.

- **Bit 6 (E): Encrypted.** Indicates an encrypted payload. Encrypted link
  frames are unsupported in the current interoperable profile; senders MUST
  leave E clear and receivers MUST discard frames with E=1.

- **Bit 7 (SI): Signer Identifier present.** When set, an 8-byte Signer
   Identifier (SIID)
   field containing the sender's EUI-64 follows the DST field. Signed frames
   (S=1) MUST also set SI=1. Unsigned frames MUST set SI=0. Frames with SI=1
   and S=0 are invalid and MUST be discarded. Frames with S=1 and SI=0 are
   invalid and MUST be discarded.

### 3.3. Destination Address

When AddrMode is Extended (0b10), DST is an 8-byte EUI-64 in network byte
order.

When AddrMode is Short (0b01), DST is a 2-byte short address assigned by the
DODAG root or derived from the lower 16 bits of the link-local IPv6 address.

When AddrMode is None (0b00), the frame is a broadcast. All nodes MUST
process the payload, subject to replay protection.

When AddrMode is Elided (0b11), the destination is recoverable from context
(e.g. the first IPv6 destination address in the SCHC payload). No destination
bytes are present on the wire in this mode.

### 3.4. Signer Identifier

When the SI bit (LLSec bit 7) is set, an 8-byte Signer Identifier (SIID) field
follows DST on the wire. The SIID carries the canonical EUI-64 of the signing
node and enables the receiver to select a bounded candidate set instead of
trial-verifying every provisioned key.

For a key-derived signer, derive the IID from the complete signing public key
as specified by the LICHEN addressing profile, then toggle the IID's
universal/local bit exactly once to obtain the SIID EUI-64. Implementations
MUST NOT use a radio serial number or unrelated hardware address as that
signer's SIID. Because an EUI-64 is only a truncated lookup namespace, the
result remains an unauthenticated candidate-selection hint until verification
under the complete public key succeeds.

The frame format intentionally omits a general source address field. SIID never
establishes or authorizes any part of the sender identity; it only selects a
bounded set of candidate trust records. The immediate link identity is
established solely by successful Schnorr verification under one current full
public key and opaque trust-store key generation (Section 4). SIID collisions
MUST retain every current candidate, and a receiver that cannot retain the
complete bounded collision set MUST fail closed. An IPv6 source address in the
payload identifies the end-to-end network-layer origin and MUST NOT be used as
the immediate signer identity. Replay, trust, routing, and fragmentation state
MUST NOT be keyed or authorized by SIID.

Signed frames (S=1) MUST set SI=1 and MUST carry a valid signer EUI-64. Unsigned
frames MUST set SI=0. Receivers MUST treat any frame with S=1 and SI=0, or S=0
and SI=1, as invalid and MUST discard it.

## 4. Authentication

### 4.1. MIC Field

When S=1, the MIC field contains the full 48-byte Schnorr signature as defined in
[draft-lichen-schnorr-00]. The signature is computed over:

```
signed_data = "LICHEN-LINK-v1" || 0x00 || LENGTH || LLSec || EPO || SEQ
              || DST_LEN(1) || DST || SIID(8) || PLD
```

The fixed 15-octet domain is hexadecimal
`4c494348454e2d4c494e4b2d763100`. It separates link signatures from all other
Schnorr-48 application profiles. DST_LEN separately delimits the variable-length
DST field; SIID is the 8-byte signer EUI-64, present only when SI=1; all wire
fields before the MIC remain in wire order and MIC itself is excluded.

Link Signature Domain Version 1 verifiers MUST reject legacy unprefixed link
transcripts and every other application domain. Rule Set Version 3 deployments
use this transcript. A different prefix requires a coordinated protocol-version
upgrade; implementations MUST NOT enable dual legacy/version-1 acceptance as a
fallback.

The signing key is the sender's long-term Ed25519 private key. The
corresponding public key is distributed via the LICHEN announce protocol or
pre-provisioned in the trust store.

### 4.2. Unsigned Frames

When S=0, the MIC field is absent (length is 0 regardless of MicLength).
Unsigned frames SHOULD be limited to:

- Bootstrap messages (before a node has announced its key)
- Simulator and test traffic (non-production only)
- Frames where the payload itself carries authentication (OSCORE)

**RPL Control Requirement:** All RPL control messages (DIO, DAO, DIS; ICMPv6 type 155 after SCHC decompression) MUST be sent with S=1 and valid Schnorr signature. Receivers MUST reject unsigned RPL control frames before any routing state mutation. Permissive mode for unsigned routing-affecting frames is limited exclusively to development simulators and test harnesses; it MUST NOT be enabled in production nodes. This reconciles the link-layer and security specifications (see spec/06-security.md:8.10).

### 4.3. Key Lookup

Receivers MUST authenticate a frame before SCHC decompression or fragment
reassembly. SIID selects only a bounded candidate set from the local trust
store; collisions MUST retain every current candidate in that set. A receiver
identifies the signer by testing candidate complete public keys that are valid
for the incoming radio/neighbor context. Implementations MAY use authenticated
neighbor metadata to narrow that set. Successful verification returns both
the complete signer public key and the opaque current key-generation token
issued by the trust-store owner. Replay and SCHC fragmentation state use that
tuple, never SIID, an EUI-64, or another address alias. Key selection MUST NOT
depend on an IPv6 source address inside the protected payload.

## 5. Replay Protection

### 5.1. Replay Window

Each node MUST maintain a replay window per `(SignerPublicKey,
KeyGeneration)`. For each current authenticated signer generation, the
node tracks:

- The highest accepted EPO value.
- The highest accepted SEQ value within that EPO.
- A bitmask of recently accepted SEQ values (sliding window).

The replay window size is 32 frames. Retiring a key generation immediately
makes its frames and replay state unusable; installing a replacement creates a
distinct replay domain even if an address alias is unchanged.

EPO and SEQ form the finite unsigned integer
`counter = (EPO << 16) | SEQ`, ranging from 0x000000 through 0xFFFFFF.
Implementations MUST compare counters using ordinary unsigned integer ordering
and MUST NOT use serial-number or modulo arithmetic. Replay state is scoped to
the peer's authenticated link key.

A frame MUST be discarded if:

1. EPO < highest accepted EPO for this signer generation (old epoch).
2. EPO == highest accepted EPO and SEQ falls outside the window or has
   already been accepted.

A lower EPO MUST always be rejected. When EPO is unchanged, a decrease from a
high SEQ to a low SEQ is stale or outside the replay window and MUST NOT be
accepted as sequence-number wrap.

### 5.2. Epoch Transitions

When SEQ reaches 0xFFFF, the sender MUST increment EPO and use SEQ zero for
the next frame. Receivers apply ordinary numeric ordering to that next tuple;
no separate epoch-change notification is required.

EPO MUST NOT wrap from 0xFF to 0x00. After sending the terminal tuple
`(EPO=0xFF, SEQ=0xFFFF)`, the sender MUST rotate its link key before sending
another authenticated frame. A receiver MUST reject `(0x00, 0x0000)` and all
other lower tuples under the exhausted key. After authenticating a new link
key according to the LICHEN security architecture, the receiver MUST create
fresh replay state for that key.

On reboot, a node SHOULD resume above its last used counter, for example by
incrementing EPO and restarting SEQ at zero. If no persisted counter is
available, a random initial EPO reduces accidental tuple reuse but does not
establish freshness: receivers retaining state for the same key apply the
normal numeric rules and may reject it. The node MUST rotate its link key if
it cannot establish an unused greater tuple under the existing key.

## 6. Examples

### 6.1. Broadcast RPL DIO (Signed)

```
  LENGTH = 0x85  (133-byte body)
  LLSec  = 0xA0  (AddrMode=None, MicLength=0, S=1, E=0, SI=1)
  EPO    = 0x03
  SEQ    = 0x00, 0x2C
  DST    = (absent, AddrMode=None)
  SIID   = 8 bytes signer EUI-64
  PLD    = 73 bytes: dispatch 0x14 + Rule ID 0xff + complete 71-byte
           IPv6/ICMPv6/DIO packet ending in Rule-Version option 13 01 03
  MIC    = 48-byte Schnorr signature
```

Body arithmetic: 4 fixed + 8 SIID + 73 PLD + 48 MIC = 133 bytes.
`LENGTH` is 0x85 and the total frame is 134 bytes. Rule 3 cannot represent the
`ff02::1a` multicast destination; Rule Set Version 3 uses validated Rule 255 for
this canonical DIO. RPL control frames MUST use S=1 per section 4.2.

### 6.2. Unicast CoAP Request (Extended Address, signed)

```
  LENGTH = 0x63  (99 bytes body)
  LLSec  = 0xA2  (AddrMode=Extended, S=1, E=0, SI=1; MIC is 48B)
            = 0b1010_0010
  EPO    = 0x01
  SEQ    = 0x00, 0x01
  DST    = 8 bytes EUI-64
  SIID   = 8 bytes signer EUI-64
  PLD    = 31 bytes: dispatch 0x14 followed by the exact 30-byte
           `coap_linklocal` SCHC Packet from test/vectors/schc_compression.json:
           14 00400000000000000001000000000000000233000448d0ff737461747573
  MIC    = 48-byte Schnorr signature
```

  Body arithmetic: 4 fixed + 8 DST + 8 SIID + 31 PLD + 48 MIC = 99 bytes.
  The body LENGTH includes the 48-byte MIC; the complete frame is 100 bytes.

### 6.3. Encrypted Frame (Unsupported)

```
  LLSec  = 0xE2  = 0b1110_0010
            (AddrMode=Extended, MicLength=0b000, S=1, E=1, SI=1)
  Result: rejected; signed encrypted frames are unsupported.
```

## 7. IANA Considerations

This document has no IANA actions.

## 8. Security Considerations

### 8.1. No Link-Layer Confidentiality

The link layer provides authentication (the 48-byte Schnorr signature) but not
confidentiality. Payload privacy may be provided by OSCORE (RFC 8613) at the
CoAP layer, but encrypted link frames with E=1 are outside the current
interoperable profile and MUST be discarded.

### 8.2. Replay Attack Resistance

The (EPO, SEQ) tuple and the replay window (Section 5) prevent frame
injection via replay. An attacker who captures an authenticated frame cannot
replay it because the SEQ will fall within the window.

### 8.3. Broadcast Spoofing and RPL Control

Broadcast frames with S=0 are unauthenticated. Implementations MUST reject unsigned RPL control messages (DIO/DAO/DIS) and MUST NOT perform routing table modifications based on them. See section 4.2 for normative receiver behavior. Permissive mode is test-only.

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
