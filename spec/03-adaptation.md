<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Adaptation Layer

## 5. Adaptation Layer

### 5.1. Design Choice: SCHC, Not 6LoWPAN IPHC

Traditional 6LoWPAN (RFC 4944, 6282) was designed for IEEE 802.15.4 networks.
LICHEN uses **SCHC (RFC 8724) instead** because:

| Aspect | 6LoWPAN IPHC | SCHC |
|--------|--------------|------|
| Designed for | 802.15.4 | **LPWAN (LoRa, Sigfox, NB-IoT)** |
| Compression | Fixed encoding | **Flexible rules** |
| Fragmentation | Tied to 802.15.4 | **LPWAN-optimized (ACK-on-Error)** |
| CoAP compression | Separate (RFC 8824) | **Integrated** |
| MTU assumption | 127 bytes | **Variable** |

**LICHEN stack (no 802.15.4):**

```
┌─────────────────────────────────┐
│  IPv6 / UDP / ICMPv6 / CoAP    │
├─────────────────────────────────┤
│  SCHC (RFC 8724)               │
│  - Compression (replaces IPHC) │
│  - Fragmentation               │
├─────────────────────────────────┤
│  LICHEN Link Layer             │
│  - Custom framing              │
│  - Schnorr signatures          │
├─────────────────────────────────┤
│  LoRa PHY                      │
└─────────────────────────────────┘
```

**Zephyr integration:** Requires custom L2 driver or network interface.
Cannot use `CONFIG_NET_L2_IEEE802154`.

### 5.2. SCHC Overview (RFC 8724)

Static Context Header Compression uses pre-shared "rules" to compress
headers. Both sender and receiver store identical rule sets; packets
carry only a Rule ID and residue (changed fields).

### 5.3. Compression Gains

The Version 3 fixed-header byte counts, excluding the unchanged option or
application tail, are:

| Rule and base headers | Uncompressed base | SCHC fixed header |
|-----------------------|-------------------|-------------------|
| Rule 0: link-local IPv6 + UDP + CoAP | 52 bytes | 23 bytes |
| Rule 1: Yggdrasil IPv6 + UDP + CoAP | 52 bytes | 37 bytes |
| Rule 3: link-local IPv6 + ICMPv6 + DIO | 68 bytes | 40 bytes |
| Rule 4: link-local IPv6 + ICMPv6 + DAO with DODAGID | 64 bytes | 37 bytes |

### 5.4. Rule Structure

Each rule specifies, for each header field:
- **TV (Target Value):** Expected value
- **MO (Matching Operator):** equal, ignore, MSB(n), etc.
- **CDA (Compression/Decompression Action):** not-sent, value-sent, LSB(n), etc.

### 5.5. Rule Registry

The canonical Version 3 wire rules are defined in `spec/appendix-schc.md`.
Generic FieldDescriptor rules 0 through 6 and 255 are registered in
`rust/lichen-schc/src/rules.rs` and `python/src/lichen/schc/rules.py`.  Rule 7
has the specialized, variable-layout residue defined below and is implemented
only by `rust/lichen-schc/src/codec.rs` and
`python/src/lichen/schc/headers.py`; it is intentionally absent from the
generic descriptor registries while remaining a canonical Version 3 wire Rule
ID.  The Rule objects numbered 64, 65, and 66 in the Python rules module are
reusable CoAP, UDP-port, and ICMPv6-Echo descriptor building blocks only.  They
are not wire Rule IDs, are not selectable by a default context, and MUST be
rejected as unknown if received as a packet's Rule ID.

**Summary of key rules (see appendix for TV/MO/CDA tables):**
- Rule 0: Link-local IPv6+UDP+CoAP (23-byte fixed compressed header;
  `fe80::/64` MSB match and two 64-bit LSBs)
- Rule 1: Yggdrasil IPv6+UDP+CoAP (37-byte fixed compressed header;
  `0200::/8` MSB match and two 120-bit LSBs)
- Rule 2: ICMPv6 Echo (23-byte fixed compressed header)
- Rule 3: Link-local RPL DIO (40-byte fixed compressed header)
- Rule 4: Link-local RPL DAO with DODAGID (37-byte fixed compressed header)
- Rules 5/6: OSCORE-protected CoAP variants
- Rule 7: MQTT-SN
- Rule 255: Uncompressed fallback (MUST implement)

Port compression uses MSB(12)/LSB(4) for CoAP range 5680-5695 in Rules 0/1
(covers CoAP, SenML, etc.; see port allocation in 09-packets-timing.md or
applications). Hop Limit is value-sent. Rule 0 matches `fe80::/64` and sends
each 64-bit IID; Rule 1 matches `0200::/8` and sends the remaining 120 bits of
each address. MQTT-SN (Rule 7, port 10883 exact) and full CDA tables are in
`appendix-schc.md` Sections A.1 through A.3.

**Rule 3/4: RPL DIO/DAO over link-local ICMPv6 (RFC 6550)**

Rule 3 for DIO (code=1), Rule 4 for DAO with D=1 (kd_flags bit 6 set, DODAGID present; common non-storing case). DAOs without DODAGID fall back to Rule 255. kd_flags byte: bit7=K (ACK req), bit6=D, lower bits flags. Matches Python `_DAO_BASE_FIELDS` in `python/src/lichen/schc/headers.py` and the Rust `RPL_DAO_RULE` registry and codec in `rust/lichen-schc/src/rules.rs`.

Both rules match source and destination addresses in `fe80::/64` and carry the
two 64-bit IIDs. Rule 3 therefore does not match the canonical RPL multicast
destination `ff02::1a`; multicast DIOs MUST use fully validated Rule 255 in Rule
Set Version 3. A decoder MUST NOT reinterpret that multicast address as
`fe80::1a`. Rule 4 does not match a ULA, Yggdrasil, or other routable source
address.

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6 (link-local as Rule 0) | ... | ... | ... |
| ICMPv6.type | 155 | equal | not-sent |
| ICMPv6.code | 1/2 | equal | not-sent |
| ICMPv6.checksum | - | ignore | compute |
| RPL.instance | - | ignore | value-sent |
| RPL.kd_flags | - | ignore | value-sent |
| RPL.reserved | 0 | equal | not-sent |
| RPL.seq (or dtsn/gmop/rank for DIO) | - | ignore | value-sent |
| RPL.dodagid | - | ignore | value-sent |

Rule 3 has a 40-byte fixed compressed header: the one-byte Rule ID followed by
a 39-byte residue. Rule 4 has a 37-byte fixed compressed header: the one-byte
Rule ID followed by a 36-byte residue. In both rules, every RPL option octet
after the DIO or DAO base object is appended verbatim. Version 3 does not apply
`MATCH_MAPPING` or any other compression to RPL options. In particular, the
Prefix Information Option is RPL Option Type 8, and its complete TLV remains
verbatim, as do state-carrying Target and Transit Information options.

**Version 3 Rules 1 and 6: Yggdrasil IPv6 + UDP + CoAP/OSCORE**

Both source and destination addresses use MSB(8)/LSB(120) against the canonical
LICHEN Yggdrasil `0200::/8` prefix. The remaining 120 address bits travel in the
residue. There is no provisioned ULA or arbitrary mesh `/64` context.

| Field | TV | MO | CDA |
|-------|----|----|-----|
| IPv6.SrcAddr | 0200::/8 | MSB(8) | LSB(120) |
| IPv6.DstAddr | 0200::/8 | MSB(8) | LSB(120) |
| (other fields as Rule 0) | | | |

**Compressed size: 37-byte fixed compressed header** (Rule ID plus 286-bit
residue padded to 36 bytes), excluding the CoAP token, options, and payload
tail.

**Rule 7: IPv6 + UDP + MQTT-SN (port 10883)**

MQTT-SN uses port 10883, outside the CoAP range compressed by Rules 0/1.
Rule 7 matches a UDP packet when at least one endpoint port is 10883. The
compressor MUST carry the other endpoint port; it MUST NOT assume that both
ports are 10883.

Before selecting Rule 7, the compressor MUST verify all fields that the rule
elides or recomputes:

| Input field | Rule 7 match requirement |
|-------------|--------------------------|
| IPv6 Version | 6 |
| IPv6 Traffic Class | 0 |
| IPv6 Flow Label | 0 |
| IPv6 Next Header | 17 (UDP) |
| IPv6 Payload Length | Exactly the available UDP datagram length |
| UDP Source/Destination Port | At least one is 10883 |
| UDP Length | At least 8 and exactly the available UDP datagram length |
| UDP Checksum | Nonzero and valid for the IPv6 pseudo-header and UDP datagram |

The IPv6 addresses MUST also satisfy this profile's exact address policy:

- A source MUST be a usable unicast address. `::`, `::1`, `ff00::/8`, and
  IPv4-mapped `::ffff:0:0/96` sources are invalid.
- A destination MUST NOT be `::`, `::1`, or IPv4-mapped. Unicast destinations
  are valid. Multicast destinations are valid only with a non-reserved scope of
  2 through 14; interface-local scope 1 and reserved scopes 0 and 15 are
  invalid on a transmitted LICHEN link.
- Canonical `fe80::/64` addresses use AddressMode=0 only when both endpoints
  are in that prefix. Other valid link-local addresses are scoped IPv6
  addresses and use full AddressMode=1; a zone/interface identifier is local
  metadata and is never serialized in the SCHC residue.

A packet that fails a structural or checksum requirement MUST be dropped. A
well-formed packet that fails only a Rule 7 matching requirement MUST use
another matching rule or Rule 255; the compressor MUST NOT normalize it into a
different packet by selecting Rule 7.

Rule 7 uses the following residue, packed most-significant bit first:

| Residue field | Width | Encoding |
|---------------|-------|----------|
| IPv6.HopLimit | 8 bits | Value sent |
| AddressMode | 1 bit | 0 only when both addresses are in canonical `fe80::/64`; 1 otherwise |
| IPv6.SrcAddr | 64 or 128 bits | IID only when AddressMode=0; full address when AddressMode=1 |
| IPv6.DstAddr | 64 or 128 bits | IID only when AddressMode=0; full address when AddressMode=1 |
| PortDirection | 1 bit | 0 when source port is 10883; 1 when destination port is 10883 |
| OtherPort | 16 bits | Destination port when PortDirection=0; source port when PortDirection=1 |

When both addresses are in `fe80::/64`, the compressor MUST set AddressMode=0
and send only their 64-bit IIDs. Otherwise it MUST set AddressMode=1 and send
both complete 128-bit addresses; Rule 7 does not apply prefix compression in
that mode. When both UDP ports are 10883, the canonical encoding MUST use
PortDirection=0 and OtherPort=10883. IPv6 payload length, UDP length, and UDP
checksum are computed during decompression. The MQTT-SN payload follows the
octet-padded residue unchanged. This section is the normative Rule 7 residue
definition; `rust/lichen-schc/src/codec.rs` implements it. The abbreviated
Rule 7 registry entry in `draft-lichen-schc-lora-00.md` Section 4 does not
define the residue layout.

A decoder MUST reject a Rule 7 residue if either decoded address violates the
address policy above, if AddressMode=1 but both decoded addresses are in the
canonical `fe80::/64` prefix, if PortDirection=1 and OtherPort=10883, or if any
final residue-padding bit is nonzero. These checks make the wire representation
unique. After reconstruction, the decoder MUST validate the IPv6 and UDP
lengths, recompute the UDP checksum, and install it before delivering the
packet. A computed one's-complement value of zero MUST be
serialized as `0xffff`, as required for UDP over IPv6; `0x0000` is never a
canonical Rule 7 checksum. The compressor validates the checksum present in the
input packet before eliding it; the decoder does not attempt to compare against
that elided value.

**Compressed size:** 21 bytes for two link-local addresses or 37 bytes for
full addresses, including the one-byte Rule ID and final residue padding but
excluding the MQTT-SN payload.

**Port Compression Note:**

Rules 0 and 1 use MSB(12)/LSB(4) matching on port 5683, compressing any port
in the range 5680-5695 to a 4-bit residue. This range covers CoAP (5683),
compact CoT (5681), SenML (5682), Cayenne LPP (5685), APRS-IS (5686), and
NMEA (5687). See Section 9.1 for the complete port allocation.

### 5.6. Fragmentation

Packets exceeding L2 MTU are fragmented using the fixed ACK-on-Error profile
defined in Section 5 of `draft-lichen-schc-lora-00`:

The compression sublayer MUST zero-pad its compressed header through the next
octet boundary before the byte-aligned payload, so fragmentation always receives
an octet-aligned SCHC Packet.

**Fragment Header:**
```
+--------+---+--------+----------------------+---------+
| RuleID | W |  FCN   | RCS and/or tile bits | Padding |
+--------+---+--------+----------------------+---------+
   8 bit  1b   6 bit        variable           variable
```

- **Rule IDs:** 0x78 canonical endpoint A-to-B data, 0x79 B-to-A data
- **W:** absolute window 0 or 1; no wrapping within a packet
- **FCN:** regular tile indices 62 down to 0; 63 is All-1
- **WINDOW_SIZE:** 63 tiles; maximum 126 tiles across two windows
- **Tile size:** 179 bytes, except the non-empty final tile may be shorter
- **RCS:** CRC-32/ISO-HDLC, carried before the final tile in All-1
- **Packing:** MSB-first, bit-contiguous, with zero padding only at message end

For each authenticated peer pair, endpoint A is the endpoint whose canonical
32-byte link-signing public key is lexicographically smaller when the keys are
compared as unsigned octet strings; endpoint B has the larger key. Equal keys
do not identify a peer pair and MUST be rejected. Data fragments, ACK REQ, and
Sender-Abort use Rule 0x78 when sent by A and Rule 0x79 when sent by B. ACK and
Receiver-Abort travel in the reverse link direction but retain the Rule ID of
the data transfer they control. Implementations MUST derive and validate this
direction from the authenticated local and remote full signer identities; an
EUI-64, untrusted address, or caller-selected default Rule ID is not sufficient.

The receiver sends no ACK for All-0. It MUST respond to All-1 or ACK REQ with
C=1 after successful whole-packet verification, or C=0 plus the RFC 8724
compressed received-tile bitmap. Bitmap 1 means received and 0 means missing.
Because a two-octet ACK REQ can be bit-identical to a compressed C=0 ACK, an
implementation MUST classify it from the authenticated sender role and the
directional Rule ID before invoking an ACK decoder or mutating sender state.
The initial All-1 plus at most three later All-1 or ACK REQ request emissions
gives MAX_ACK_REQUESTS=4. Attempts counts state-machine output generation; the
link layer separately reports whether those bytes were transmitted by radio.
The receiver independently counts the ACK responses it generates for a
session. It emits at most four ACK responses; when a fifth otherwise-valid
All-1 or ACK REQ would require another ACK, it sends Receiver-Abort instead and
enters the terminal hold-down described below.

Receivers MUST support 1281-byte SCHC Packets, allowing a 1280-byte IPv6 packet
plus the uncompressed fallback Rule ID. Larger buffers are optional up to the
22,554-byte encoded SCHC Packet profile ceiling. The Rule ID counts toward that
ceiling: Rule 255 carries at most 22,553 bytes of raw IPv6, while a compressible
raw IPv6 packet may be larger when its final encoded SCHC Packet remains at
most 22,554 bytes. In RFC 8724, T is the bit width of the DTag
(Datagram Tag), which distinguishes concurrent SCHC Packets using the same
fragmentation Rule ID between the same endpoints. LICHEN fixes T=0, so the
DTag field is absent and has only one possible value. Consequently, a sender
MUST NOT have more than one fragmented SCHC Packet active for the same
authenticated link identities and directional fragmentation Rule ID (0x78 or
0x79).

The reassembly context key is the ordered tuple `(local_identity,
remote_signer_identity, remote_key_generation, fragmentation_rule_id)`. A
generation is the opaque current token issued by the authority that owns the
remote trust record. `local_identity` is the receiver's full local link-signing
public key. An implementation that supports live replacement of that local key
MUST additionally bind its opaque current `local_key_generation`; a fixed-local-key
owner MAY persist state under the full local public key because changing
that key creates a new owner and invalidates all live capabilities.
`remote_signer_identity` is the full peer identity whose signature was
successfully verified for the fragment; an
untrusted address, EUI-64, interface index, or caller-supplied opaque value is
not a substitute. Implementations MUST authenticate a fragment and pass link
replay protection before it can allocate, reset, abort, or otherwise mutate a
fragmentation context. Before every context mutation or control response, the
receiver MUST revalidate that every applicable generation token is current. Revocation or
replacement atomically invalidates every active context, tombstone, cached
response, and admission floor in the retired generation, even when the same
public key is reinstalled. They MUST bound the number of contexts per remote signer
and globally. On authenticated allocation exhaustion, the receiver sends one
Receiver-Abort for the rejected key and MUST NOT evict or mutate an active
authenticated context. An unauthenticated fragment is silently dropped and
MUST NOT cause a control response.

Each accepted fragment also carries its authenticated unsigned 24-bit link
replay counter (Epoch followed by SeqNum). A context tracks the greatest counter
accepted anywhere in the session using the ordinary unsigned ordering required
by the link layer; this comparison does not wrap.
An authenticated fragment that repeats an already stored tile coordinate with
identical tile bytes is a duplicate, not evidence of a new packet. The receiver
MUST discard it idempotently without clearing, replacing, or resetting any
stored tile. It MUST still advance the session-wide high-water counter to the
fresh authenticated link counter. A repeated coordinate with different tile
bytes is not an idempotent duplicate and MUST fail closed; it MUST NOT reset the
context into an attacker-selected partial packet.
After successful completion or an authenticated Sender-Abort/Receiver-Abort,
the receiver MUST retain a terminal tombstone containing that session-wide
high-water counter, the terminal outcome, and the final ACK when applicable.
For 60 seconds (the fragmentation inactivity interval), a repeated authenticated
All-1 or ACK REQ with a strictly newer counter receives the same terminal ACK or
abort idempotently; it does not start a session. Every authenticated late data
or control message in the same current generation advances the tombstone
high-water when its counter is greater, including discarded Regular and All-1
messages. This covers the four 10-second ACK attempts plus propagation margin
when a terminal response is lost.

After the 60-second response hold-down, the generation-scoped high-water remains
as a bounded durable admission floor. Only the canonical first Regular Fragment
(`W=0`, `FCN=62`) with a counter strictly greater than that floor can start the
next session. All-1 never opens a session: a one-tile packet fits the
unfragmented profile and MUST be sent without fragmentation. The opening
counter becomes an immutable session-admission floor; every subsequently
accepted fragment or control MUST have a strictly greater counter. ACK REQ,
Sender-Abort, Receiver-Abort, All-1, and any other Regular FCN never create a
session. A context that expires without a terminal exchange enters the same
60-second hold-down with its session-wide high-water counter but no cached
success ACK. Late fragments MUST NOT create or contaminate the next session.
Tombstones, floors, and hold-down records are bounded state and are persisted
with the authenticated trust/replay transaction. Link-key rotation invalidates
all such state for the old signer generation; a counter at
`0xffffff` cannot be reused or wrapped under the same key.

The fixed M=1 window field and N=6 FCN field identify positions within one
such session and do not provide concurrency identity. Fragmentation is
hop-by-hop; routers reassemble and decompress before IPv6 forwarding.

### 5.7. Rule Versioning and Interoperability

SCHC requires identical rule sets on sender and receiver. To ensure
interoperability across firmware versions:

**Rule Set Version:**

Each LICHEN release defines a rule set version (8-bit unsigned integer).
Version increments when rules are added, removed, or modified.

| Version | Description |
|---------|-------------|
| 0 | Reserved; never an operational registry |
| 1 | Legacy experimental fragmentation formats; not interoperable |
| 2 | RFC 8724 fragmentation profile defined in Section 5.6 |
| 3 | Canonical specialized Rule 7 MQTT-SN residue defined above |
| 4+ | Future versions |

**DIO Rule Version Option (project-local provisional Type `0x13`):** This
value is reserved by the LICHEN RPL option registry in
`09-packets-timing.md`; it is not an IANA assignment. Implementations MUST NOT
use `0x13` for another RPL option.

Every node that emits a DIO usable for parent selection or DODAG admission MUST
advertise the DODAG's rule set version. The root originates the version and
non-root routers propagate that same value in every such DIO. A serializer MUST
emit exactly one canonical Rule Version Option. A root serializer MAY insert
its current immutable version when the caller supplies no option. A non-root
serializer for a parent-selectable DIO MUST require the authenticated
root-originated DODAG version as input and preserve it byte-for-byte; it MUST
NOT silently substitute its current local version when that input is absent.
When the caller supplies one option, the serializer preserves it so legacy or
mismatched advertisements remain detectable by receivers. It MUST reject
duplicate version options rather than silently choosing one:

```
+--------+--------+--------+
| Type   | Length | Version|
+--------+--------+--------+
   1B       1B       1B
```

The option is exactly three octets; a parser that does not return a consumed
length MUST reject trailing bytes. A node MUST process it only after the DIO's
link signature and replay counter have been verified. Version 3 is the only
operational registry in this specification. A node MUST NOT join a DODAG when
the option is absent, malformed, reserved, unsupported, or differs from its
local immutable registry. These checks apply equally to root and non-root
candidate-parent DIOs; accepting an optionless non-root DIO is not a valid
multi-hop fallback.

**Fallback Rule (Rule ID 255): No Compression**

Rule 255 is reserved for uncompressed packets. All implementations MUST
support its syntax regardless of version, but policy MUST still reject its use
inside an incompatible DODAG. Its payload MUST be a complete,
structurally valid IPv6 packet: version 6, exact Payload Length, no IPv6
Fragment header, and, for UDP, exact UDP Length plus a nonzero valid checksum.

```
Rule 255 packet:
+----------+-----------------+
| RuleID   | Full IPv6 packet|
| (1 byte) | (40+ bytes)     |
+----------+-----------------+
```

**When a sender may select Rule 255:**
- No mutually supported compression rule for a valid IPv6 packet
- Compression-rule version mismatch only outside the incompatible DODAG, when
  the authenticated peer registry is known and the packet fits one link frame
- Debugging / diagnostics
- Communicating unfragmented packets with explicitly configured legacy peers
  outside an operational Version 3 DODAG

Rule 255 does not provide fragmentation compatibility. If the Rule 255 SCHC
Packet exceeds one link frame, both peers MUST support the same fragmentation
Rule Set Version or the packet cannot be sent.

**Decompression Failure Handling:**

| Scenario | Action |
|----------|--------|
| Unknown Rule ID | Drop packet, log warning |
| Decompression produces invalid IPv6 | Drop packet, log warning |
| Repeated failures from same source | Assume version mismatch, notify operator |

Production decompression ingress MUST maintain a bounded consecutive-failure
tracker keyed by the authenticated link signer. Unknown rules, truncated or
non-canonical residues, and invalid decompressed packets increment that signer;
an output-buffer or transport failure does not. A successfully validated
decompression clears only that signer. The configured threshold emits exactly
one notification per consecutive run. When the tracker is full, an ingress
MUST fail closed for a previously untracked signer and MUST NOT evict an
existing run; this deterministic no-eviction policy is shared by all
implementations.

**Version Negotiation:**

Explicit version negotiation is NOT required. The DIO advertisement
provides passive discovery. Nodes with mismatched versions:
1. Cannot join the same DODAG (DIO filter)
2. Can communicate a validated single-frame packet via sender-selected Rule 255 outside that DODAG
3. Should be upgraded to matching firmware

A receiver MUST drop an unknown Rule ID. It MUST NOT reinterpret the unknown
residue as IPv6 or wrap it in Rule 255 after decompression fails.

**Backward Compatibility:**

When updating firmware:
1. New rules SHOULD be added with new Rule IDs (don't reuse)
2. An implementation MAY retain an old registry for offline decoding,
   diagnostics, or an explicitly configured legacy link outside an operational
   DODAG. Merely retaining it MUST NOT make that registry operational, satisfy
   DODAG admission, enable fragmentation, or permit compressed traffic under a
   Version 3 peer context.
3. Version number MUST increment on any rule change

Every DIO that is usable for parent selection, whether emitted by a root or a
non-root router, carries exactly one authenticated Rule Version Option. A
non-root MUST propagate the root-originated DODAG version unchanged; it MUST
NOT replace an unsupported value with its local version or omit the option to
create a legacy fallback. DIOs not usable for parent selection MAY be retained
for diagnostics but MUST NOT create or refresh an operational SCHC context.

---

[← Previous: Physical and Link Layers](02-physical-link.md) | [Index](README.md) | [Next: Network Layer →](04-network.md)
