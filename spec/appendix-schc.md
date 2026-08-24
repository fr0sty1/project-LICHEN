<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Appendix A: SCHC Compression Rules

See draft-lichen-schc-lora-00.md §4 for rules, §5 for fragmentation (M=1 N=6 T=0, RCS=CRC32, timers, bitmap MSB-first) from constants.toml and test/vectors/. Full table is canonical here.

| Rule ID | Use Case | Compressed Size | Notes |
|---------|----------|-----------------|-------|
| 0 | Link-local IPv6 + UDP + CoAP | 23-byte fixed header | 22-byte padded residue + Rule ID, then CoAP tail |
| 1 | Yggdrasil IPv6 + UDP + CoAP | 37-byte fixed header | 36-byte padded residue + Rule ID, then CoAP tail; `0200::/8` MSB, 120-bit LSB each |
| 2 | ICMPv6 Echo | 23-byte fixed header | 22-byte residue + Rule ID; echo payload follows verbatim |
| 3 | RPL DIO (link-local unicast) | 40-byte fixed header | Both endpoints MUST be `fe80::/64`; 39-byte residue + Rule ID; options follow verbatim |
| 4 | RPL DAO with DODAGID (link-local) | 37-byte fixed header | 36-byte residue + Rule ID; ICMPv6 type=155/code=2; options follow verbatim |
| 5 | Link-local IPv6 + UDP + OSCORE | 23-byte fixed header | Same residue as Rule 0, then OSCORE tail |
| 6 | Yggdrasil IPv6 + UDP + OSCORE | 37-byte fixed header | Same residue as Rule 1, then OSCORE tail; `0200::/8` MSB |
| 7 | MQTT-SN (port 10883) | 21 or 37 bytes | Canonical specialized residue; Rule Set Version 3 |
| 255 | No compression | Full headers | Sender-selected validated IPv6 fallback |

Current constants (Rust/C synchronized):

| Rule ID | Name | Use Case |
|---------|------|----------|
| 0 | LINK_LOCAL_COAP | Link-local IPv6 + UDP + CoAP |
| 1 | GLOBAL_COAP | Global IPv6 + UDP + CoAP |
| 2 | ICMPV6_ECHO | ICMPv6 Echo Request/Reply |
| 3 | RPL_DIO | RPL DIO over link-local ICMPv6 |
| 4 | RPL_DAO | RPL DAO with DODAGID over link-local ICMPv6 |
| 5 | LINK_LOCAL_OSCORE | Link-local IPv6 + UDP + OSCORE-protected CoAP |
| 6 | GLOBAL_OSCORE | Global IPv6 + UDP + OSCORE-protected CoAP |
| 7 | MQTT_SN | IPv6 + UDP + MQTT-SN (port 10883) |
| 255 | UNCOMPRESSED | No compression (full headers passthrough) |

### A.1. Rule 7 MQTT-SN Residue

Rule 7 uses the specialized Version 3 residue defined normatively in
`03-adaptation.md` Section 5.5: Hop Limit, AddressMode, either two `fe80::/64`
IIDs or two full IPv6 addresses, PortDirection, and OtherPort, followed by zero
octet-padding and the unchanged MQTT-SN payload. Its total fixed compressed
header is 21 bytes in canonical link-local mode or 37 bytes in full-address
mode, including the Rule ID and excluding the payload tail. The compressor
validates all elided IPv6/UDP fields and checksum; the decoder rejects alternate
address/direction modes, nonzero padding, and packets beyond the profile bound,
then recomputes the checksum. Source and destination validity is the exact
policy in `03-adaptation.md`: no unspecified, loopback, or IPv4-mapped endpoint;
no multicast source; and multicast destination scope must be 2 through 14.
Rule 7 is a
specialized codec path and intentionally has no generic FieldDescriptor export.

Rule 255 is selected by a sender before transmission. Its payload is a complete
validated IPv6 packet; an unknown received Rule ID is always dropped and is
never reinterpreted as Rule 255.

See the rule registry in rust/lichen-schc/src/rules.rs, the SCHC profile declarations in lichen/subsys/lichen/schc/include/lichen/schc.h, the shared SCHC constants table in constants.toml, and test/vectors/schc_compression.json for exact matching logic and test vectors. Fragmentation uses [schc.fragment]: M=1, N=6, T=0, TILE_SIZE=179 bytes, RCS=4 bytes, RETX=10s, MAX_ACK_REQUESTS=4 (the initial All-1 plus at most three later request emissions), INACTIVITY=60s, and an MSB-first received-tile bitmap in which 1 means received and 0 means missing.

## A.2. Fragmentation (from constants.toml [schc.fragment])

See draft-lichen-schc-lora-00.md §5 (updated to match current constants).

## A.3. CoAP Compression

Rules 0 and 5 match `fe80::/64` and carry the two 64-bit address LSBs. Their
174-bit residue is padded to 22 bytes, for a 23-byte fixed compressed header
including the Rule ID. Rules 1 and 6 match the canonical LICHEN Yggdrasil
`0200::/8` prefix and carry the two 120-bit address LSBs. Their 286-bit residue
is padded to 36 bytes, for a 37-byte fixed compressed header including the
Rule ID. Both CoAP endpoint ports use MSB(12)/LSB(4), and Hop Limit is
value-sent. The CoAP token, options, and payload follow the fixed header
unchanged.

See RFC 8824 and lichen-coap. Content-Format for SenML-CBOR is 112 (see the Content-Format option definitions in lichen-coap/src/option.rs and appendix-senml.md).

## A.4. OSCORE Compression (Rules 5 and 6)

Rules 5/6 reuse the Rule 0/1 residue layouts with distinct rule IDs. The OSCORE
option and encrypted payload travel in the unchanged tail after the residue.
Exact descriptors, byte counts, and test vectors govern behavior.

## A.5. RPL Compression (Rules 3 and 4)

Rules 3 and 4 use link-local IPv6 source and destination addresses, matching
`fe80::/64` and carrying both 64-bit IIDs. Rule 3 carries a 39-byte residue, so
its fixed compressed header is 40 bytes including the Rule ID. Rule 4 carries
a 36-byte residue, so its fixed compressed header is 37 bytes including the
Rule ID. Rule 4 matches a DAO only when the D flag is set and the DODAGID is
present; it does not match a ULA, Yggdrasil, or other routable source address.

Version 3 compresses only the IPv6, ICMPv6, and RPL base-object fields. All RPL
options after the base object are an opaque tail and MUST be copied verbatim.
No active Rule 3 or Rule 4 Field Descriptor uses `MATCH_MAPPING`. This applies
to Pad options and to state-carrying options such as Destination Advertisement
Object Target and Transit Information. The RFC 6550 Prefix Information Option
has Type 8 (and Length 30 when carrying its fixed fields); its Type, Length,
prefix, lifetimes, and all other bytes likewise remain verbatim. Introducing
option mapping compression requires a new rule-set version, executable codec
support, and bit-exact test vectors.

The canonical RPL DIO destination is `ff02::1a`, which does not match Rule 3.
Multicast DIOs therefore MUST use sender-selected, fully validated Rule 255 in
Rule Set Version 3. Rule 3 MUST NOT be extended implicitly, and a decoder MUST
NOT turn `ff02::1a` into `fe80::1a`. Destination and multicast-scope validation
precedes all routing-state mutation.

---

[← Previous: Applications](12-apps.md) | [Index](README.md) | [Next: Appendix B →](appendix-rpl.md)
