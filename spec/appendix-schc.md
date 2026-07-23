<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Appendix A: SCHC Compression Rules

See draft-lichen-schc-lora-00.md §4 for rules, §5 for fragmentation (M=1 N=6 T=0, RCS=CRC32, timers, bitmap MSB-first) from constants.toml and test/vectors/. Full table is canonical here.

| Rule ID | Use Case | Compressed Size | Notes |
|---------|----------|-----------------|-------|
| 0 | Link-local IPv6 + UDP + CoAP | 4-6 bytes | MSB(64) IIDs; ports MSB(12)/LSB(4) for CoAP/SenML range |
| 1 | Global IPv6 + UDP + CoAP | 12-14 bytes | ULA/GUA source, full dst as needed |
| 2 | ICMPv6 Echo | 3 bytes | Type 128/129, Code=0 not-sent |
| 3 | RPL DIO (link-local) | 8 bytes | ICMPv6 type=155/code=0 + options |
| 4 | RPL DAO (routable ULA source for multi-hop) | 6 bytes | Multi-hop source preservation |
| 5 | Link-local IPv6 + UDP + OSCORE | ~6 bytes residue | + OSCORE tail |
| 6 | Global IPv6 + UDP + OSCORE | ~14 bytes residue | + OSCORE tail |
| 7 | MQTT-SN (port 10883) | ~6 bytes | Exact port match |
| 255 | No compression | Full headers | Version mismatch or unknown rule fallback |

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

See rust/lichen-schc/src/rules.rs, lichen/subsys/lichen/schc/include/lichen/schc.h:93, constants.toml:29-36, and test/vectors/schc_compression.json for exact matching logic and test vectors. Fragmentation uses [schc.fragment]: M=1, N=6, T=0, RCS=4 bytes, RETX=10s, MAX_ACK=3, INACTIVITY=60s (MSB-first bitmap).

## A.2. Fragmentation (from constants.toml [schc.fragment])

See draft-lichen-schc-lora-00.md §5 (updated to match current constants).

## A.3. CoAP Compression

See RFC 8824 and lichen-coap. Content-Format for SenML-CBOR is 112 (see lichen-coap/src/option.rs:33 and appendix-senml.md).

## A.3. OSCORE Compression (Rules 5 and 6)

Rules 5/6 reuse FieldDescriptors from rules 0/1 but with distinct rule IDs (rules.rs:80,85; Python rules.py:306). OSCORE option + encrypted payload travel in tail after residue (codec.rs:541 treats identically for now).

No deviid/port-MSB optimizations yet. Hop limit value-sent. Exact descriptors and `residue_byte_length` govern behavior per test vectors. `rules.rs:55` stub to be populated from Python for Rust as source of truth (P2 follow-up filed separately if needed).

## A.4. RPL Compression (Rules 3 and 4)

Rules 3 (RPL_DIO) and 4 (RPL_DAO) compress IPv6+ICMPv6+base RPL fields to fixed residue (8B DIO, ~6B DAO). RPL options (TLVs per RFC 6550 §6.7) appended verbatim as tail after residue (headers.rs:19-20).

Per RFC 8724 §10 TLV compression, example for Pad1 (type=0x00):

| Field | TV | MO | CDA |
|-------|----|----|-----|
| RPL.Option.Type | 0 | equal | not-sent |

PadN/Target(5)/Transit(6)/PIO(3)/Config(4) use Ignore+ValueSent or mapping. Full descriptors: rules.rs:480 (RPL_DIO_RULE), headers.rs:692 (profiles), test/vectors/rpl_messages.json:254 (pad1/padn vector), python/src/lichen/schc/rules.py:274.

See test/vectors/schc_compression.json for base cases.

---

[← Previous: Applications](12-apps.md) | [Index](README.md) | [Next: Appendix B →](appendix-rpl.md)
