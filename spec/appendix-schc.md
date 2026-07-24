<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Appendix A: SCHC Compression Rules

See draft-lichen-schc-lora-00.md §4 for rules, §5 for fragmentation (M=1 N=6 T=0, RCS=CRC32, timers, bitmap MSB-first) from constants.toml and test/vectors/. Full table is canonical here.

| Rule ID | Use Case | Compressed Size (residue only) | Test Vector Size (total) | Notes |
|---------|----------|-------------------------------|--------------------------|-------|
| 0 | Link-local IPv6 + UDP + CoAP | 32 B (256 bit) | 33 B | MSB(64) IIDs; hop-limit value-sent; ports value-sent; CoAP fields value-sent; payload length/checksum computed |
| 1 | Global IPv6 + UDP + CoAP | 48 B (384 bit) | 49 B | Full src/dst IPv6 addresses (Ignore/ValueSent) |
| 2 | ICMPv6 Echo | 26 B (208 bit) | 27 B | Type value-sent; identifier+sequence value-sent; code not-sent; checksum computed |
| 3 | RPL DIO (link-local) | 39 B (312 bit) | 40 B | ICMPv6 RPL base + DIO fields: instance/version/rank/gmop/dtsn value-sent; dodagid value-sent (128 bit) |
| 4 | RPL DAO (routable link-local) | 36 B (288 bit) | 37 B | ICMPv6 RPL base + DAO fields: instance/flags value-sent; dodagid value-sent (128 bit) |
| 5 | Link-local IPv6 + UDP + OSCORE | 32 B (256 bit) residue | — | Reuses Rule 0 FieldDescriptors; OSCORE option + encrypted payload in tail after residue |
| 6 | Global IPv6 + UDP + OSCORE | 48 B (384 bit) residue | — | Reuses Rule 1 FieldDescriptors; OSCORE tail |
| 7 | MQTT-SN (port 10883) | 12-14 B | — | Full src/dst IPv6 + UDP ports value-sent; no CoAP fields |
| 255 | No compression | Full headers | — | Version mismatch or unknown rule fallback |

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

Rules 3/4 compress base fields (IPv6+ICMPv6+RPL base) to ~8B (DIO)/~6B (DAO). Options use MATCH_MAPPING on Type field (prioritized list of common TLVs) + per-type descriptors. For PIO (type=3, common for prefix ads):

| Field | TV | MO | CDA | Notes |
|-------|----|----|-----|-------|
| RPL.Option.Type | [0,3,2,5,6,7,...] | match-mapping | mapping-sent | 3-bit index (Pad1=0, PIO=1, ...) |
| RPL.Option.Length | 30 | equal | not-sent | Standard PIO size |
| PIO.Prefix Length | 64 | equal | not-sent | /64 default for LICHEN |
| PIO.Flags | 0xC0 | equal | not-sent | LA bits per spec/09-rpl.md |
| PIO.Lifetime | - | ignore | value-sent | Valid/preferred lifetimes |
| PIO.Prefix | - | msb(64) | lsb(64) | Compressible IID |

This reduces typical options overhead from 20-40B (verbatim tail) to 8-15B. See `rust/lichen-schc/src/rules.rs`, `python/src/lichen/schc/rules.py:324`, test vectors, and RFC 8724 §10 for TLV patterns. Full rules in constants.toml and schc_compression.json.

Pad1 uses simple equal/not-sent as before.

---

[← Previous: Applications](12-apps.md) | [Index](README.md) | [Next: Appendix B →](appendix-rpl.md)
