<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Appendix A: SCHC Compression Rules

## A.1. Rule Set

Precise sizes use `1 + residue_byte_length(rule)` from BitWriter (Python `codec.py:49`, Rust `codec.rs:142`). Test vectors include variable tail, yielding 33/49 bytes for rules 0/1.

| Rule ID | Use Case | SCHC Header Size | Test Vector Size | Notes |
|---------|----------|------------------|------------------|-------|
| 0 | Link-local IPv6 + UDP + CoAP | 26 bytes | 33 bytes | 198 residue bits (25B) + rule ID; see rules.rs:59, codec.rs:319 |
| 1 | Global IPv6 + UDP + CoAP | 42 bytes | 49 bytes | 326 residue bits (41B); full addresses; see rules.rs:63 |
| 2 | ICMPv6 Echo | 23 bytes | 27 bytes | 176 residue bits (22B) + rule ID; similar + ICMP; see rules.rs:67 |
| 3 | RPL DIO (link-local) | 40 bytes | 40 bytes | 312 residue bits (39B) + rule ID; RPL fields after ICMP; see rules.rs:71 |
| 4 | RPL DAO (routable ULA source, multi-hop) | 53 bytes | 53 bytes | 416 residue bits (52B) + rule ID; matches test vector; see rules.rs:75 and DAO note below |
| 5 | OSCORE link-local IPv6 + UDP | 26 bytes | tbd | reuses CoAP fields with distinct rule ID; see rules.rs:80 |
| 6 | OSCORE global IPv6 + UDP | 42 bytes | tbd | see rules.rs:85 |
| 7 | MQTT-SN | tbd | tbd | see rules.rs:89 |
| 255 | No compression | 1 byte | full | fallback; see rules.rs:93 |

**DAO Source Model (Rule 4):** See 04-network.md and 05-routing.md for the routable multi-hop DAO source model using ULA from DODAG root prefix. Relays forward preserving the original IPv6 source per security spec. Test vectors updated accordingly.

## A.2. CoAP Compression

| Field | TV | MO | CDA |
|-------|----|----|-----|
| Version | 1 | equal | not-sent |
| Type | - | ignore | value-sent (2 bits) |
| TKL | - | ignore | value-sent (4 bits) |
| Code | - | ignore | value-sent (8 bits) |
| MID | - | ignore | value-sent (16 bits) |
| Token | - | ignore | value-sent (TKL bytes) |

## A.3. OSCORE Compression (Rules 5 and 6)

Rules 5/6 reuse FieldDescriptors from rules 0/1 but with distinct rule IDs (rules.rs:80,85; Python rules.py:306). OSCORE option + encrypted payload travel in tail after residue (codec.rs:541 treats identically for now).

No deviid/port-MSB optimizations yet. Hop limit value-sent. Exact descriptors and `residue_byte_length` govern behavior per test vectors. `rules.rs:55` stub to be populated from Python for Rust as source of truth (P2 follow-up filed separately if needed).

---

[← Previous: Applications](12-apps.md) | [Index](README.md) | [Next: Appendix B →](appendix-rpl.md)
