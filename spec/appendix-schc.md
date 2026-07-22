<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Appendix A: SCHC Compression Rules

## A.1. Rule Set

| Rule ID | Use Case | Compressed Size |
|---------|----------|-----------------|
| 0 | Link-local IPv6 + UDP + CoAP | 4-6 bytes |
| 1 | Global IPv6 + UDP + CoAP | 12-14 bytes |
| 2 | ICMPv6 Echo | 3 bytes |
| 3 | RPL DIO (link-local) | 8 bytes |
| 4 | RPL DAO (routable ULA source for multi-hop) | 6 bytes |
| 5 | Link-local IPv6 + UDP + OSCORE | 6 bytes |
| 6 | Global IPv6 + UDP + OSCORE | 14 bytes |
| 255 | No compression | Full headers |

## A.2. CoAP Compression

| Field | TV | MO | CDA |
|-------|----|----|-----|
| Version | 1 | equal | not-sent |
| Type | - | ignore | value-sent (2 bits) |
| TKL | - | ignore | value-sent (4 bits) |
| Code | - | ignore | value-sent (8 bits) |
| MID | - | ignore | value-sent (16 bits) |
| Token | - | ignore | value-sent (TKL bytes) |

---

[← Previous: Applications](12-apps.md) | [Index](README.md) | [Next: Appendix B →](appendix-rpl.md)
