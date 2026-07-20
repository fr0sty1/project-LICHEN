<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Appendix A: SCHC Compression Rules

## A.1. Rule Set

| Rule ID | Use Case | Compressed Size |
|---------|----------|-----------------|
| 0 | Link-local IPv6 + UDP + CoAP | 18 bytes plus CoAP |
| 1 | Native Yggdrasil IPv6 + UDP + CoAP | 33 bytes plus CoAP |
| 2 | Native Yggdrasil IPv6 + MQTT-SN | 32 bytes |
| 3 | RPL multicast control | 10 bytes |
| 4 | RPL unicast control | 18 bytes |
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
