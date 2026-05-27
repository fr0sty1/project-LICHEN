<!-- Part of LICHEN Protocol Specification -->

# Appendix A: SCHC Compression Rules

## A.1. Rule Set

| Rule ID | Use Case | Compressed Size |
|---------|----------|-----------------|
| 0 | Link-local IPv6 + UDP + CoAP | 4-6 bytes |
| 1 | Global IPv6 + UDP + CoAP | 12-14 bytes |
| 2 | ICMPv6 Echo | 3 bytes |
| 3 | RPL DIO | 8 bytes |
| 4 | RPL DAO | 6 bytes |
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
