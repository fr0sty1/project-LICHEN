# IETF RFCs

Standards from the Internet Engineering Task Force that LICHEN implements or depends on.

## Core Protocol Stack

### IPv6 & Networking

| RFC | Title | LICHEN Use |
|-----|-------|------------|
| [RFC 768](https://www.rfc-editor.org/rfc/rfc768) | User Datagram Protocol | Transport layer |
| [RFC 4193](https://www.rfc-editor.org/rfc/rfc4193) | Unique Local IPv6 Unicast Addresses | ULA for mesh-internal routing |
| [RFC 4291](https://www.rfc-editor.org/rfc/rfc4291) | IPv6 Addressing Architecture | Address format, scopes |
| [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443) | ICMPv6 | Echo, router/neighbor discovery |
| [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200) | IPv6 Specification | Network layer |

### Compression & Adaptation

| RFC | Title | LICHEN Use |
|-----|-------|------------|
| [RFC 4944](https://www.rfc-editor.org/rfc/rfc4944) | 6LoWPAN Transmission | Fragment dispatch (reference) |
| [RFC 6282](https://www.rfc-editor.org/rfc/rfc6282) | 6LoWPAN Header Compression | IPHC (NOT used, see SCHC) |
| [RFC 8724](https://www.rfc-editor.org/rfc/rfc8724) | SCHC for LPWANs | **Primary compression** |
| [RFC 8138](https://www.rfc-editor.org/rfc/rfc8138) | IPv6 Routing Header (6LoRH) | Source routing in RPL |

### Routing

| RFC | Title | LICHEN Use |
|-----|-------|------------|
| [RFC 6206](https://www.rfc-editor.org/rfc/rfc6206) | Trickle Algorithm | RPL control message timing |
| [RFC 6550](https://www.rfc-editor.org/rfc/rfc6550) | RPL Routing Protocol | Gateway-rooted tree routing |
| [RFC 6554](https://www.rfc-editor.org/rfc/rfc6554) | RPL Source Routing Header | Downward routes |
| [RFC 6719](https://www.rfc-editor.org/rfc/rfc6719) | MRHOF Objective Function | RPL metric calculation |

### Application Protocols

| RFC | Title | LICHEN Use |
|-----|-------|------------|
| [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252) | CoAP | Application protocol |
| [RFC 7390](https://www.rfc-editor.org/rfc/rfc7390) | CoAP Group Communication | Multicast messaging |
| [RFC 7641](https://www.rfc-editor.org/rfc/rfc7641) | CoAP Observe | Resource subscriptions |
| [RFC 7959](https://www.rfc-editor.org/rfc/rfc7959) | CoAP Block-Wise Transfers | Large payload handling |
| [RFC 6690](https://www.rfc-editor.org/rfc/rfc6690) | CoRE Link Format | Resource discovery |
| [RFC 9176](https://www.rfc-editor.org/rfc/rfc9176) | CoAP Resource Directory | Service discovery |

### Data Encoding

| RFC | Title | LICHEN Use |
|-----|-------|------------|
| [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) | CBOR | Binary encoding |
| [RFC 8428](https://www.rfc-editor.org/rfc/rfc8428) | SenML | Sensor data format |
| [RFC 7946](https://www.rfc-editor.org/rfc/rfc7946) | GeoJSON | Position encoding |

## Security

### Object Security

| RFC | Title | LICHEN Use |
|-----|-------|------------|
| [RFC 8613](https://www.rfc-editor.org/rfc/rfc8613) | OSCORE | E2E CoAP security |
| [RFC 9203](https://www.rfc-editor.org/rfc/rfc9203) | OSCORE Group Communication | Group messaging security |
| [RFC 9528](https://www.rfc-editor.org/rfc/rfc9528) | EDHOC | Lightweight key exchange |
| [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) | COSE Structures | Signed/encrypted objects |
| [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053) | COSE Algorithms | Cipher suites |

### Cryptographic Algorithms

| RFC | Title | LICHEN Use |
|-----|-------|------------|
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | EdDSA (Ed25519) | Signatures, key derivation |
| [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) | X25519 | ECDH key agreement |

### Key Management

| RFC | Title | LICHEN Use |
|-----|-------|------------|
| [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) | DANE | DNS-based key pinning (optional) |
| [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) | ACME | Certificate automation (optional) |

## Informational

| RFC | Title | LICHEN Use |
|-----|-------|------------|
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) | Requirement Keywords | Spec language (MUST, SHOULD, MAY) |
| [RFC 3629](https://www.rfc-editor.org/rfc/rfc3629) | UTF-8 | Text encoding |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | Base Encodings | Base64 in text contexts |
| [RFC 1071](https://www.rfc-editor.org/rfc/rfc1071) | Internet Checksum | UDP checksum |

## Not Used (by design)

| RFC | Title | Why Not |
|-----|-------|---------|
| RFC 6282 | 6LoWPAN IPHC | SCHC is better for LPWAN |
| RFC 793 | TCP | Too much overhead for LoRa |
| RFC 5246 | TLS 1.2 | Use OSCORE instead |
