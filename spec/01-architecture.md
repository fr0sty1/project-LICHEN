<!-- Part of LICHEN Protocol Specification -->

# Architecture

## 1. Design Principles

### 1.1. Standards-Based

Every protocol layer uses existing IETF standards:

| Layer | Standard | RFC |
|-------|----------|-----|
| Compression | SCHC | RFC 8724 |
| Adaptation | 6LoWPAN | RFC 4944, 6282 |
| Network | IPv6 | RFC 8200 |
| Routing | RPL | RFC 6550 |
| Security | OSCORE, LLSec | RFC 8613, custom |
| Transport | UDP | RFC 768 |
| Application | CoAP, MQTT-SN | RFC 7252, OASIS |

### 1.2. Design Goals

1. **Real IPv6:** Globally routable addresses, not proprietary node IDs
2. **Efficient:** SCHC compresses headers to 6-15 bytes
3. **Authenticated:** Every packet cryptographically signed
4. **Interoperable:** Standard CoAP/MQTT-SN applications work unmodified
5. **Mesh:** RPL provides multi-hop routing without central coordination
6. **Gateway-friendly:** Border routers connect mesh to internet

### 1.3. Non-Goals

- Backward compatibility with Meshtastic or MeshCore
- Support for non-IP protocols
- Complex QoS or traffic engineering

---

## 2. Protocol Stack

```
+----------------------------------------------------------+
|                    Application Layer                      |
|  CoAP (RFC 7252) | MQTT-SN (OASIS) | Raw UDP | ICMPv6    |
+----------------------------------------------------------+
|                    Security Layer                         |
|  OSCORE (RFC 8613) for CoAP | DTLS 1.3 for MQTT-SN       |
+----------------------------------------------------------+
|                    Transport Layer                        |
|  UDP (RFC 768) - compressed via SCHC                      |
+----------------------------------------------------------+
|                    Network Layer                          |
|  IPv6 (RFC 8200) - compressed via SCHC                    |
|  Link-local (fe80::/10) or Global (/64 prefix)            |
+----------------------------------------------------------+
|                    Routing Layer                          |
|  RPL (RFC 6550) - DODAG mesh formation                    |
|  Source routing via 6LoRH (RFC 8138)                      |
+----------------------------------------------------------+
|                    Adaptation Layer                       |
|  6LoWPAN (RFC 4944, 6282) - fragmentation                 |
|  SCHC (RFC 8724) - header compression                     |
+----------------------------------------------------------+
|                    Link Security Layer                    |
|  Ed25519 signatures (truncated) | Replay protection       |
+----------------------------------------------------------+
|                    MAC Layer                              |
|  TSCH (RFC 7554) or CSMA/CA                               |
+----------------------------------------------------------+
|                    Physical Layer                         |
|  LoRa CSS (Semtech SX126x/SX127x)                         |
+----------------------------------------------------------+
```

---

[Index](README.md) | [Next: Physical and Link Layers →](02-physical-link.md)
