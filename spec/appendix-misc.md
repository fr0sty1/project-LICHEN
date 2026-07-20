<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Appendix C-E: Miscellaneous

## Appendix C: CoAP Resource Directory

### C.1. Registration

```
POST coap://[6lbr]/rd?ep=node-001&lt=86400
Content-Format: application/link-format
</sensors/temp>;rt="temperature";if="sensor"
</sensors/humidity>;rt="humidity";if="sensor"
```

### C.2. Lookup

```
GET coap://[6lbr]/rd-lookup/res?rt=temperature

Response:
<coap://[node-001]/sensors/temp>;rt="temperature"
<coap://[node-042]/sensors/temp>;rt="temperature"
```

---

## Appendix D: Comparison with Existing Protocols

| Feature | LICHEN | Meshtastic | MeshCore | LoRaWAN |
|---------|--------|------------|----------|---------|
| Topology | Mesh (RPL) | Mesh (flood) | Mesh (path) | Star |
| IP Support | Full IPv6 | None | None | IPv6 (SCHC) |
| Max Hops | Unlimited* | 7 | 63 | 1 |
| Header Overhead | 18-33 bytes baseline | 16 bytes | 6 bytes | 13 bytes |
| Authentication | Ed25519 | None/Ed25519 | HMAC | AES-CMAC |
| Encryption | OSCORE | AES-256-CTR | AES-128-ECB | AES-128 |
| Forward Secrecy | No** | No | No | No |
| Standard | IETF | Proprietary | Proprietary | LoRa Alliance |
| CoAP Support | Native | No | No | Via SCHC |
| Global Mesh Routing | Separate Yggdrasil profile | Via gateway | Via gateway | LoRaWAN core |

*Limited by network diameter and duty cycle
**Can add EDHOC for session keys

---

## Appendix E: Example Network

```
                        Yggdrasil
                             |
                    +--------+--------+
                    |  Border Router  |
                    | native /128     |
                    | DODAG Root      |
                    +--------+--------+
                             |
            +----------------+----------------+
            |                                 |
    +-------+-------+                 +-------+-------+
    |   Router A    |                 |   Router B    |
    | native /128   |                 | native /128   |
    +-------+-------+                 +-------+-------+
            |                                 |
      +-----+-----+                     +-----+-----+
      |           |                     |           |
  +---+---+   +---+---+             +---+---+   +---+---+
  | Leaf 1|   | Leaf 2|             | Leaf 3|   | Leaf 4|
  | /128  |   | /128  |             | /128  |   | /128  |
  +-------+   +-------+             +-------+   +-------+

  Leaf 1: Temperature sensor, CoAP server
  Leaf 2: Humidity sensor, CoAP server
  Leaf 3: MQTT-SN client, publishes to broker
  Leaf 4: Actuator, CoAP client
```

**Traffic flow:**

1. Leaf 1 -> Border Router: CoAP response with temperature (upward via RPL)
2. Root -> Leaf 4: CoAP request (downward via source routing)
3. Leaf 3 -> MQTT Broker: MQTT-SN PUBLISH (via gateway at border router)

---

[← Previous: Appendix B](appendix-rpl.md) | [Index](README.md) | [Next: Appendix F →](appendix-senml.md)
