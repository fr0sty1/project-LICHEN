<!-- Part of LICHEN Protocol Specification -->

# Transport and Application Layers

## 9. Transport Layer

### 9.1. UDP

Standard UDP (RFC 768), compressed via SCHC.

**Ports:**
| Port | Protocol |
|------|----------|
| 5683 | CoAP (unencrypted) |
| 5684 | CoAPS (DTLS) |
| 10883 | MQTT-SN |

### 9.2. No TCP

TCP is NOT recommended for LoRa mesh due to:
- High overhead (20-byte header minimum)
- Poor performance over lossy links
- Congestion control incompatible with duty cycles

Use CoAP (with Observe) or MQTT-SN for reliable messaging.

---

## 10. Application Layer

### 10.1. CoAP (RFC 7252)

Constrained Application Protocol - REST-like for constrained devices.

**Message Format:**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Ver| T |  TKL  |      Code     |          Message ID           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Token (if any, TKL bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Options (if any) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 1 1 1 1 1 1 1|    Payload (if any) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Methods:**
| Code | Method |
|------|--------|
| 0.01 | GET |
| 0.02 | POST |
| 0.03 | PUT |
| 0.04 | DELETE |

### 10.2. CoAP Observe (RFC 7641)

Subscribe to resource changes:

```
GET /.well-known/core?rt=temperature
Observe: 0

<-- 2.05 Content
    Observe: 1
    {temperature: 23.5}

<-- 2.05 Content (notification)
    Observe: 2
    {temperature: 24.0}
```

### 10.3. CoAP Block-wise Transfer (RFC 7959)

Large payloads fragmented at CoAP layer (independent of SCHC fragmentation):

| Option | Value |
|--------|-------|
| Block1 | Request payload blocks |
| Block2 | Response payload blocks |
| Size1 | Request size hint |
| Size2 | Response size hint |

Block size: 16, 32, 64, 128, 256, 512, or 1024 bytes.

### 10.4. MQTT-SN (OASIS Standard)

MQTT for Sensor Networks - UDP-based MQTT variant.

**Key Differences from MQTT:**
- Topic IDs instead of strings (2 bytes vs. variable)
- QoS -1 (fire and forget, no connection)
- Gateway-assisted topic registration

**Message Types:**
| Type | Code | Description |
|------|------|-------------|
| CONNECT | 0x04 | Client connect |
| CONNACK | 0x05 | Connect acknowledgment |
| REGISTER | 0x0A | Register topic alias |
| REGACK | 0x0B | Registration acknowledgment |
| PUBLISH | 0x0C | Publish message |
| PUBACK | 0x0D | Publish acknowledgment |
| SUBSCRIBE | 0x12 | Subscribe to topic |
| SUBACK | 0x13 | Subscribe acknowledgment |

### 10.5. MQTT-SN over LoRa Mesh

**Architecture:**
```
[Sensor Node] --LoRa--> [MQTT-SN Gateway] --IP--> [MQTT Broker]
                              |
                        [Border Router]
```

Gateway at border router translates MQTT-SN <-> MQTT 3.1.1/5.0.

### 10.6. Resource Directory (RFC 9176)

Border router runs CoAP Resource Directory for discovery:

```
# Registration
POST coap://[border-router]/rd?ep=sensor-42
</temperature>;rt="sensor";if="core.s"

# Lookup
GET coap://[border-router]/rd-lookup/res?rt=sensor
```

---

[← Previous: Security](06-security.md) | [Index](README.md) | [Next: Node Types →](08-nodes.md)
