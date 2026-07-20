# LICHEN Application Layer -- Design Thinking

Working notes from design discussion.

**Status:** Key decisions resolved and moved to spec. See:
- `07-transport-app.md` Section 9.1 (port allocation)
- `07-transport-app.md` Section 10.1 (raw UDP applications)
- `03-adaptation.md` Section 5.5 (SCHC rules including MQTT-SN)

This document is retained for historical context and rationale.

---

## The Question

Meshtastic has predefined application types: text messages, weather station telemetry, 4-slot sensor readings. What does LICHEN have? What should it have?

## What Others Do

### Meshtastic

Hardcoded message types:
- Text message (sender, text, timestamp)
- Device telemetry (battery, voltage, channel utilization, airtime)
- Environment (temp, humidity, pressure, gas resistance)
- Position (lat/lon/alt/speed/heading)

Fixed schemas, no negotiation. Simple but inflexible.

### LoRaWAN / Cayenne LPP

Compact binary format. `[channel:1][type:1][value:N]`

Type codes map to known sensors:
- 103 = temperature (2 bytes, 0.1°C resolution)
- 104 = humidity (1 byte, 0.5% resolution)
- 113 = accelerometer (6 bytes, 3 axes)
- 136 = GPS (9 bytes)

Very compact. Not IETF. Receiver must know the schema.

### Amazon Sidewalk

Transport framing (Get/Set/Notify/Response), not sensor schemas. Max 200 bytes FSK, 19 bytes CSS. Not much to steal for sensor profiles.

### Yolink

Proprietary. Locked down. Cloud API only.

### TAK / Cursor on Target (CoT)

The tac/milsim lingua franca. XML-based event format:
- PLI (Position Location Information): lat/lon/alt, course, speed, team, role
- GeoChat: text messages with sender and location
- Markers: points of interest with type hierarchy
- Alerts: emergency/contact reports

Type hierarchy: `a-f-G-U-C` = atoms → friendly → ground → unit → combat

Origin: US Air Force Research Laboratory (AFRL), ~2005. Not IETF -- DoD de facto standard. Open, documented, widely deployed.

What Meshtastic ATAK plugin actually sends over mesh (bandwidth-constrained):
- PLI
- Chat
- Point markers

Everything else (video, data packages, 9-line MEDEVAC) is too fat for mesh.

### Substrate / PARLANCE

CoAP + CBOR + OSCORE + IPSO Smart Objects. Full device protocol:
- Sensor readings with quality indicators
- Device metadata
- Network status, diagnostics
- Firmware OTA
- Policy documents

Hub-and-spoke topology (device → controller). Rich semantics, audit trail, safety classes.

## LICHEN Already Has

From the architecture:
```
Application:  CoAP / MQTT-SN / Raw UDP
Security:     OSCORE (E2E) + Schnorr link signatures
Transport:    UDP (compressed via SCHC)
Network:      IPv6 (link-local control + native Yggdrasil /128)
```

SenML profiles for sensor data:
- location, battery, temperature, humidity, pressure
- accelerometer, gyroscope, CO2, VOC

Native protocol messages for control plane:
- Hello, Config, SendMessage/MessageReceived, MeshState, NodeInfo, Logging

## Key Insight: LICHEN is the Network, Not the Application

LICHEN provides IPv6 mesh over LoRa. Applications run on top. Different applications for different use cases:

```
┌─────────────────────────────────────────────────┐
│              APPLICATIONS                        │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ Tac Msgs │  │  SenML   │  │   CoAP/IPSO   │  │
│  │ (CoT)    │  │ telemetry│  │  (PARLANCE)   │  │
│  └──────────┘  └──────────┘  └───────────────┘  │
├─────────────────────────────────────────────────┤
│                 OSCORE (E2E)                    │
├─────────────────────────────────────────────────┤
│                 UDP / IPv6                      │
├─────────────────────────────────────────────────┤
│              SCHC compression                   │
├─────────────────────────────────────────────────┤
│              LICHEN mesh (LoRa)                 │
└─────────────────────────────────────────────────┘
```

A tac handheld runs tac messaging. A Substrate building gateway runs CoAP/IPSO. A hybrid node runs both. The mesh doesn't care -- it moves IPv6 packets.

## Application Type Discriminator

One byte at the start of every application payload:

```
[app_type:1][payload...]

0x00  Raw       -- opaque bytes, application-defined
0x01  CoT       -- compact binary CoT (PLI, chat, markers, alerts)
0x02  SenML     -- CBOR-encoded RFC 8428 sensor records
0x03  CoAP      -- full CoAP message (for PARLANCE/IPSO)
0x04+ reserved
```

One byte overhead. Receivers dispatch instantly. Extensible.

## Compact CoT Encoding

If both sides know the CoT schema, strip it to the bone:

**CoT XML (what ATAK speaks):**
```xml
<event type="a-f-G-U-C" uid="ALPHA-1" time="..." stale="...">
  <point lat="47.606" lon="-122.332" hae="158"/>
  <detail>
    <contact callsign="ALPHA-1"/>
    <__group name="Blue" role="Team Lead"/>
    <track course="270" speed="1.2"/>
  </detail>
</event>
```
~400+ bytes

**Compact wire:**
```
[0x01][subtype:1][lat:4][lon:4][alt:2][course:2][speed:2][team:1][role:1]
```
= 18 bytes for full PLI

**Subtype mapping:**
| Byte | CoT type | What |
|------|----------|------|
| 0x01 | `b-t-f` | Chat |
| 0x02 | `a-f-G-*` | Friendly ground PLI |
| 0x03 | `a-h-G-*` | Hostile ground |
| 0x04 | `a-n-G-*` | Neutral ground |
| 0x05 | `a-u-G-*` | Unknown ground |
| 0x10 | `a-f-G-E-S` | Marker |
| 0x20 | `b-a` | Alert |

**Field encoding:**
- lat/lon: int32 microdegrees (±180° fits in 32 bits)
- alt: int16 decimeters
- course: uint16 centidegrees
- speed: uint16 cm/s
- team/role: enum bytes
- text: length-prefixed UTF-8

**Gateway expands to full CoT XML for ATAK interop.**

## SenML vs Cayenne LPP

Same problem, different tradeoffs:

| | SenML | Cayenne LPP |
|---|---|---|
| Origin | IETF RFC 8428 | LoRa Alliance |
| Philosophy | Self-describing | Schema-based |
| Wire format | CBOR or JSON | Fixed binary |
| Overhead | ~25-30 bytes/reading | ~4 bytes/reading |

**Decision: Keep SenML, skip Cayenne.**

Rationale:
1. LICHEN's selling point is "IETF did this for us" -- don't dilute it
2. SCHC compresses SenML field names across packets
3. Not sending telemetry every second -- extra bytes aren't critical
4. One codec to implement vs two

If bytes become critical, define a "SenML Compact Profile" (integer keys, implied units) -- still RFC 8428 compliant.

## The "Shape" Problem

CBOR is encoding. SenML is structure. Neither defines "weather station = temp + humidity + pressure + wind."

**Where do composite profiles come from?**

| Source | What it gives |
|--------|---------------|
| IPSO Smart Objects | Individual sensors (3303=temp, 3304=humidity) |
| OMA LwM2M registry | Device profiles (heavyweight) |
| Matter device types | Composite definitions (Matter ecosystem) |
| Meshtastic | Hardcoded slots |

**Proposed solution:**

Use IPSO object IDs as vocabulary (standards-based). Define LICHEN composite profiles:

```yaml
# profiles/weather-station.yaml
name: weather-station
version: 1
ipso_objects: [3303, 3304, 3315]
records:
  - {n: "3303/0", u: "Cel", required: true}   # temperature
  - {n: "3304/0", u: "%RH", required: true}   # humidity
  - {n: "3315/0", u: "Pa", required: true}    # pressure
  - {n: "wind", u: "m/s", required: false}    # extension
```

Profiles live in registry/repo, not on wire. Devices advertise which profile they implement.

## Substrate Building Integration

A Substrate building "joins" the mesh via gateway:

```
┌─────────────────────────────────────────────────────────────┐
│                      LICHEN MESH                            │
│                                                             │
│  [Tac Node]◄──────►[Tac Node]◄──────►[Gateway Node]        │
│       │                                    │                │
│       │         compact wire               │                │
│       │                                    │                │
└───────┼────────────────────────────────────┼────────────────┘
        │                                    │
        │  PARLANCE (CoAP/OSCORE/IPSO)       │
        ▼                                    │
   ┌─────────┐                               │
   │ FRAME   │◄──────────────────────────────┘
   │Controller│
   └────┬────┘
        │
   [Thread/WiFi devices]
```

Gateway is bilingual:
- Mesh side: lightweight CoT/SenML, appears as normal node
- Building side: full PARLANCE to FRAME controller
- Translates: building sensors → mesh telemetry, mesh commands → CoAP actuator requests

Tac users never see CoAP overhead.

## Standards Story

| Layer | Standard | Body |
|-------|----------|------|
| Network | IPv6 | IETF |
| Compression | SCHC | IETF RFC 8724 |
| Security | OSCORE | IETF RFC 8613 |
| Encoding | CBOR | IETF RFC 8949 |
| Sensors | SenML | IETF RFC 8428 |
| Tac semantics | CoT | DoD (de facto) |
| Device mgmt | CoAP | IETF RFC 7252 |
| Device model | IPSO | OMA |

Pitch: "LICHEN is IETF RFCs all the way down. For tac interop, we translate to CoT at the gateway -- the format the DoD ecosystem already speaks."

## Open Questions

1. ~~Port assignments -- different UDP ports per app type, or discriminator byte only?~~
   **Resolved:** Port-based dispatch. Ports 5681-5687 for raw UDP apps (compact CoT,
   SenML, Cayenne, APRS-IS, NMEA), 5683 for CoAP, 10883 for MQTT-SN. See spec.
2. Group/broadcast semantics for each app type
3. ACK/delivery confirmation for tac messages (or rely on link layer?)
4. Exact CBOR schemas for SenML profiles
5. Profile registry format and distribution
6. ~~CoT subtype allocation (reserve ranges for extensions?)~~
   **Resolved:** Subtype byte defined in spec Section 10.1.1. Ranges: 0x01-0x0F PLI,
   0x10-0x1F markers, 0x20-0x2F alerts.

## What CoAP Actually Buys You

CoAP is HTTP for constrained devices. ~10-20 byte overhead.

| Feature | What it does |
|---------|--------------|
| Methods | GET/PUT/POST/DELETE semantics |
| URIs | `/sensors/temp` addressing |
| Message IDs | Match responses to requests |
| Confirmable | Retransmit until ACK'd |
| Observe | Subscribe to resource changes |
| Block | Chunked transfer |

**For tac messaging:** Overkill. Fire-and-forget or simple ACK. Raw UDP + CBOR + sequence number.

**For Substrate/IPSO:** Required. GET `/io/sensors/3303/0`, Observe for push, PUT for commands. The lingua franca.

CoAP is optional. Use it where it earns its overhead.
