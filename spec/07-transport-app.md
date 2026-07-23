<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Transport and Application Layers

## 9. Transport Layer

### 9.1. UDP

Standard UDP (RFC 768), compressed via SCHC.

LICHEN uses UDP port numbers to distinguish application protocols. Ports are
selected to optimize SCHC header compression while remaining compatible with
IANA-registered services where applicable.

**Port Allocation:**

| Port | Transport | Payload Format | Standard |
|------|-----------|----------------|----------|
| 5681 | Raw UDP | Compact CoT | LICHEN-defined |
| 5682 | Raw UDP | SenML | RFC 8428 (CBOR) |
| 5683 | CoAP | Via Content-Format | RFC 7252 |
| 5684 | Reserved | (CoAPS/DTLS) | RFC 7252 |
| 5685 | Raw UDP | Cayenne LPP | LoRa Alliance |
| 5686 | Raw UDP | APRS-IS | ASCII |
| 5687 | Raw UDP | NMEA | ASCII |
| 10883 | MQTT-SN | Pub/Sub | OASIS |

**Port Selection Rationale:**

Ports 5681-5687 share the same upper 12 bits as port 5683 (CoAP). SCHC rules
compress these ports using MSB(12) matching with LSB(4) residue, reducing the
4-byte source+destination port pair to a single byte. This provides 16 ports
(5680-5695) at minimal wire cost.

Port 10883 (MQTT-SN) lies outside this range and requires a dedicated SCHC
rule. The additional rule costs one Rule ID slot and approximately 100 bytes
of firmware, but preserves IANA compliance and ecosystem compatibility.

Port 5684 is reserved. LICHEN uses OSCORE for end-to-end security rather than
DTLS, so CoAPS is not used, but the port remains reserved to avoid confusion
with standard CoAP deployments.

**Mesh-Internal Semantics:**

Ports 5681, 5682, and 5685-5687 carry LICHEN-specific payload formats that
may not have standard UDP port assignments elsewhere. These ports are
mesh-internal: gateways MUST translate to standard protocols before
forwarding traffic to external networks.

| Mesh Port | External Translation |
|-----------|---------------------|
| 5681 (Compact CoT) | CoT XML over TCP 8087 |
| 5682 (SenML) | CoAP with Content-Format 110 |
| 5685 (Cayenne) | LoRaWAN application server |
| 5686 (APRS-IS) | APRS-IS TCP or AX.25 RF |
| 5687 (NMEA) | Serial NMEA or CoAP/SenML |

This approach keeps mesh traffic compact while maintaining interoperability
at network boundaries.

**Why Not a Discriminator Byte?**

An alternative design places a 1-byte application type discriminator at the
start of every UDP payload, allowing all traffic to share a single port.
LICHEN uses port-based dispatch instead because:

1. SCHC compresses the 568x port family to 4 bits per port (8 bits total for
   source + destination), the same overhead as a discriminator byte.
2. Port-based dispatch is standard practice; discriminator bytes require
   custom parsing.
3. OS and network stacks can filter by port without application involvement.

If LICHEN required more than 16 application types, the discriminator approach
would be more efficient. Current allocation uses 7 of 16 available slots.

**Protocols Not Included:**

| Protocol | Why Not |
|----------|---------|
| "The Web" | HTML, CSS, JavaScript, WebSockets, megabytes of assets. LoRa moves ~100 bytes/minute under duty limits. The math doesn't math. |
| Drone telemetry | See MAVLink. Real-time drone control requires sub-second latency and continuous streams. LoRa mesh is seconds of latency and sparse packets. Wrong tool. |
| FTP | TCP-based, chatty handshake, separate control/data channels. Use CoAP block-wise or application chunking for file transfer. |
| Generic protobuf | Encoding format, not application protocol. No standard semantics to dispatch on. Wrap in CoAP with appropriate Content-Format if needed. |
| HTTP/HTTPS | TCP-based. See Section 9.2 (No TCP). Also, TLS handshake alone exceeds LoRa's hourly duty budget. |
| LwM2M | Runs over CoAP. Use port 5683 with LwM2M resource paths. No separate port needed. |
| Matter | Runs over CoAP. Use port 5683. |
| MAVLink | Designed for 100+ kbps links at 10-50 Hz. LoRa duty cycle allows ~90 packets/hour. 40x over budget. Use CoT/SenML for sparse position beacons instead. |
| MeshCore RF | Same as Meshtastic. BLE compat exists for mobile apps; RF formats are incompatible by design. |
| Meshtastic RF | Handled at BLE compatibility layer, not mesh transport. LICHEN RF is IPv6; Meshtastic RF is proprietary protobuf. Tunneling buys nothing--the radios don't interoperate anyway. |
| P25 | Public safety digital radio for real-time voice. Voice codec (IMBE/AMBE+2) needs ~9.6 kbps continuous stream; LoRa duty cycle dies in under a second. P25 data services (location, status) are tightly coupled to trunking. Interop path: gateway extracts P25 unit locations, translates to CoT PLI, forwards over LICHEN. Voice stays on P25. |
| Post-Quantum Crypto | Get the key sizes sane first. Kyber keys are ~1 KB, Dilithium signatures ~2.5 KB. LICHEN L2 MTU is ~200 bytes. Also, LICHEN link-layer uses signatures for authentication, not confidentiality--harvest-now-decrypt-later isn't a threat model for "I proved I sent this packet." Revisit when NIST finishes and key sizes shrink. |
| Raw binary | Use CoAP with `Content-Format: application/octet-stream`, or stuff bytes in any raw UDP port. No need for a dedicated "raw" port--every port already carries whatever payload you put in it. |
| REST | REST is an architectural style, not a protocol. CoAP *is* REST for constrained devices--same verbs (GET/PUT/POST/DELETE), same resource model, 1/10th the overhead. |
| SNMP | Designed for managed networks with thousands of OIDs. Absurdly verbose for LoRa. CoAP + SenML covers the same device monitoring use case at 1/10th the size. |
| Your favorite mil-tac protocol | Give us the specs--unclassified, unrestricted distribution--and explain why it's better than CoT. Then we'll talk. CoT is open, documented, and already the lingua franca from ATAK to NATO feeds. |
| Zigbee Cluster Library | Tied to 802.15.4 framing. LICHEN uses SCHC/IPv6. |

### 9.2. No TCP

TCP is NOT recommended for LoRa mesh due to:
- High overhead (20-byte header minimum)
- Poor performance over lossy links
- Congestion control incompatible with duty cycles

Use CoAP (with Observe) or MQTT-SN for reliable messaging.

---

## 10. Application Layer

LICHEN is an IPv6 mesh network, not an application protocol. Applications run
on top of LICHEN using standard or domain-specific protocols. The port
allocation above supports multiple application profiles without requiring
application-layer dispatch bytes or protocol negotiation.

### 10.1. Raw UDP Applications

Ports 5681, 5682, and 5685-5687 carry raw UDP datagrams with known payload
formats. No framing overhead beyond UDP. Receivers dispatch based on
destination port.

#### 10.1.1. Compact CoT (Port 5681)

Cursor on Target (CoT) is the tactical messaging format used by ATAK and
similar systems. Standard CoT is XML, which is prohibitively verbose for
LoRa. LICHEN defines a compact binary encoding for mesh transport.

**Subtype Byte:**

The first byte identifies the CoT event type:

| Byte | CoT Type | Description |
|------|----------|-------------|
| 0x01 | b-t-f | Chat message |
| 0x02 | a-f-G-* | Friendly ground PLI |
| 0x03 | a-h-G-* | Hostile ground |
| 0x04 | a-n-G-* | Neutral ground |
| 0x05 | a-u-G-* | Unknown ground |
| 0x10 | b-m-p-* | Point marker |
| 0x20 | b-a-* | Alert |

**PLI Encoding (subtypes 0x02-0x05):**

```
+--------+--------+--------+--------+--------+--------+
| subtype| latitude (int32) | longitude (int32)       |
+--------+--------+--------+--------+--------+--------+
| altitude| course | speed  | team   | role   |
| (int16) |(uint16)|(uint16)| (uint8)| (uint8)|
+--------+--------+--------+--------+--------+--------+
```

Total: 18 bytes for full PLI (vs 400+ bytes XML).

Field encoding:
- Latitude/longitude: int32 microdegrees (±180° in 32 bits)
- Altitude: int16 decimeters
- Course: uint16 centidegrees (0-35999)
- Speed: uint16 cm/s
- Team/role: enumerated bytes (Blue=1, Red=2, etc.)

**Chat Encoding (subtype 0x01):**

```
+--------+--------+--------//--------+--------+--------//--------+
| 0x01   |dest_type| dest_id (if any) | length |    UTF-8 text   |
+--------+--------+--------//--------+--------+--------//--------+
```

Destination types:

| dest_type | Destination | dest_id |
|-----------|-------------|---------|
| 0x00 | Broadcast (all) | (none) |
| 0x01 | Team | 1 byte team enum |
| 0x02 | Direct | 8 byte IID |

Team enumeration (matches PLI team byte):

| Byte | Team |
|------|------|
| 0x01 | Blue |
| 0x02 | Red |
| 0x03 | Green |
| 0x04 | Orange |
| 0x05 | Magenta |
| 0x06 | Maroon |
| 0x07 | Purple |
| 0x08 | Teal |
| 0x09 | White |
| 0x0A | Yellow |

Examples:
- Broadcast: `[0x01][0x00][len][text]` -- 3 + len bytes
- Team Blue: `[0x01][0x01][0x01][len][text]` -- 4 + len bytes
- Direct to IID: `[0x01][0x02][8-byte IID][len][text]` -- 11 + len bytes

Sender identity comes from LICHEN L2/OSCORE context, not the CoT payload.

Gateways expand compact CoT to full XML for ATAK interoperability.

#### 10.1.2. SenML (Port 5682)

Sensor Measurement Lists (RFC 8428) in CBOR encoding. Self-describing
sensor data with units, timestamps, and values.

```cbor
[
  {"bn": "urn:dev:mac:0011223344556677/", "bt": 1234567890},
  {"n": "temperature", "u": "Cel", "v": 23.5},
  {"n": "humidity", "u": "%RH", "v": 65}
]
```

SCHC compresses repeated field names across packets. For bandwidth-critical
deployments, a SenML Compact Profile MAY use integer keys and implied units
while remaining RFC 8428 compliant.

IPSO Smart Object IDs (3303=temperature, 3304=humidity, etc.) provide
standard vocabulary for sensor types.

**Why SenML over Cayenne LPP as primary?**

Both encode sensor data compactly. SenML is IETF (RFC 8428); Cayenne is
LoRa Alliance. LICHEN's value proposition is "IETF standards all the way
down." SenML also self-describes (field names, units), while Cayenne
requires receivers to know the schema. SCHC amortizes SenML's field name
overhead across packets. Cayenne remains available (port 5685) for
bandwidth-critical deployments or LoRaWAN gateway interop.

#### 10.1.3. Cayenne LPP (Port 5685)

Low Power Payload format defined by the LoRa Alliance. Compact binary
encoding with implicit schemas.

```
[channel:1][type:1][value:N]
```

Type codes:
- 103: Temperature (2 bytes, 0.1°C resolution)
- 104: Humidity (1 byte, 0.5% resolution)
- 115: Barometer (2 bytes, 0.1 hPa resolution)
- 136: GPS (9 bytes: lat/lon/alt)

**When to use Cayenne vs SenML:**

| Consideration | Cayenne | SenML |
|---------------|---------|-------|
| Wire size | ~4 bytes/reading | ~25 bytes/reading (before SCHC) |
| Self-describing | No | Yes |
| Standards body | LoRa Alliance | IETF |
| Schema flexibility | Fixed type codes | Arbitrary names/units |
| Gateway interop | LoRaWAN native | IETF ecosystem |

Use Cayenne when every byte counts and sensor types are fixed. Use SenML
for flexibility, self-description, or when SCHC compression amortizes the
overhead across multiple readings per packet.

#### 10.1.4. APRS-IS (Port 5686)

Automatic Packet Reporting System in Internet Service format. ASCII
position reports, status messages, and telemetry compatible with amateur
radio APRS networks.

**Why APRS-IS, not AX.25?**

Traditional APRS runs over AX.25, which provides link-layer framing
(callsigns, control fields, CRC). LICHEN already has its own link layer
with addressing, integrity, and authentication. AX.25 framing would be
redundant overhead. APRS-IS is the payload format used on APRS internet
servers -- same position/message encoding, no link-layer baggage.

Payloads are ASCII APRS data:

```
!4903.50N/07201.75W-PHG2360/LICHEN node
```

Format characters:
- `!` or `/`: Position report
- `@`: Timestamped position
- `:`: Message
- `>`: Status
- `T`: Telemetry

Gateways reconstruct AX.25 framing when bridging to RF APRS or forward
directly to APRS-IS servers over TCP.

#### 10.1.5. NMEA (Port 5687)

NMEA 0183 ASCII sentences for GPS and navigation data. Direct passthrough
of standard sentences:

```
$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,47.0,M,,*47
$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A
```

Useful for bridging legacy GPS devices or marine equipment. Gateways may
convert to SenML or CoT for integration with other systems.

### 10.2. CoAP (Port 5683)

Constrained Application Protocol (RFC 7252) provides REST-like semantics
for constrained devices. Use CoAP when applications require:

- Request/response semantics (GET, PUT, POST, DELETE)
- Resource addressing (URI paths)
- Content negotiation (Content-Format option)
- Observation (RFC 7641)
- Reliable delivery (Confirmable messages)

**Why one CoAP port covers IPSO, LwM2M, Matter, and custom REST?**

These are all CoAP on the wire. They differ in resource paths and payload
schemas, not transport. CoAP's Content-Format option and URI structure
provide the dispatch mechanism:

- IPSO: `/3303/0/5700` (temperature sensor, instance 0, value)
- LwM2M: `/rd`, `/bs` (registration, bootstrap)
- Matter: `/oic/*` (OCF-derived paths)
- Custom: Application-defined paths

Separate ports would fragment the CoAP ecosystem and complicate firewall
rules. One port, many applications.

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

CoAP adds 4-10 bytes overhead but provides the semantics required for
device management, configuration, and complex interactions.

#### 10.2.1. Content-Format Dispatch

CoAP's Content-Format option identifies payload type:

| Value | Media Type | Use |
|-------|------------|-----|
| 0 | text/plain | Simple text |
| 60 | application/cbor | Generic CBOR |
| 110 | application/senml+json | SenML (JSON) |
| 112 | application/senml+cbor | SenML sensors |
| 11542 | application/vnd.ocf+cbor | OCF/IoTivity |

IPSO Smart Objects, LwM2M, and similar frameworks use CoAP with standard
Content-Format values and well-known resource paths (`/3303/0` for
temperature sensor instance 0).

#### 10.2.2. CoAP Parameters for LoRa

RFC 7252 defaults are tuned for low-latency networks. LoRa mesh requires
adjusted parameters to avoid retry storms and duty cycle violations.

**Transmission Parameters:**

| Parameter | RFC 7252 Default | LICHEN Value | Rationale |
|-----------|------------------|--------------|-----------|
| ACK_TIMEOUT | 2 s | 15 s | Multi-hop RTT can exceed 10s |
| ACK_RANDOM_FACTOR | 1.5 | 2.0 | More jitter reduces collision |
| MAX_RETRANSMIT | 4 | 2 | Fewer retries, fail faster |
| NSTART | 1 | 1 | Keep 1 outstanding CON |
| LEISURE | 5 s | 15 s | Multicast response spread |
| PROBING_RATE | 1 B/s | 0.1 B/s | Respect duty cycle |

With LICHEN values: retries at 15-30s, 30-60s, give up at ~90s.

**Prefer NON Messages:**

For most telemetry and notifications, use NON (non-confirmable):
- No retry overhead
- Application handles reliability if needed (e.g., delivery receipts)
- Suitable for periodic sensor readings, position beacons

Use CON only when delivery confirmation is critical:
- Configuration changes
- Firmware update blocks
- SOS acknowledgments

#### 10.2.3. Duty Cycle Awareness

Nodes MUST track duty cycle usage and throttle transmissions accordingly.

**Duty Cycle Tracking:**

```
Per-channel state:
  last_tx_end: <monotonic uptime>
  tx_time_window: <rolling 1-hour sum of airtime>
  duty_limit: <region-specific, e.g., 0.01 for EU 868 sub-band>
```

Note: `last_tx_end` uses monotonic uptime (not wall-clock time) because duty
cycle accounting must work even when wall-clock time is unavailable. The
rolling window is tracked via uptime deltas.

**Congestion Levels:**

| Level | Duty Used | Action |
|-------|-----------|--------|
| Normal | <50% of limit | Transmit normally |
| Elevated | 50-80% | Delay non-urgent traffic, increase backoff |
| Critical | 80-95% | Only SOS/routing, shed application traffic |
| Exhausted | >95% | Stop TX until window rolls over |

**Load Shedding:**

When congested, respond to new requests with:

```
5.03 Service Unavailable
Max-Age: <seconds until duty cycle recovers>
Content-Format: application/cbor
{
  "reason": "duty_cycle",
  "retry_after": 120,
  "level": "critical"
}
```

Senders receiving 5.03 MUST back off for the indicated duration.

**Priority Queue:**

TX queue ordered by priority:

| Priority | Traffic Type |
|----------|--------------|
| 0 (highest) | SOS, emergency |
| 1 | RPL control (DIO, DAO) |
| 2 | CoAP CON, tactical chat |
| 3 | CoAP NON, telemetry, position |
| 4 (lowest) | Bulk transfer, firmware |

During congestion, low-priority traffic is dropped first.

**Application-to-Priority Mapping:**

| Port | Application | Subtype/Condition | Priority |
|------|-------------|-------------------|----------|
| 5681 | Compact CoT | Alert (0x20) | P0 |
| 5681 | Compact CoT | Chat (0x01) | P2 |
| 5681 | Compact CoT | PLI (0x02-0x05) | P3 |
| 5681 | Compact CoT | Marker (0x10) | P3 |
| 5682 | SenML | All | P3 |
| 5683 | CoAP | CON | P2 |
| 5683 | CoAP | NON | P3 |
| 5685 | Cayenne | All | P3 |
| 5686 | APRS-IS | All | P3 |
| 5687 | NMEA | All | P3 |
| 10883 | MQTT-SN | QoS 1+ | P2 |
| 10883 | MQTT-SN | QoS 0/-1 | P3 |

Tactical chat (CoT subtype 0x01) is elevated to P2 because tac messaging
typically carries time-sensitive coordination. Routine PLI and telemetry
remain at P3. CoT alerts jump to P0--they are emergency traffic.

### 10.3. CoAP Observe (RFC 7641)

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

Observe reduces polling overhead but requires state on both endpoints.
Use for slowly-changing resources where push notification saves bandwidth.

### 10.4. MQTT-SN (Port 10883)

MQTT for Sensor Networks (OASIS standard) provides publish/subscribe
messaging over UDP.

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

#### 10.4.1. MQTT-SN Gateway Architecture

```
[Sensor Node] --LoRa--> [MQTT-SN Gateway] --IP--> [MQTT Broker]
                              |
                        [Border Router]
```

Gateway at border router translates MQTT-SN <-> MQTT 3.1.1/5.0.

MQTT-SN requires a dedicated SCHC rule for port 10883 compression. The rule
matches port 10883 exactly (not-sent encoding) for minimal overhead.

### 10.5. Fragmentation

**CoAP Block-wise (RFC 7959) is NOT RECOMMENDED for LICHEN.**

SCHC fragmentation (RFC 8724) handles all packet fragmentation at the
adaptation layer. Using CoAP block-wise creates redundant fragmentation
with worse performance characteristics for LoRa.

**Why SCHC fragmentation is preferred:**

| Aspect | CoAP Block-wise | SCHC Fragmentation |
|--------|-----------------|-------------------|
| Designed for | Reliable networks | LPWAN (LoRa) |
| ACK overhead | Per-block ACK required | ACK-on-Error (sparse) |
| Recovery | Application must retry | L2 handles retransmission |
| State | Both endpoints track | Receiver reassembles |

**SCHC fragmentation capacity:**

```
FCN: 6 bits -> 63 tiles per window
Windows: 2
Tile size: 187 bytes
Encoding ceiling: 126 × 187 = 23,562 bytes
Mandatory receiver capacity: 1281 bytes
```

Most LICHEN traffic (telemetry, messages, config) is <1 KB and requires
no fragmentation. SCHC handles the rare larger payloads transparently.

**Large Transfers (Firmware, Bulk Data):**

For payloads exceeding the receiver's known reassembly limit, use
application-level chunking. If the limit is unknown, chunks MUST fit the
mandatory 1281-byte SCHC receiver capacity:

```
Application Chunking Protocol:
1. Sender: POST /firmware/upload {chunk: 0, total: 500, data: <1KB>}
2. Receiver: 2.04 Changed {received: 0}
3. Sender: POST /firmware/upload {chunk: 1, total: 500, data: <1KB>}
4. ... repeat ...
5. Receiver: 2.01 Created {status: "complete", hash: "..."}
```

Each chunk fits in one SCHC transaction. Application tracks progress,
handles retries at chunk granularity.

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
