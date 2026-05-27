<!-- Part of LICHEN Protocol Specification -->

# Applications

## 18. Applications

This section defines standard application-layer features using IETF protocols.
All features use CoAP (RFC 7252) with CBOR payloads and leverage existing
standards wherever possible.

### 18.1. Messaging

Text messaging between nodes, supporting unicast, multicast, and broadcast.

**Relevant Standards:**
- CoAP (RFC 7252) for transport
- CoAP Observe (RFC 7641) for push notifications
- CBOR (RFC 8949) for encoding

#### 18.1.1. Message Format

```cbor
{
  "id": 12345,                    ; unique message ID (uint)
  "from": "fd12:...:1111",        ; sender IPv6 (string)
  "to": "fd12:...:2222",          ; recipient or "ff02::1" for broadcast (string)
  "ts": 1716742800,               ; Unix timestamp (uint)
  "body": "Hello from the mesh",  ; message text (tstr)
  "ack": true,                    ; request delivery receipt (bool, optional)
  "priority": 0,                  ; 0=normal, 1=high, 2=emergency (uint, optional)
  "reply_to": 12340,              ; references previous message (uint, optional)
  "ttl": 3600                     ; message expires after N seconds (uint, optional)
}
```

#### 18.1.2. Resources

**Send Message:**

```
POST coap://[destination]/msg/inbox
Content-Format: application/cbor

{
  "body": "Hello!",
  "ack": true
}

Response: 2.01 Created
Location-Path: /msg/sent/12345
```

For broadcast, POST to `coap://[ff02::1]/msg/inbox` (link-local all-nodes)
or use the mesh multicast address.

**Receive Messages (Observable):**

```
GET coap://[node]/msg/inbox
Observe: 0
Content-Format: application/cbor

{
  "messages": [
    {"id": 123, "from": "...", "ts": ..., "body": "Hi"}
  ],
  "unread": 3
}
```

New messages trigger Observe notifications.

**Delivery Receipt:**

When `ack: true`, recipient sends:

```
POST coap://[sender]/msg/ack
Content-Format: application/cbor

{
  "id": 12345,
  "status": "delivered",    ; "delivered", "read", "failed"
  "ts": 1716742900
}
```

#### 18.1.3. Canned Messages

Pre-defined messages for quick sending (configurable):

```
GET coap://[node]/msg/canned
Content-Format: application/cbor

{
  "messages": [
    {"id": 0, "text": "I'm OK"},
    {"id": 1, "text": "Need assistance"},
    {"id": 2, "text": "At checkpoint"},
    {"id": 3, "text": "Returning to base"},
    {"id": 4, "text": "Emergency - send help"}
  ]
}
```

```
POST coap://[destination]/msg/inbox
Content-Format: application/cbor

{"canned": 4, "ack": true}
```

#### 18.1.4. Store-and-Forward

Nodes MAY implement store-and-forward for offline recipients:

1. Sender POSTs to destination
2. If destination unreachable, intermediate node stores message
3. When destination appears, stored messages are delivered
4. TTL prevents unbounded storage

Store-and-forward nodes advertise capability:

```
GET /.well-known/core?rt=msg.store

</msg/store>;rt="msg.store"
```

Implementation is OPTIONAL. Maximum stored messages and TTL are
implementation-defined.

### 18.2. Position Sharing

Real-time location sharing for mutual awareness ("blue force tracking").

**Relevant Standards:**
- SenML (RFC 8428) for data format (see Appendix F)
- CoAP Observe (RFC 7641) for streaming
- GeoJSON (RFC 7946) for waypoint concepts

#### 18.2.1. Position Beacon

Nodes with GPS SHOULD periodically broadcast position:

```
PUT coap://[ff02::1]/pos
Content-Format: application/senml+cbor

[
  {"bn": "urn:dev:mac:0011223344556677:", "bt": 1716742800},
  {"n": "lat", "u": "lat", "v": 37.774929},
  {"n": "lon", "u": "lon", "v": -122.419416}
]
```

Beacon interval: configurable, default 60 seconds when moving, 300 when stationary.

Nodes receiving beacons update their position cache:

```
GET coap://[node]/pos/cache
Content-Format: application/cbor

{
  "positions": [
    {
      "node": "fd12:...:1111",
      "lat": 37.774929,
      "lon": -122.419416,
      "alt": 10.5,
      "ts": 1716742800,
      "age_s": 45
    }
  ]
}
```

#### 18.2.2. Position Query

Request current position from specific node:

```
GET coap://[target]/sensors/location
Content-Format: application/senml+cbor

[
  {"bn": "urn:dev:mac:...", "bt": 1716742800},
  {"n": "lat", "u": "lat", "v": 37.774929},
  {"n": "lon", "u": "lon", "v": -122.419416},
  {"n": "alt", "u": "m", "v": 10.5},
  {"n": "speed", "u": "m/s", "v": 1.2},
  {"n": "heading", "u": "deg", "v": 45}
]
```

#### 18.2.3. Position Subscribe

Observe a node's position for continuous tracking:

```
GET coap://[target]/sensors/location
Observe: 0

<-- 2.05 Content (initial position)
<-- 2.05 Content (notification on movement)
...
```

Notification triggers: distance threshold (e.g., 50m) or time interval.

#### 18.2.4. Privacy Considerations

Nodes MAY implement position privacy:

| Setting | Behavior |
|---------|----------|
| public | Beacon to all, respond to queries |
| group | Beacon to group only, query requires auth |
| private | No beacon, query requires explicit auth |
| off | GPS disabled, no position sharing |

```
GET coap://[node]/config/privacy
Content-Format: application/cbor

{"location": "group"}
```

### 18.3. Waypoints

Shareable points of interest with metadata.

**Relevant Standards:**
- GeoJSON (RFC 7946) concepts, CBOR-encoded
- CoAP Resource Directory (RFC 9176) for discovery

#### 18.3.1. Waypoint Format

```cbor
{
  "id": "wpt-001",              ; unique ID (tstr)
  "name": "Rally Point Alpha",  ; human-readable name (tstr)
  "lat": 37.774929,             ; WGS84 latitude (float)
  "lon": -122.419416,           ; WGS84 longitude (float)
  "alt": 10.5,                  ; altitude meters (float, optional)
  "icon": "flag",               ; icon hint (tstr, optional)
  "color": "#FF0000",           ; color hint (tstr, optional)
  "notes": "Meet here at 1400", ; description (tstr, optional)
  "created": 1716742800,        ; creation time (uint)
  "creator": "fd12:...:1111",   ; creator node (tstr)
  "expires": 1716829200         ; expiration time (uint, optional)
}
```

Icon values (suggested): `flag`, `marker`, `camp`, `water`, `danger`,
`medical`, `vehicle`, `poi`, `start`, `finish`, `checkpoint`.

#### 18.3.2. Resources

**List Waypoints:**

```
GET coap://[node]/waypoints
Content-Format: application/cbor

{
  "waypoints": [
    {"id": "wpt-001", "name": "Rally Point Alpha", "lat": ..., "lon": ...},
    {"id": "wpt-002", "name": "Water Source", "lat": ..., "lon": ...}
  ]
}
```

**Get Single Waypoint:**

```
GET coap://[node]/waypoints/wpt-001
Content-Format: application/cbor

{"id": "wpt-001", "name": "Rally Point Alpha", ...}
```

**Create Waypoint:**

```
POST coap://[node]/waypoints
Content-Format: application/cbor

{
  "name": "Checkpoint 3",
  "lat": 37.78,
  "lon": -122.42,
  "icon": "checkpoint"
}

Response: 2.01 Created
Location-Path: /waypoints/wpt-003
```

**Share Waypoint:**

```
POST coap://[destination]/waypoints
Content-Format: application/cbor

{
  "name": "Rally Point Alpha",
  "lat": 37.774929,
  "lon": -122.419416,
  "notes": "Meet here at 1400",
  "creator": "fd12:...:1111"
}

Response: 2.01 Created
```

**Broadcast Waypoint:**

```
POST coap://[ff02::1]/waypoints
Content-Format: application/cbor

{...waypoint...}
```

**Delete Waypoint:**

```
DELETE coap://[node]/waypoints/wpt-001

Response: 2.02 Deleted
```

#### 18.3.3. Routes

Ordered list of waypoints:

```cbor
{
  "id": "route-001",
  "name": "Patrol Route A",
  "waypoints": ["wpt-001", "wpt-002", "wpt-003"],
  "distance_m": 2500,           ; total distance (uint, optional)
  "created": 1716742800,
  "creator": "fd12:...:1111"
}
```

Resources: `/routes`, `/routes/{id}` - same CRUD pattern as waypoints.

### 18.4. Emergency / SOS

Priority alerting for emergencies.

**Relevant Standards:**
- CoAP (RFC 7252)
- CAP concepts (OASIS Common Alerting Protocol) for alert structure

#### 18.4.1. Emergency Alert Format

```cbor
{
  "type": "sos",               ; "sos", "medical", "security", "cancel" (tstr)
  "node": "fd12:...:1111",     ; originating node (tstr)
  "ts": 1716742800,            ; timestamp (uint)
  "lat": 37.774929,            ; position if available (float, optional)
  "lon": -122.419416,          ; (float, optional)
  "msg": "Injured, need evac", ; details (tstr, optional)
  "seq": 1                     ; sequence for updates (uint)
}
```

Alert types:

| Type | Meaning |
|------|---------|
| sos | General emergency |
| medical | Medical emergency |
| security | Security threat |
| fire | Fire emergency |
| cancel | Cancel previous alert |

#### 18.4.2. Sending Emergency Alert

**Dedicated SOS endpoint with multicast:**

```
POST coap://[ff02::1]/sos
Content-Format: application/cbor

{
  "type": "sos",
  "msg": "Injured, need help"
}

Response: 2.01 Created
```

Nodes receiving SOS:
1. Display alert prominently
2. Re-broadcast once (controlled flooding, TTL-limited)
3. Log to `/sos/log`

#### 18.4.3. SOS Button Behavior

Hardware SOS button (if present):

| Action | Result |
|--------|--------|
| Press and hold 3s | Initiate SOS |
| Triple-press | Initiate SOS |
| Press during SOS | Send update with current position |
| Hold 5s during SOS | Cancel SOS |

#### 18.4.4. Emergency Resources

**View Active Emergencies:**

```
GET coap://[node]/sos
Content-Format: application/cbor

{
  "active": [
    {
      "node": "fd12:...:1111",
      "type": "medical",
      "ts": 1716742800,
      "lat": 37.77,
      "lon": -122.42,
      "msg": "Broken leg"
    }
  ]
}
```

**Emergency Log:**

```
GET coap://[node]/sos/log
Content-Format: application/cbor

{
  "events": [
    {"ts": 1716742800, "node": "...", "type": "sos", "action": "initiated"},
    {"ts": 1716743000, "node": "...", "type": "sos", "action": "cancelled"}
  ]
}
```

#### 18.4.5. Network Behavior During Emergency

When SOS is active:

1. **Priority routing:** SOS packets get priority in TX queue
2. **Beacon boost:** Originating node beacons position every 30s
3. **Relay duty:** All nodes relay SOS (once per SOS ID)
4. **Persistence:** SOS remains active until cancelled or 4-hour timeout

### 18.5. Presence and Status

Node availability and activity status.

**Relevant Standards:**
- PIDF concepts (RFC 3863) simplified for CBOR
- CoAP Observe (RFC 7641)

#### 18.5.1. Presence Format

```cbor
{
  "status": "available",      ; presence status (tstr)
  "activity": "moving",       ; activity hint (tstr, optional)
  "msg": "On patrol",         ; custom status message (tstr, optional)
  "battery": 87,              ; battery percentage (uint, optional)
  "ts": 1716742800            ; last update (uint)
}
```

Status values (based on RFC 3863 simplified):

| Status | Meaning |
|--------|---------|
| available | Online and reachable |
| busy | Online but occupied |
| away | Temporarily unavailable |
| offline | Not reachable |
| emergency | In emergency state |

Activity values (optional refinement):

| Activity | Meaning |
|----------|---------|
| stationary | Not moving |
| moving | In motion |
| resting | Taking break |
| working | Performing task |

#### 18.5.2. Resources

**Get/Set Own Presence:**

```
GET coap://[node]/presence
Content-Format: application/cbor

{"status": "available", "activity": "moving", "battery": 87}
```

```
PUT coap://[node]/presence
Content-Format: application/cbor

{"status": "busy", "msg": "In meeting"}

Response: 2.04 Changed
```

**Subscribe to Peer Presence:**

```
GET coap://[peer]/presence
Observe: 0

<-- 2.05 Content {"status": "available", ...}
<-- 2.05 Content {"status": "away", ...}  (on change)
```

**Presence Cache (All Known Nodes):**

```
GET coap://[node]/presence/cache
Content-Format: application/cbor

{
  "nodes": [
    {"addr": "fd12:...:1111", "status": "available", "battery": 87, "age_s": 30},
    {"addr": "fd12:...:2222", "status": "away", "battery": 45, "age_s": 120}
  ]
}
```

#### 18.5.3. Automatic Status

Nodes SHOULD automatically update status based on:

| Condition | Status | Activity |
|-----------|--------|----------|
| GPS shows movement | available | moving |
| GPS stationary > 5min | available | stationary |
| No user interaction > 30min | away | - |
| SOS active | emergency | - |
| Battery < 10% | (unchanged) | (add low_battery flag) |

### 18.6. Check-In / Roll Call

Group accountability and safety checks.

**Relevant Standards:**
- CoAP Group Communication (RFC 7390)
- CoAP Observe (RFC 7641)

#### 18.6.1. Check-In

Individual node checks in with group/leader:

```
POST coap://[leader]/checkin
Content-Format: application/cbor

{
  "node": "fd12:...:1111",
  "ts": 1716742800,
  "lat": 37.77,
  "lon": -122.42,
  "status": "ok",              ; "ok", "help", "delayed"
  "msg": "At checkpoint 2"     ; optional note
}

Response: 2.04 Changed
```

#### 18.6.2. Roll Call (Group Query)

Leader initiates roll call via multicast:

```
POST coap://[ff02::mesh]/rollcall
Content-Format: application/cbor

{
  "id": "roll-001",
  "from": "fd12:...:leader",
  "ts": 1716742800,
  "timeout_s": 60
}
```

Nodes respond with unicast check-in to leader.

#### 18.6.3. Roll Call Status

Leader tracks responses:

```
GET coap://[leader]/rollcall/roll-001
Content-Format: application/cbor

{
  "id": "roll-001",
  "started": 1716742800,
  "timeout_s": 60,
  "responded": [
    {"node": "fd12:...:1111", "ts": 1716742810, "status": "ok"},
    {"node": "fd12:...:2222", "ts": 1716742815, "status": "ok"}
  ],
  "missing": [
    {"node": "fd12:...:3333", "last_seen": 1716740000}
  ]
}
```

#### 18.6.4. Scheduled Check-Ins

Nodes can be configured for automatic periodic check-in:

```
PUT coap://[node]/config/checkin
Content-Format: application/cbor

{
  "enabled": true,
  "target": "fd12:...:leader",
  "interval_s": 900,           ; every 15 minutes
  "include_location": true
}
```

Missed check-ins trigger alerts (see 18.4).

### 18.7. Range Testing

Link quality diagnostics.

**Relevant Standards:**
- ICMPv6 Echo (RFC 4443)
- SenML (RFC 8428) for telemetry response

#### 18.7.1. Basic Ping

Standard ICMPv6 Echo Request/Reply for reachability:

```
ping6 fd12:3456:789a:1::1111
```

Returns: RTT, reachable/unreachable.

#### 18.7.2. Extended Range Test

Application-layer test with radio telemetry:

```
POST coap://[target]/diag/rangetest
Content-Format: application/cbor

{
  "seq": 1,
  "payload_len": 32,          ; optional: test with specific payload size
  "count": 5                  ; optional: request N responses
}

Response: 2.05 Content
Content-Format: application/senml+cbor

[
  {"bn": "urn:dev:mac:...", "bt": 1716742800},
  {"n": "seq", "v": 1},
  {"n": "rssi", "u": "dBm", "v": -85},
  {"n": "snr", "u": "dB", "v": 7.5},
  {"n": "sf", "v": 9},
  {"n": "freq", "u": "MHz", "v": 906.875}
]
```

#### 18.7.3. Continuous Range Test

For walk/drive testing:

```
GET coap://[target]/diag/rangetest
Observe: 0
Content-Format: application/cbor

{"interval_ms": 5000}

<-- 2.05 Content (every 5s with RSSI/SNR)
```

#### 18.7.4. Trace Route

Discover path through mesh:

```
GET coap://[target]/diag/traceroute
Content-Format: application/cbor

{
  "hops": [
    {"addr": "fe80::1111", "rssi": -65, "rtt_ms": 120},
    {"addr": "fe80::2222", "rssi": -78, "rtt_ms": 340},
    {"addr": "fe80::3333", "rssi": -82, "rtt_ms": 580}
  ],
  "total_hops": 3,
  "total_rtt_ms": 580
}
```

Implementation: Uses RPL source routing information or hop-by-hop probing.

### 18.8. Groups and Channels

Logical separation of communication.

**Relevant Standards:**
- CoAP Group Communication (RFC 7390)
- OSCORE Group (RFC 9203) for group encryption

#### 18.8.1. Group Concept

Groups provide:
1. **Multicast address:** For group-wide broadcasts
2. **Encryption context:** Optional per-group OSCORE key
3. **Resource namespace:** `/groups/{gid}/...`

```cbor
{
  "id": "team-alpha",
  "name": "Team Alpha",
  "mcast": "ff35:40:fd12:3456:789a:1::1",  ; mesh-local multicast
  "members": [
    "fd12:...:1111",
    "fd12:...:2222",
    "fd12:...:3333"
  ],
  "key_id": "key-alpha-001"    ; OSCORE Group key reference (optional)
}
```

#### 18.8.2. Group Multicast Addressing

Per RFC 7390 and RFC 3306 (unicast-prefix-based multicast):

```
ff35:0040:<64-bit ULA prefix>::<16-bit group ID>
```

Example: Group 1 on mesh `fd12:3456:789a:1::/64`:
```
ff35:0040:fd12:3456:789a:0001::0001
```

#### 18.8.3. Group Resources

**List Groups:**

```
GET coap://[node]/groups
Content-Format: application/cbor

{
  "groups": [
    {"id": "team-alpha", "name": "Team Alpha", "members": 3},
    {"id": "all", "name": "All Nodes", "members": 12}
  ]
}
```

**Group Messaging:**

```
POST coap://[group-mcast]/msg/inbox
Content-Format: application/cbor

{"body": "Team Alpha, rally at checkpoint 2"}
```

**Group Position Sharing:**

```
PUT coap://[group-mcast]/pos
Content-Format: application/senml+cbor

[...position SenML...]
```

#### 18.8.4. Group Key Management

For encrypted groups (OSCORE Group per RFC 9203):

```
GET coap://[node]/groups/team-alpha/key
Content-Format: application/cbor

{
  "key_id": "key-alpha-001",
  "algorithm": "AES-CCM-16-64-128",
  "expires": 1716829200
}
```

Key distribution is out-of-band or via secure unicast to each member.

### 18.9. Resource Summary

| Resource | Methods | Observable | Description |
|----------|---------|------------|-------------|
| /msg/inbox | GET, POST | Yes | Message inbox |
| /msg/sent | GET | No | Sent messages |
| /msg/ack | POST | No | Delivery receipts |
| /msg/canned | GET, PUT | No | Preset messages |
| /pos | PUT | No | Position broadcast (multicast) |
| /pos/cache | GET | Yes | Cached peer positions |
| /waypoints | GET, POST | Yes | Waypoint list |
| /waypoints/{id} | GET, PUT, DELETE | No | Single waypoint |
| /routes | GET, POST | No | Route list |
| /routes/{id} | GET, PUT, DELETE | No | Single route |
| /sos | GET, POST | Yes | Emergency alerts |
| /sos/log | GET | No | Emergency history |
| /presence | GET, PUT | Yes | Own presence status |
| /presence/cache | GET | Yes | Peer presence cache |
| /checkin | POST | No | Check-in submission |
| /rollcall | POST | No | Initiate roll call |
| /rollcall/{id} | GET | Yes | Roll call status |
| /groups | GET, POST | No | Group list |
| /groups/{id} | GET, PUT, DELETE | No | Single group |
| /diag/rangetest | GET, POST | Yes | Range testing |
| /diag/traceroute | GET | No | Path discovery |

### 18.10. Content-Format Summary

| Content-Format | ID | Usage |
|----------------|-----|-------|
| application/cbor | 60 | General structured data |
| application/senml+cbor | 112 | Sensor/telemetry data |
| application/link-format | 40 | Resource discovery |

---

[← Previous: Local Client Interface](11-lci.md) | [Index](README.md) | [Next: Appendix A →](appendix-schc.md)
