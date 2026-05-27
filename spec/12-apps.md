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

Implementation is OPTIONAL. Implementations that support store-and-forward
MUST comply with the limits below.

**Storage Limits:**

| Parameter | Minimum | Default | Maximum |
|-----------|---------|---------|---------|
| Total messages | 8 | 16 | 64 |
| Per-destination messages | 2 | 4 | 16 |
| Message size | 128 B | 256 B | 512 B |
| Total storage | 1 KB | 4 KB | 16 KB |
| Message TTL | 1 hour | 4 hours | 24 hours |

Nodes MUST support at least the minimum values. Constrained nodes (e.g.,
STM32WL) SHOULD use minimum values to preserve RAM for other functions.

**Eviction Policy:**

When storage is full, evict messages in this order:

1. **Expired messages:** TTL exceeded (always evict first)
2. **Per-destination fairness:** If one destination has more than fair share,
   evict its oldest message first
3. **FIFO:** Oldest message across all destinations

Fair share = total_messages / active_destinations. A destination with 8
messages when fair share is 4 has its oldest message evicted before a
destination with 2 messages.

**Back-Pressure Signaling:**

When a store-and-forward node cannot accept a message:

| Condition | Response Code | Meaning |
|-----------|---------------|---------|
| Storage full | 5.03 Service Unavailable | Retry later |
| Message too large | 4.13 Request Entity Too Large | Reduce size |
| Destination blacklisted | 4.03 Forbidden | Won't store for this dest |
| TTL too long | 4.00 Bad Request | Reduce TTL |

Example rejection:

```
POST coap://[store-node]/msg/store
Content-Format: application/cbor
{...message...}

Response: 5.03 Service Unavailable
Max-Age: 60              ; retry after 60 seconds
Content-Format: application/cbor
{
  "reason": "storage_full",
  "available": 0,
  "retry_after": 60
}
```

**Memory Reservation:**

Nodes SHOULD reserve store-and-forward memory statically at boot:

| Platform | Recommended S&F Budget |
|----------|------------------------|
| ESP32/nRF52840 | 4-8 KB |
| STM32WL | 1-2 KB |
| Border router | 16-64 KB |

Store-and-forward MUST NOT allocate memory dynamically in a way that
starves routing tables, network buffers, or other critical functions.

**Delivery:**

When destination becomes reachable:

1. Query routing table for destination
2. If reachable, deliver stored messages in FIFO order
3. Wait for ACK (if requested) before delivering next
4. On delivery failure, retain message (until TTL expires)
5. On successful delivery, delete from store

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
| group | Beacon to group only (encrypted), query requires group membership |
| private | No beacon, query requires pairwise OSCORE |
| off | GPS disabled, no position sharing |

```
GET coap://[node]/config/privacy
Content-Format: application/cbor

{"location": "group", "group_id": "team-alpha"}
```

**Query Authentication:**

Position queries (`GET /sensors/location`) are protected based on privacy mode:

| Mode | Authentication Required |
|------|------------------------|
| public | None |
| group | OSCORE with group context (see 18.8) |
| private | OSCORE with pairwise context (see 8.8 EDHOC) |

Unauthenticated queries to non-public nodes receive `4.01 Unauthorized`:

```
GET coap://[node]/sensors/location
(no OSCORE)

Response: 4.01 Unauthorized
Content-Format: application/cbor
{"error": "oscore_required", "mode": "private"}
```

**Group Beacon Encryption:**

In `group` mode, position beacons are encrypted with the group OSCORE key:

```
PUT coap://[ff35:...group-mcast]/pos
Content-Format: application/senml+cbor
OSCORE: <group context, key_id=key-alpha-001>

[encrypted position SenML]
```

Only group members can decrypt the beacon. Non-members see:
- That a transmission occurred (presence)
- Encrypted payload (no location data)

**Private Mode Behavior:**

In `private` mode:
- No beacons transmitted
- Position revealed only to peers with established OSCORE context
- Node must explicitly allow each peer (whitelist)

```
PUT coap://[node]/config/privacy/allowed
Content-Format: application/cbor

{"peers": ["fd12:...:1111", "fd12:...:2222"]}
```

Only whitelisted peers' OSCORE-protected queries are answered.

**Presence vs Location Privacy:**

| What | Can Be Hidden? |
|------|---------------|
| Location (lat/lon) | Yes (encryption) |
| Presence (node exists) | **No** |

**Important limitation:** Even with encryption, passive observers can detect:
- That a node is transmitting (radio activity)
- Approximate node location via RF direction-finding
- Communication patterns (who talks to whom)

True presence hiding requires cover traffic (constant dummy transmissions),
which is impractical on duty-cycle-limited LoRa. LICHEN does not attempt
to hide presence—only location content.

For high-security scenarios requiring presence hiding, consider:
- Radio silence (off mode)
- Physical security (Faraday, remote deployment)
- Accepting presence disclosure as operational constraint

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

#### 18.4.1. SOS Authentication and Rate Limiting

SOS messages are high-priority and trigger network-wide flooding. Without
controls, fake SOS floods cause denial of service. All SOS messages MUST
be authenticated and rate-limited.

**Authentication (REQUIRED):**

SOS messages MUST carry a valid link-layer signature from the originating
node. The Ed25519/Schnorr signature is verified at each receiving node
before rebroadcast. Unsigned or invalid SOS messages are silently dropped.

```
SOS frame = [LLSec header] [SOS payload] [Schnorr signature (48B)]
```

**Rate Limiting (REQUIRED):**

Each node enforces per-source SOS rate limits:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| SOS cooldown | 10 minutes | Prevents accidental spam |
| Max SOS per hour | 3 | Limits intentional abuse |
| Burst allowance | 2 | Allows rapid updates to same SOS |

Nodes track (source IID, SOS count, last SOS timestamp). An SOS from
a node that exceeds rate limits is dropped and logged but not relayed.

**Soft Blacklist (RECOMMENDED):**

Nodes MAY implement reputation tracking for SOS abuse:

| Violation | Reputation Impact |
|-----------|-------------------|
| SOS cancelled within 5 min | -1 point |
| Repeated SOS without response | -2 points |
| False SOS confirmed by operator | -10 points |
| Valid emergency confirmed | Reset to 0 |

Nodes with reputation below threshold (-10) have their SOS messages
delayed or dropped entirely. Blacklist entries expire after 7 days
without violations.

**Operator Override:**

Nodes SHOULD support operator commands to:
- Clear rate limit for a specific node (emergency responder scenario)
- Manually blacklist/whitelist nodes
- Disable rate limiting entirely (trusted network)

#### 18.4.2. Emergency Alert Format

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

#### 18.4.3. Sending Emergency Alert

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

#### 18.4.4. SOS Button Behavior

Hardware SOS button (if present):

| Action | Result |
|--------|--------|
| Press and hold 3s | Initiate SOS |
| Triple-press | Initiate SOS |
| Press during SOS | Send update with current position |
| Hold 5s during SOS | Cancel SOS |

#### 18.4.5. Emergency Resources

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

#### 18.4.6. Network Behavior During Emergency

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
  "owner": "fd12:...:1111",                ; group creator
  "admins": ["fd12:...:2222"],             ; delegated admins
  "members": [
    "fd12:...:1111",
    "fd12:...:2222",
    "fd12:...:3333"
  ],
  "key_id": "key-alpha-001",   ; OSCORE Group key reference (optional)
  "created": 1716742800,
  "key_epoch": 1               ; increments on rekey
}
```

#### 18.8.2. Group Membership Protocol

**Roles:**

| Role | Capabilities |
|------|--------------|
| Owner | Full control: delete group, promote/demote admins, invite/remove anyone |
| Admin | Invite members, remove members (not owner/admins), distribute keys |
| Member | Send/receive group messages, view membership |

Owner is always a member. Admins are always members.

**Group Creation:**

```
POST coap://[creator-node]/groups
Content-Format: application/cbor

{
  "name": "Team Alpha",
  "encrypted": true    ; whether to use OSCORE Group
}

Response: 2.01 Created
Location-Path: /groups/team-alpha
Content-Format: application/cbor

{
  "id": "team-alpha",
  "mcast": "ff35:0040:...",
  "key_id": "key-alpha-001",   ; if encrypted
  "master_secret": "<base64>"  ; only in creation response
}
```

Creator automatically becomes owner. Group ID derived from name hash or
randomly generated.

**Invitations:**

Owner or admin invites a node:

```
POST coap://[target-node]/groups/invite
Content-Format: application/cbor

{
  "group_id": "team-alpha",
  "group_name": "Team Alpha",
  "mcast": "ff35:0040:...",
  "inviter": "fd12:...:1111",
  "role": "member",            ; "member" or "admin"
  "expires": 1716829200,       ; invitation expiry
  "signature": "<inviter's signature over above fields>"
}

Response: 2.04 Changed (accepted) or 4.03 Forbidden (declined)
```

Target validates inviter's signature. If accepted, target adds group to
local store and requests key (if encrypted).

**Key Distribution:**

For encrypted groups, new members request the group key:

```
POST coap://[inviter]/groups/team-alpha/key
Content-Format: application/cbor
OSCORE: <secured with pairwise context>

{
  "request": "join_key",
  "node": "fd12:...:3333"
}

Response: 2.05 Content
Content-Format: application/cbor
OSCORE: <secured with pairwise context>

{
  "key_id": "key-alpha-001",
  "key_epoch": 1,
  "master_secret": "<32 bytes, base64>",
  "master_salt": "<8 bytes, base64>",
  "algorithm": "AES-CCM-16-64-128"
}
```

Key is sent over the existing pairwise OSCORE context (established via
EDHOC) between inviter and new member. Never sent in plaintext.

**Leaving a Group:**

Member voluntarily leaves:

```
DELETE coap://[own-node]/groups/team-alpha

Response: 2.02 Deleted
```

Node removes group from local store, deletes key material.

**Removal by Admin/Owner:**

```
POST coap://[target-node]/groups/remove
Content-Format: application/cbor

{
  "group_id": "team-alpha",
  "removed_by": "fd12:...:1111",
  "reason": "no longer on team",
  "signature": "<remover's signature>"
}

Response: 2.04 Changed
```

Target validates signature is from owner or admin, then deletes group.

**Membership Synchronization:**

Full membership list is NOT broadcast (privacy). Nodes track:
- Groups they belong to (local)
- Who invited them (can request updated member list)

Owner/admins maintain authoritative member list:

```
GET coap://[owner]/groups/team-alpha/members
OSCORE: <group context>

Response: 2.05 Content
{
  "owner": "fd12:...:1111",
  "admins": ["fd12:...:2222"],
  "members": ["fd12:...:3333", "fd12:...:4444"]
}
```

**Rekeying:**

When a member is removed, the group key SHOULD be rotated:

1. Owner/admin generates new master_secret
2. Increment key_epoch
3. Distribute new key to remaining members via pairwise OSCORE
4. Old key_epoch rejected after grace period (1 hour)

Rekeying is NOT required for voluntary leaves (member already has key,
but is trusted not to abuse it).

**Admin Delegation:**

```
POST coap://[owner]/groups/team-alpha/admins
Content-Format: application/cbor

{
  "action": "promote",
  "node": "fd12:...:2222"
}

Response: 2.04 Changed
```

Only owner can promote/demote admins.

#### 18.8.3. Group Multicast Addressing

Per RFC 7390 and RFC 3306 (unicast-prefix-based multicast):

```
ff35:0040:<64-bit ULA prefix>::<16-bit group ID>
```

Example: Group 1 on mesh `fd12:3456:789a:1::/64`:
```
ff35:0040:fd12:3456:789a:0001::0001
```

#### 18.8.4. Group Resources

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

#### 18.8.5. Group Key Management

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
