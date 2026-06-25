# Meshtastic Compatibility Layer — Developer Guide

This document describes how LICHEN nodes expose a Meshtastic-compatible BLE interface, allowing unmodified Meshtastic apps to connect.

## Build Considerations

**This feature is off by default.** The Meshtastic adapter adds significant firmware size:

- Protobuf runtime and compiled schemas: ~15-20 KB
- GATT service and adapter logic: ~8-12 KB
- Total overhead: ~25-30 KB

To enable Meshtastic compatibility, explicitly request it at build time:

```
# Rust
cargo build --features meshtastic-compat

# Python (development/simulation only)
pip install lichen[meshtastic]
```

**Supported platforms:**
- ESP32 (via esp32-nimble)
- nRF52840 (via nrf-softdevice)
- Linux (via bluer, for testing)

**Not supported:**
- STM32WL (no BLE hardware—use serial transport instead)
- Native Zephyr (use Rust via FFI if needed)

Without this feature, users must use LICHEN-native apps (iOS, Android, CLI, or web) to interact with the node.

## Architecture

```
┌─────────────────────┐
│  Meshtastic App     │  Unmodified iOS/Android app
│  (iOS / Android)    │
└─────────┬───────────┘
          │ BLE GATT (Meshtastic protocol)
          ▼
┌─────────────────────┐
│  Meshtastic Adapter │  Translation shim
│  (on LICHEN node)   │
└─────────┬───────────┘
          │ Internal API
          ▼
┌─────────────────────┐
│  LICHEN Node        │  Standard LICHEN stack
│  (IPv6/CoAP/RPL)    │
└─────────┬───────────┘
          │ LICHEN link layer
          ▼
┌─────────────────────┐
│  LICHEN Mesh        │  Other LICHEN nodes
└─────────────────────┘
```

The adapter is a protocol translator. It:
- Presents Meshtastic's GATT service to BLE centrals
- Converts Meshtastic protobufs to LICHEN CoAP requests
- Maps LICHEN mesh state to Meshtastic's data model

Neither the Meshtastic app nor the LICHEN protocol are modified.

## Translation Design

This section explains the fundamental mismatches between Meshtastic and LICHEN, and how the adapter bridges them.

### Address Translation

**The problem:** Meshtastic uses 32-bit node numbers. LICHEN uses 64-bit IIDs derived from Ed25519 public keys.

**The solution:** Truncate LICHEN IIDs to 32 bits for Meshtastic display.

```
LICHEN IID (64 bits):  0x1a2b3c4d_5e6f7a8b
Meshtastic num (32b):  0x5e6f7a8b  (low 32 bits)
Meshtastic id string:  "!5e6f7a8b"
```

**Collision risk:** Two LICHEN nodes could have IIDs that share the same low 32 bits. This is unlikely (~1 in 4 billion) but possible. The Meshtastic app would show them as the same node. LICHEN itself uses full IIDs so routing is unaffected—only the app display is wrong.

**Reverse lookup:** When the app sends to a 32-bit destination, the adapter searches the peer table for an IID ending in those 32 bits. If no match, the message is dropped. Broadcast (0xFFFFFFFF) maps to IPv6 link-local all-nodes multicast.

### User Names (short_name, long_name)

**The problem:** Meshtastic stores user-configured names on each node. Users expect to set their name in the app and have it stick.

**The solution:** Ignore writes, synthesize reads.

- **long_name**: Read from the node's CoAP `/node` resource (if available), otherwise generate from IID: `"LICHEN-5e6f7a8b"`
- **short_name**: First 4 characters of long_name: `"LICH"` or `"5e6f"`
- **App writes**: Acknowledged but discarded. LICHEN node identity comes from the Ed25519 keypair, not user config.

The app may show a "saved" confirmation, but the name won't persist. This is intentional—LICHEN nodes don't store Meshtastic user profiles.

### Hardware Model

**The problem:** Meshtastic apps display device type (T-Beam, Heltec, RAK, etc.) from a `hw_model` enum.

**The solution:** Always report `PRIVATE_HW` (255) or a new `LICHEN_NODE` value if Meshtastic adds one.

The app will show "Unknown" or a generic icon. This is accurate—LICHEN runs on various hardware, and Meshtastic's model list doesn't apply.

### Channels and Encryption

**The problem:** Meshtastic uses named channels with PSK (pre-shared key) encryption. Users configure channels in the app, share QR codes, etc.

**The solution:** Present one synthetic channel, ignore all channel config.

```
Channel 0:
  name: "LICHEN"
  role: PRIMARY
  psk: <empty or dummy>
  uplink_enabled: false
  downlink_enabled: false
```

**Why this works:**
- LICHEN always encrypts (OSCORE + link signatures). The app shows the lock icon.
- LICHEN doesn't have "channels" in Meshtastic's sense. All nodes on a mesh can communicate.
- PSK config is meaningless—LICHEN uses Ed25519 keypairs and SCHC contexts.

**What the app sees:** One channel called "LICHEN", always encrypted, no way to add more. Channel config screens work but changes are discarded.

### Radio Configuration

**The problem:** Meshtastic lets users configure LoRa parameters (region, frequency, spreading factor, power).

**The solution:** Report current LICHEN PHY settings as read-only. Ignore writes.

| Meshtastic Config | Reported Value | Writes |
|-------------------|----------------|--------|
| `lora.region` | Mapped from LICHEN region | Ignored |
| `lora.modem_preset` | `LONG_MODERATE` (closest match) | Ignored |
| `lora.hop_limit` | Current IPv6 hop limit | Ignored |
| `lora.tx_power` | Current TX power | Ignored |
| `lora.frequency_offset` | 0 | Ignored |

LICHEN nodes may auto-configure radio parameters based on mesh conditions. The app can't override this.

### Routing

**The problem:** Meshtastic shows hop counts, SNR per hop, and sometimes routing paths. Users expect to see "3 hops away" or similar.

**The solution:** Report all messages as direct (0 hops).

LICHEN uses RPL (IPv6 routing) which doesn't expose per-packet hop counts to applications. The adapter has no way to know how many hops a packet took. Rather than guess, it reports 0.

Users won't see routing metrics. Messages either arrive or they don't.

### Position Handling

**The problem:** Position formats match (lat/lon/alt), but Meshtastic positions are pushed; LICHEN uses the announce protocol.

**The solution:** Two-way translation.

**Outbound (app → mesh):**
1. App sends Position via MeshPacket
2. Adapter extracts lat/lon/alt/timestamp
3. Triggers LICHEN announce with position payload

**Inbound (mesh → app):**
1. LICHEN receives peer announce with position
2. Adapter converts to Meshtastic Position protobuf
3. Queues as MeshPacket with `POSITION_APP` portnum
4. App displays on map

Position precision is preserved (1e-7 degree resolution).

### Message Delivery Semantics

**The problem:** Meshtastic has implicit ACKs and "delivered" indicators. LICHEN uses CoAP confirmable/non-confirmable.

**The solution:** Best-effort mapping.

| Meshtastic | LICHEN |
|------------|--------|
| `want_ack: true` | CoAP CON (confirmable) |
| `want_ack: false` | CoAP NON (non-confirmable) |
| Delivery receipt | CoAP ACK response |

If a CoAP CON gets an ACK, the adapter signals delivery. If it times out, no delivery confirmation. This roughly matches Meshtastic behavior.

### What We Stub

These Meshtastic features return plausible defaults but do nothing:

| Feature | Stub Behavior |
|---------|---------------|
| `device.reboot_seconds` | Acknowledged, ignored |
| `device.factory_reset` | Acknowledged, ignored |
| `device.nodeinfo_broadcast_secs` | Returns 900, ignored |
| `position.gps_enabled` | Returns current GPS state |
| `position.fixed_position` | Returns false |
| `power.*` | Returns defaults |
| `network.*` | Returns empty (no WiFi) |
| `display.*` | Returns defaults |
| `bluetooth.enabled` | Returns true |
| `bluetooth.fixed_pin` | Returns 123456 |

### What We Reject

These features can't be stubbed meaningfully. The adapter returns errors or empty responses:

| Feature | Response |
|---------|----------|
| Admin messages (remote config) | Empty/error |
| Secondary channels | Not created |
| Store-and-forward queries | Empty |
| Range test | Not implemented |
| Audio | Not implemented |
| Traceroute | Returns empty path |

## BLE GATT Service

**Service UUID:** `6ba1b218-15a8-461f-9fa8-5dcae273eafd`

| Characteristic | UUID | Properties | Direction |
|----------------|------|------------|-----------|
| ToRadio | `f75c76d2-129e-4dad-a1dd-7866124401e7` | Write | App → Node |
| FromRadio | `2c55e69e-4993-11ed-b878-0242ac120002` | Read | Node → App |
| FromNum | `ed9da18c-a800-4f66-a670-aa7547e34453` | Read, Notify | Packet counter |

### Connection Flow

1. App connects, requests MTU 512
2. App writes `ToRadio { want_config_id: N }`
3. Node responds with config sequence via FromRadio reads:
   - `MyNodeInfo` (this node's identity)
   - `NodeInfo` (each known peer)
   - `Config` sections (radio, display, etc.)
   - `Channel` definitions
   - `ConfigCompleteId`
4. App subscribes to FromNum notifications
5. On notify, app reads FromRadio until empty
6. App writes ToRadio for outbound messages

### MTU Handling

Meshtastic apps expect 512-byte MTU. Messages larger than ATT MTU are chunked by the BLE stack. The adapter reassembles ToRadio writes and chunks FromRadio reads.

## Protobuf Messages

The adapter implements a subset of Meshtastic's protobuf schema.

### Inbound (ToRadio)

| Field | Handling |
|-------|----------|
| `want_config_id` | Triggers config sync |
| `packet` | MeshPacket to send |
| `disconnect` | Close connection |

### Outbound (FromRadio)

| Field | Source |
|-------|--------|
| `my_info` | This node's LICHEN identity |
| `node_info` | LICHEN peer table |
| `config` | Synthetic config from LICHEN state |
| `channel` | Mapped from SCHC context |
| `packet` | Incoming mesh messages |
| `config_complete_id` | Signals end of config sync |

### MeshPacket

| Meshtastic Field | LICHEN Mapping |
|------------------|----------------|
| `from` | Sender IID, truncated to 32 bits |
| `to` | Destination IID (0xFFFFFFFF = broadcast) |
| `id` | CoAP Message-ID |
| `rx_time` | Packet receive timestamp |
| `rx_snr` | LoRa SNR from link layer |
| `hop_limit` | IPv6 hop limit |
| `decoded.portnum` | CoAP Uri-Path mapping (see below) |
| `decoded.payload` | CoAP payload |

### Port Number Mapping

Meshtastic uses `portnum` to identify message types. The adapter maps these to CoAP resources:

| Meshtastic Portnum | CoAP Uri-Path | Notes |
|--------------------|---------------|-------|
| `TEXT_MESSAGE_APP` (1) | `/msg` | Plain text messages |
| `POSITION_APP` (3) | `/pos` | Position updates |
| `NODEINFO_APP` (4) | `/node` | Node info exchange |
| `TELEMETRY_APP` (67) | `/telem` | Device telemetry |
| `TRACEROUTE_APP` (70) | N/A | Handled internally |

Unsupported portnums are silently dropped or return empty responses.

## State Mapping

### Node Identity

| Meshtastic | LICHEN | Conversion |
|------------|--------|------------|
| `num` (u32) | IID (64-bit) | `iid & 0xFFFFFFFF` |
| `user.id` | IID hex | `!` + hex(iid)[0:8] |
| `user.long_name` | CoAP `/node` resource | Fetched from node |
| `user.short_name` | Derived | First 4 chars of long_name |
| `user.hw_model` | Fixed | `LICHEN_NODE` |

### Position

| Meshtastic | LICHEN | Notes |
|------------|--------|-------|
| `latitude_i` | Announce latitude | Scaled by 1e7 |
| `longitude_i` | Announce longitude | Scaled by 1e7 |
| `altitude` | Announce altitude | Meters |
| `time` | Announce timestamp | Unix epoch |

### Channels

Meshtastic channels don't map directly to LICHEN. The adapter presents a synthetic channel:

| Meshtastic | Value |
|------------|-------|
| `index` | 0 |
| `role` | `PRIMARY` |
| `settings.name` | "LICHEN" |
| `settings.psk` | Empty (security handled differently) |

Additional channels are not supported. Config writes to channel settings are acknowledged but ignored.

## Config Sections

The adapter returns synthetic config matching Meshtastic's expected structure:

| Config Section | Handling |
|----------------|----------|
| `device` | Node name from LICHEN identity |
| `position` | GPS settings (if applicable) |
| `power` | Stubbed defaults |
| `network` | Stubbed (no WiFi) |
| `display` | Stubbed defaults |
| `lora` | Maps from LICHEN PHY config |
| `bluetooth` | Current BLE state |

Config writes via ToRadio are acknowledged but most are no-ops. The LICHEN stack controls actual radio parameters.

## Message Flow Examples

### Sending a Text Message

```
App: ToRadio { packet: MeshPacket {
    to: 0xFFFFFFFF,
    decoded: Data { portnum: TEXT_MESSAGE_APP, payload: "Hello" }
}}

Adapter:
    1. Extracts destination (broadcast)
    2. Creates CoAP POST to /msg
    3. Payload: "Hello"
    4. Sends via LICHEN mesh

LICHEN: IPv6/UDP/CoAP packet transmitted
```

### Receiving a Position Update

```
LICHEN: Receives announce with position from peer

Adapter:
    1. Extracts position from announce
    2. Builds MeshPacket {
        from: peer_iid & 0xFFFFFFFF,
        decoded: Data { portnum: POSITION_APP, payload: Position {...} }
    }
    3. Queues in FromRadio buffer
    4. Increments FromNum, triggers notify

App: Reads FromRadio, displays position on map
```

## Limitations

### Not Supported

| Feature | Reason |
|---------|--------|
| Multiple channels | LICHEN uses different keying model |
| Store-and-forward | Use LICHEN DTN instead |
| Meshtastic routing | LICHEN handles routing (RPL) |
| Remote admin | Security model incompatible |
| Firmware update | Use LICHEN OTA |
| Range test | Meshtastic-specific |
| Audio | Not implemented |

### Behavioral Differences

- **Routing is invisible**: Meshtastic shows hop counts and routing decisions. LICHEN routing (RPL) is handled transparently; the app sees direct delivery.

- **Node discovery**: Meshtastic expects periodic NodeInfo broadcasts. LICHEN uses announce protocol; the adapter synthesizes NodeInfo from peer state.

- **Encryption indicator**: Meshtastic shows lock icon per channel. LICHEN always uses OSCORE + link signatures; the adapter reports all traffic as encrypted.

- **Hop limit**: Meshtastic's hop_limit is advisory. LICHEN uses IPv6 hop limit, decremented by actual routers.

## Implementation Files

```
lichen/interface/meshtastic/
├── __init__.py
├── adapter.py      # Main translation logic
├── gatt.py         # BLE GATT service definition
├── protos/         # Compiled Meshtastic protobufs
│   ├── mesh_pb2.py
│   ├── portnums_pb2.py
│   └── ...
└── mapping.py      # State conversion functions
```

## Testing

### Unit Tests

- Protobuf encode/decode round-trips
- IID ↔ node num conversion
- Position scaling
- Config generation

### Integration Tests

- Mock BLE central connecting
- Config sync sequence
- Message send/receive
- Peer discovery updates

### Manual Testing

Use Meshtastic Android app with nRF Connect or similar to verify:
1. Service discovery finds LICHEN node
2. Config sync completes without errors
3. Text messages send and receive
4. Position updates appear on map
5. Node list populates with peers
