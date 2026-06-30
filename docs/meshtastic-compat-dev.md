# Meshtastic Compatibility Layer — Developer Guide

This document describes how LICHEN nodes expose a Meshtastic-compatible BLE interface, allowing unmodified Meshtastic apps to connect.

## Build and Target Architecture

**This feature is off by default.** The Meshtastic adapter adds significant firmware size:

- Protobuf runtime and compiled schemas: ~15-20 KB
- GATT service and adapter logic: ~8-12 KB
- Total overhead: ~25-30 KB

The firmware MVP target is native Zephyr C. It should use a bounded, no-dynamic-allocation protobuf codec for the
small app-compat subset, exposed through Zephyr Bluetooth GATT services and wired into the same LICHEN app-level
contract used by native LICHEN clients. Rust and Python implementations remain reference, host tooling, and simulator
paths unless a later Bead explicitly selects an FFI or host-bridge architecture.

To enable Meshtastic compatibility, explicitly request it at build time. Final Zephyr Kconfig names are tracked by the
Meshtastic implementation Beads; the Rust/Python commands below are for development and simulation only:

```
# Rust reference / host tooling
cargo build -p lichen-meshtastic

# Python (development/simulation only)
pip install lichen[meshtastic]
```

**Firmware platforms:**
- Zephyr boards with BLE local transport, such as nRF52840 targets, are the first implementation target.
- ESP32-S3 targets remain possible once Zephyr BLE support is validated for the board.
- STM32WL has no BLE hardware; a serial/TCP Meshtastic-compatible stream is separate work and must not be confused with BLE GATT.

**Reference and test platforms:**
- Python prototype and tests for adapter behavior.
- Rust `lichen-meshtastic` for schema, address mapping, config, and host tooling. Its current `gatt.rs` is not
  authoritative for BLE framing until updated to raw protobuf-per-GATT-value semantics.
- Linux BLE clients for smoke tests.

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

**Collision risk:** Two LICHEN nodes could have IIDs that share the same low 32 bits. This is unlikely
(~1 in 4 billion) but possible. The Meshtastic app would show them as the same node. LICHEN itself uses full IIDs so
routing is unaffected; only the app display is wrong.

**Reverse lookup:** When the app sends to a 32-bit destination, the adapter searches the peer table for an IID ending
in those 32 bits. If no match, the message is dropped. Broadcast (0xFFFFFFFF) maps to IPv6 link-local all-nodes
multicast.

### User Names (short_name, long_name)

**The problem:** Meshtastic stores user-configured names on each node. Users expect to set their name in the app and
have it stick.

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

**The problem:** Meshtastic has implicit ACKs and "delivered" indicators. LICHEN uses CoAP
confirmable/non-confirmable.

**The solution:** Best-effort mapping.

| Meshtastic | LICHEN |
|------------|--------|
| `want_ack: true` | CoAP CON (confirmable) |
| `want_ack: false` | CoAP NON (non-confirmable) |
| Local enqueue status | `queueStatus` |
| Delivery receipt | `ROUTING_APP` ACK/NAK packet with `decoded.request_id` |

The adapter may use CoAP CON/NON internally, but the Meshtastic app-visible delivery state must be surfaced as a
`FromRadio.packet` carrying a `ROUTING_APP` ACK/NAK correlated to the original Meshtastic packet ID with
`decoded.request_id`. A local CoAP ACK alone is not enough for the app to show delivery.

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
| Admin config writes | Empty/error |
| Read-only owner/session admin requests | Return synthetic owner/session data or document limited compatibility |
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

1. App connects and discovers the Meshtastic service.
2. App writes raw serialized `ToRadio` protobuf values to `ToRadio`.
3. Current Android and iOS apps use a two-stage sync: `want_config_id = 69420` for config and
   `want_config_id = 69421` for node DB. Android/iOS may also send `ToRadio.heartbeat` around the handshake,
   especially between stages; firmware must tolerate heartbeat but must not require it before stage 1.
4. Node responds via `FromRadio` reads:
   - `MyNodeInfo` (this node's identity)
   - `DeviceMetadata` and config/module/channel records for config sync
   - `NodeInfo` (each known peer)
   - `ConfigCompleteId` matching the request nonce
5. App subscribes to `FromNum` notifications; Android also proactively drains after writes.
6. On notify, app reads `FromRadio` until the characteristic returns an empty value.
7. App writes `ToRadio.packet` for outbound messages.

### MTU Handling

BLE uses one protobuf per GATT value, not the serial/TCP `0x94 0xc3 + length` stream framing. Current Meshtastic
firmware generated sizes are below 512 bytes (`ToRadio` about 504 bytes, `FromRadio` about 510 bytes), but exact ATT
MTU, long-read, and long-write requirements are tracked separately. The adapter must bound decode/encode buffers and
reject oversized values deterministically.

## Protobuf Messages

The adapter implements a subset of Meshtastic's protobuf schema.

### Inbound (ToRadio)

| Field | Handling |
|-------|----------|
| `want_config_id` | Triggers config sync |
| `heartbeat` | Keepalive/liveness trigger; may return `queueStatus` |
| `packet` | MeshPacket to send |
| `disconnect` | Close connection |

### Outbound (FromRadio)

| Field | Source |
|-------|--------|
| `my_info` | This node's LICHEN identity |
| `node_info` | LICHEN peer table |
| `config` | Synthetic config from LICHEN state |
| `moduleConfig` | Synthetic module config defaults |
| `channel` | Mapped from SCHC context |
| `metadata` | Synthetic device metadata |
| `region_presets` | Region/preset constraints, or explicitly omitted under a tested safe-absence policy |
| `packet` | Incoming mesh messages |
| `queueStatus` | Send queue status |
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

## Planned Firmware Files

```
lichen/subsys/lichen/meshtastic/
├── Kconfig         # Adapter feature gates, buffers, queue sizes
├── CMakeLists.txt  # Zephyr build integration
├── codec.*         # Bounded protobuf subset codec
├── adapter.*       # App-level mapping and dispatcher
├── gatt.*          # Zephyr BLE GATT service
├── include/lichen/meshtastic/*.h
└── mapping.*       # LICHEN state conversion

python/src/lichen/interface/meshtastic/
├── adapter.py      # Prototype state machine
├── translate.py    # Reference translation helpers
└── address.py      # Reference node-number mapping

rust/lichen-meshtastic/
├── proto/          # Reference schema subset
└── src/            # Reference and host-tooling code; current gatt.rs is stale for BLE framing
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
