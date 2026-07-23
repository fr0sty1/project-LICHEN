# Meshtastic Compatibility Layer -- Developer Guide

This document describes how LICHEN nodes expose a Meshtastic-compatible BLE interface, allowing unmodified Meshtastic apps to connect.

## Source Baseline

This contract is based on the Meshtastic app/protocol research. Pinned baselines:

| Source | Commit inspected |
|--------|------------------|
| `meshtastic/protobufs` | `032b7dfd68e875c4323e6ac67590c6fc616b1714` |
| `meshtastic/firmware` | `2f97112987af311ca81dd70b83cbcf7236d6c119` |
| `meshtastic/python` | `6d76edf8a7b192c51e3a5d26bc5868da556ac3d9` |
| `meshtastic/Meshtastic-Android` | `eb3bd10757a312d1537874bfab245117c46c36a9` |
| `meshtastic/Meshtastic-Apple` | `aeeb0cc49fbe0ed593e918ba2f95100ecf694256` |

The vendored `PortNum` table was rechecked against current `meshtastic/protobufs` `master` at `aa53c96b79d9cb49a38e71fc2bc9c46cec1fd7c6`. `LORA_OTA_APP = 79`
is new since the pinned protobuf baseline above; the LICHEN minimal subset also now includes app-visible
PortNum values that existed upstream but had not previously been vendored locally.

`DeviceMetadata` was rechecked for Bead `project-LICHEN-t2hn.24` against the checked-in LICHEN revision
`908b6d0f87aae73a248a30d0bb49e01c6f998255` and current `meshtastic/protobufs` `master` at
`9cb134be322dd7122e80d49b17dad9a213ff752e`. The pinned protobuf commit above and current upstream both define the same
12-field `DeviceMetadata` message:

| Number | Field | LICHEN policy |
|--------|-------|---------------|
| 1 | `firmware_version` | LICHEN-branded compatibility firmware string |
| 2 | `device_state_version` | `1` |
| 3 | `canShutdown` | `false` |
| 4 | `hasWifi` | `false` |
| 5 | `hasBluetooth` | True only when the Meshtastic-compatible BLE surface is active |
| 6 | `hasEthernet` | `false` |
| 7 | `role` | `CLIENT` |
| 8 | `position_flags` | `0` |
| 9 | `hw_model` | `PRIVATE_HW` / `255` |
| 10 | `hasRemoteHardware` | `false` |
| 11 | `hasPKC` | `false` |
| 12 | `excluded_modules` | MVP unsupported-module bitmask |

The Zephyr encoder emits all 12 fields explicitly. No `platform_type` field exists in pinned or current upstream
`DeviceMetadata`; do not add one unless a future upstream protobuf revision introduces it.

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

BLE advertising and product-mode ownership are tracked in
`docs/ble-app-surface-owner.md`. Current firmware builds keep native LICHEN BLE,
Meshtastic BLE, and MeshCore BLE mutually exclusive.

Use `docs/meshtastic-smoke-test.md` for Android and iOS Meshtastic app smoke
runs. It defines the required no-hardware preflight, BLE discovery, config sync,
node DB sync, message ingress/egress, unsupported-operation checks, and physical
client evidence.

## Support Matrix (R1 MVP)

This matrix describes the implemented LICHEN Meshtastic app-compatibility surface for R1. It is intentionally **local-client compatibility only**. LICHEN nodes do not join Meshtastic LoRa meshes, emit Meshtastic frames, or share keys with Meshtastic nodes.

| Area | Current support | Evidence | Remaining gap |
|------|-----------------|----------|---------------|
| RF interoperability | Not supported. Local BLE app interface only; all mesh uses LICHEN IPv6/SCHC/RPL/CoAP/Ed25519/LoRa. | `lichen/tests/meshtastic_*`, `docs/meshtastic-smoke-test.md` unsupported checks, no Meshtastic RF path in adapter. | None; RF interop out of scope (see t2hn.2 contract). |
| BLE transport | Meshtastic service UUID `6ba1b218-...`, ToRadio (write), FromRadio (read), FromNum (notify/read/write). Raw protobuf values, no StreamAPI prefix. ATT long ops (~504B write/510B read). | `lichen/apps/gateway/src/ble_meshtastic.*`, `meshtastic_adapter.c`, `tests/meshtastic_ble`, `test/vectors/meshtastic_app_compat.json`, smoke-test ATT section. | R1 Neo ATT evidence in project-LICHEN-t2hn.21 (P1). |
| Discovery/pairing | Advertises `LICHEN-XXXX` name + service. Plain permissions for MVP (no mandatory pairing). | BLE owner, advertising logs `Meshtastic BLE advertising as`, smoke-test discovery table. | Android/iOS pairing behavior evidence in t2hn.16.1/.16.2 (hardware blocked). |
| Sync flows | want_config_id stages return LICHEN-branded DeviceMetadata (PRIVATE_HW, excluded_modules), region presets, channels, oneof-clean configs, moduleConfig placeholders, node DB. config_complete_id terminates each stage. | t2hn.6/13/15/24/25, codec tests, adapter enqueue order, vectors, smoke-test checkpoints 6-9. | Post-sync ADMIN_APP in t2hn.23. |
| Messaging | Broadcast text maps to LICHEN local submit (port TEXT_MESSAGE_APP). Incoming LICHEN text/status -> FromRadio events + FromNum notify. | t2hn.7/.8, gateway_adapter tests, vectors for ingress/egress. | Concrete submit provider (t2hn.7.2); full physical smoke pending hardware. |
| Unsupported ops | Explicit ERR or no-op for admin/radio/secondary-channel/store-forward/range-test/unknown portnum. No LICHEN state mutation. | t2hn.9, unsupported tests, smoke-test section. | Any new op that reaches radio must add test+Bead. |
| R1 build | r1_neo/nrf52840 + gateway + MESHTASTIC_BLE overlay. Fits in flash/RAM. | `lichen/apps/gateway/boards/r1_neo_nrf52840.*`, ev5b.4, smoke preflight twister. | Hardware flash+smoke blocked by avrb (ev5b.5). |

Any expansion of a "Not supported" row requires new Beads for tests, vectors, and smoke evidence before updating this matrix.

**Reference and test platforms:**
- Python prototype and tests for adapter behavior.
- Rust `lichen-meshtastic` for schema, address mapping, config, and host tooling. Its current `gatt.rs` is not
  authoritative for BLE framing until updated to raw protobuf-per-GATT-value semantics. Rust no longer carries a
  separate Admin/config handler; active read-only sync behavior is owned by Zephyr compatibility codec/adapter tests,
  and packet-level `ADMIN_APP` reads are tracked separately by `project-LICHEN-t2hn.23`.
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

The app may show a "saved" confirmation, but the name won't persist. This is intentional--LICHEN nodes don't store Meshtastic user profiles.

### Hardware Model

**The problem:** Meshtastic apps display device type (T-Beam, Heltec, RAK, etc.) from a `hw_model` enum.

**The solution:** Always report `PRIVATE_HW` (255) unless Meshtastic upstream adds an official LICHEN-specific enum
value.

The app will show "Unknown" or a generic icon. This is accurate--LICHEN runs on various hardware, and Meshtastic's model list doesn't apply.

### Synthetic Metadata and Version Policy

Meshtastic app compatibility metadata is synthetic. It exists so unmodified Meshtastic clients can complete discovery and
sync against a local LICHEN node. It MUST NOT imply that the device is running Meshtastic RF firmware or can interoperate
with Meshtastic nodes over LoRa.

Policy for `MyNodeInfo`, `DeviceMetadata`, and `User` fields:

| Field | Policy |
|-------|--------|
| `firmware_version` | LICHEN-branded app-compat firmware string, for example `"LICHEN compat 0.1.0"` or `"LICHEN compat 0.1.0+zephyr.3.7.0"`; must start with `LICHEN`, must not contain `Meshtastic` in any casing, and must not present an unlabeled RTOS version as the LICHEN firmware release |
| `min_app_version` | Default `30200` until mobile smoke testing proves a higher minimum is required |
| `pio_env` | Zephyr-branded environment string such as `"zephyr-r1_neo_nrf52840"` |
| `hw_model` | `PRIVATE_HW` (255) for both `DeviceMetadata.hw_model` and `User.hw_model` |
| `role` | `CLIENT` unless a later tested app flow requires a different local-app role |
| `has_bluetooth` | True only when the Meshtastic-compatible BLE surface is active |
| `has_wifi`, `has_ethernet`, `has_remote_hardware`, `has_pkc` | False for the MVP unless backed by an implemented LICHEN capability |
| `position_flags` | `0` for the MVP; Position support is exposed through NodeDB Position records, not Meshtastic device capability flags |
| `excluded_modules` | Bitmask excludes unsupported Meshtastic modules/features for the MVP; Bluetooth config is excluded only when the compatibility BLE surface is absent |

The user-visible device name and `User.long_name` SHOULD remain visibly LICHEN-branded, such as `"LICHEN R1 Neo"` or
`"LICHEN <board>"`. Board-specific Meshtastic hardware enum values such as T-Beam, Heltec, or RAK4631 MUST NOT be used
even when LICHEN is running on that hardware, because those values imply Meshtastic firmware behavior and RF semantics.

### Placeholder Module and Region Policy

This policy was checked for Bead `project-LICHEN-t2hn.6.5` against current Meshtastic source heads:

| Source | Commit inspected | Relevant behavior |
|--------|------------------|-------------------|
| `meshtastic/protobufs` | `9cb134be322dd7122e80d49b17dad9a213ff752e` | `LoRaRegionPresetMap` clients must tolerate absence; `ExcludedModules` defines bits through `NETWORK_CONFIG = 0x4000`; `ModuleConfig` has variants through `mesh_beacon = 17` |
| `meshtastic/firmware` | `e64d20548c4313c92e0e641c41d388828e1d024a` | `PhoneAPI` sends metadata, region presets, channels, config, then its implemented module config cases before node DB |
| `meshtastic/Meshtastic-Android` | `60119ce9d2e4efcb2e81336dbde29c1b70c9f293` | `min_app_version` only gates an app-update prompt; `region_presets` is handled when present and documented as absent on firmware before 2.8; module configs are persisted independently as they arrive |
| `meshtastic/Meshtastic-Apple` | `aeeb0cc49fbe0ed593e918ba2f95100ecf694256` | No newer head than the pinned baseline during this check |
| `meshtastic/python` | `6d76edf8a7b192c51e3a5d26bc5868da556ac3d9` | No newer head than the pinned baseline during this check |

LICHEN's MVP MUST prefer honest absence or explicit disabled placeholders over fabricated Meshtastic capabilities:

| Surface | MVP placeholder | Reason |
|---------|-----------------|--------|
| `min_app_version` | `30200` | Low enough for current app compatibility while still exercising the app version path; do not raise it without Android/iOS smoke evidence |
| `excluded_modules` | `0x5fff` when Meshtastic BLE is active, `0x7fff` when it is not | Marks MQTT, serial, external notification, store-forward, range test, telemetry, canned message, audio, remote hardware, neighbor info, ambient lighting, detection sensor, paxcounter, and network unsupported; also marks Bluetooth config unsupported when the compatibility BLE surface is absent |
| `moduleConfig` | One `telemetry` record with `device_update_interval = 0`, `environment_update_interval = 0`, and `device_telemetry_enabled = false` | Gives clients an explicit disabled telemetry placeholder without claiming sensor, MQTT, serial, store-forward, remote hardware, TAK, mesh beacon, or other module support |
| `region_presets` | One group containing `LONG_FAST` with default `LONG_FAST`, mapped only to `US` | Documents the current conservative native_sim/default radio profile; additional regions require a tested region table and must not be guessed |

Any future module, region, battery, GNSS, or network placeholder that becomes app-visible MUST have a native_sim test and
must either be backed by a real LICHEN/HAL capability or be marked unavailable in metadata/config so users do not see a
fictional Meshtastic feature.

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
- PSK config is meaningless--LICHEN uses Ed25519 keypairs and SCHC contexts.

**What the app sees:** One channel called "LICHEN", always encrypted, no way to add more. Channel config screens work but changes are discarded.

### Radio Configuration

**The problem:** Meshtastic lets users configure LoRa parameters (region, frequency, spreading factor, power).

**The solution:** Report current LICHEN PHY settings as read-only. Ignore writes.

| Meshtastic Config | Reported Value | Writes |
|-------------------|----------------|--------|
| `lora.region` | Mapped from LICHEN region | Ignored |
| `lora.modem_preset` | `LONG_FAST` for the MVP default profile | Ignored |
| `lora.hop_limit` | Current IPv6 hop limit | Ignored |
| `lora.tx_power` | Current TX power | Ignored |
| `lora.frequency_offset` | 0 | Ignored |

LICHEN nodes may auto-configure radio parameters based on mesh conditions. The app can't override this.

### Routing

**The problem:** Meshtastic shows hop counts, SNR per hop, and sometimes routing paths. Users expect to see "3 hops away" or similar.

**The solution:** Report all messages as direct (0 hops), except for NodeDB
peer records that already carry an explicit LICHEN peer hop distance.

LICHEN uses RPL (IPv6 routing) which doesn't expose per-packet hop counts to applications. The adapter has no way to know how many hops a packet took. Rather than guess, it reports 0.

Peer RSSI, SNR, and last-heard age remain internal LICHEN peer/status data for
now. They are not encoded into Meshtastic `NodeInfo`, because that message's
stable fields in this compatibility layer are identity, optional location,
device metrics, channel, and `hops_away`; overloading it with link-quality or
age data would make mobile clients treat adapter-derived diagnostics as native
Meshtastic RF telemetry. If a later compatibility pass exposes those metrics,
it must choose and test a concrete Meshtastic wire/status surface instead of
piggybacking them onto NodeInfo.

Users won't see packet path metrics. Messages either arrive or they don't.

### Position Handling

**The problem:** Position formats match (lat/lon/alt), but Meshtastic positions are pushed; LICHEN uses the announce protocol.

**Current MVP behavior:** expose map-ready local NodeDB Position only when a
LICHEN location snapshot has both latitude and longitude. App-originated
`POSITION_APP` writes are accepted as local-client location submissions when
the payload has valid latitude and longitude. Peer-position announce
translation is handled by the network-location producer path, not by fabricating
Meshtastic RF behavior.

The firmware path is implemented in the Zephyr Meshtastic compatibility layer:
`POSITION_APP` packets from a local Meshtastic client decode into the shared
adapter position snapshot, the gateway submits accepted values through the
LICHEN app-interface as `LOCAL_CLIENT` location updates, and local NodeDB sync
can emit this node's current valid location back to the app. Malformed Position
payloads return deterministic status and must not replace an existing HAL
location snapshot. Native LICHEN location, time, and status resources remain
authoritative for richer provider diagnostics.

Peer coordinates learned from LICHEN announces are not Meshtastic peer-position
messages and are not automatically this node's own location. If a gateway build
enables approximate mesh-derived location fallback, those coordinates are
submitted only as `NETWORK` source metadata with source name `mesh-announce` or
a similarly explicit provenance string. They must remain lower priority than
fresh local hardware, manual/static, or local-client location and must age out
with the announce freshness window. Coordinate-only announce metadata carries no
Unix fix time; build/provision epoch floors apply only if a separate network
time or fix-time sample is submitted to the shared time provider. Builds that do
not explicitly enable that fallback keep peer announce coordinates in
routing/diagnostic state only.

**Outbound (app → mesh):**
1. App sends Position via MeshPacket
2. Adapter validates the payload shape and requires valid latitude/longitude
3. Position is submitted to the LICHEN local-client location provider
4. Queue status reports success when the local submission is accepted

**Inbound (mesh → app):**
1. Gateway reads local HAL/app-interface location metadata
2. If both latitude and longitude are valid, NodeDB `NodeInfo.position` is encoded
3. Optional altitude, fix time, and satellites are included only with that position
4. App displays local node position from NodeDB sync

Position precision is preserved (1e-7 degree resolution).

Meshtastic Position payloads are emitted only when both latitude and longitude
are valid. Time-only, altitude-only, and satellites-only GNSS metadata remains
available through native LICHEN status/time resources, but it is not wrapped in
a Meshtastic Position message because mobile clients treat the presence of that
message as map-ready location data. When coordinates are valid, optional
altitude, fix time, and satellites are included if available.

For app-originated `POSITION_APP`, Meshtastic `timestamp` field 7 is treated as
the actual fix timestamp and wins over legacy `time` field 4 when both are
present. Field 4 is used only when field 7 is absent. A chosen timestamp below
the deterministic firmware build epoch is stripped from the submitted location
sample; the coordinates remain usable as local-client position metadata. A
stricter authenticated board/provision epoch is not applied to the stored
location `fix_time_unix` by the compatibility gateway; it is enforced only if
Position-derived time is submitted through the shared firmware time provider.

Meshtastic `location_source` and `altitude_source` describe the upstream
Meshtastic fix provenance, but they do not upgrade trust for a value received
from the local compatibility app surface. The submitted LICHEN source class
remains `LOCAL_CLIENT`; the source name records the Meshtastic provenance, for
example `mt-pos-internal`, `mt-pos-external`, or `mt-pos-manual`.
Barometric altitude metadata does not imply a GNSS fix source.

Meshtastic `gps_accuracy` is decoded as the raw GPS module accuracy constant in
millimeters. It is not mapped to app-visible horizontal accuracy unless DOP
fields are also available to calculate final positional accuracy.
`precision_bits` is decoded and retained for diagnostics/vector coverage, but it
is not currently mapped to a native location accuracy or emitted in NodeDB
Position messages.

No-hardware coverage for this contract lives in the Meshtastic adapter and
gateway adapter ztests. Those tests cover valid full and minimal Position
payloads, negative altitude, field 7 timestamp precedence over legacy field 4,
duplicate field 4 last-wins behavior, below-build-epoch timestamp stripping
while preserving coordinates, source/altitude/gps_accuracy/precision metadata,
malformed payload rejection, and preservation of a prior HAL snapshot after
malformed input. Physical phone/BLE smoke testing and RF validation remain
separate from this software-only contract.

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
| `position.gps_mode` | Returns `NOT_PRESENT` until a GNSS provider is wired |
| `position.fixed_position` | Returns false |
| `power.*` | Returns defaults |
| `network.*` | Returns empty (no WiFi) |
| `display.*` | Returns defaults |
| `bluetooth.enabled` | Returns true |
| `bluetooth.mode` | Returns `NO_PIN` in the local compatibility surface |

### What We Reject

These features can't be stubbed meaningfully. The adapter returns errors or empty responses:

| Feature | Response |
|---------|----------|
| Admin config writes/commands | Deterministic no-op/error; read-only admin requests still return synthetic compatibility data |
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
   - `DeviceMetadata`, region presets, channel, one Config record per supported section, and module config records for config sync
   - `NodeInfo` (each known peer)
   - `ConfigCompleteId` matching the request nonce
5. App subscribes to `FromNum` notifications; Android also proactively drains after writes.
6. On notify, app reads `FromRadio` until the characteristic returns an empty value.
7. App writes `ToRadio.packet` for outbound messages.
8. Node emits `FromRadio.queueStatus` for local enqueue/accounting state and emits `FromRadio.packet` with
   `ROUTING_APP` ACK/NAK for app-visible delivery state when the LICHEN contract can confirm success or failure.

The sync nonces are fixed by current Android and iOS client flows. `69420` means "send config and static metadata";
`69421` means "send node database". The adapter must echo the nonce in `config_complete_id` after the records for that
stage. It must not assume the app is done after the first `config_complete_id`, because Apple and Android use the second
stage to seed the node database. Other nonces are treated as legacy/full-sync requests for Python or older clients: queue
the stage-1 config/static records and the stage-2 node database, then echo the original nonce in `config_complete_id`.
Stage-1 order is `my_info`, `metadata`, `region_presets`, `channel`, repeated oneof-clean `config` records,
`moduleConfig`, then `config_complete_id`. This follows current Meshtastic firmware
`e64d20548c4313c92e0e641c41d388828e1d024a`, whose `PhoneAPI` state machine sends region presets immediately after
metadata and before the first channel.

The `FromNum` characteristic is an edge-triggered queue hint, not the data channel. Every queued `FromRadio` value
increments `FromNum` modulo 2^32 and notifies subscribed clients when notifications are enabled. A `FromRadio` read
returns one complete protobuf value. An empty value means the queue is drained.

### MTU Handling

BLE uses one protobuf per GATT value, not the serial/TCP `0x94 0xc3 + length` stream framing. The source baseline in
`project-LICHEN-t2hn.1` records Meshtastic firmware generated protobuf budgets of `ToRadio_size = 504` bytes and
`FromRadio_size = 510` bytes, with a 512-byte characteristic value envelope.

LICHEN compatibility builds use these limits:

| Direction | Characteristic | Maximum protobuf value | Required behavior |
|-----------|----------------|------------------------|-------------------|
| App to node | `ToRadio` | 504 bytes | Accept one complete raw protobuf value; reject 505+ bytes |
| Node to app | `FromRadio` | 510 bytes | Emit one complete raw protobuf value per read; never emit 511+ bytes |
| Notify/read hint | `FromNum` | 4 bytes | Notify/read a little-endian monotonic queue counter |

ATT MTU is a transport detail below the app contract. The Zephyr GATT binding may rely on ATT long write/read support or
platform-provided value reassembly, but the Meshtastic adapter must see exactly one complete protobuf value per
`ToRadio` write and must expose exactly one queued protobuf value per `FromRadio` read. The adapter must not implement
Meshtastic-specific app-level BLE chunking or accept StreamAPI length-prefixed frames on BLE.

Boundary behavior is deterministic:

- `ToRadio` values larger than 504 bytes are rejected before decode and must not leave partial parser or sync state.
- `FromRadio` payloads that would encode larger than 510 bytes must be reduced, split at the semantic queue level, or
  replaced with a deterministic compatibility error before they reach the GATT value.
- If a board/stack cannot carry 504-byte writes or 510-byte reads through ATT long operations, that board is not
  Meshtastic-compatible until the limitation is fixed or documented as a blocker.

`test/vectors/meshtastic_app_compat.json` includes BLE stream-prefix rejection and 505-byte `ToRadio` rejection cases.
Captured Android/iOS/Python ATT evidence is tracked separately by `project-LICHEN-t2hn.21`.

## Protobuf Messages

The adapter implements a subset of Meshtastic's protobuf schema.

### Inbound (ToRadio)

| Field | Handling |
|-------|----------|
| `want_config_id = 69420` | Queue stage-1 identity, metadata, region presets, channel, one Config record per supported section, module config, and matching `config_complete_id` |
| `want_config_id = 69421` | Queue stage-2 node database and matching `config_complete_id` |
| Other `want_config_id` | Queue legacy/full sync and matching `config_complete_id`; log compatibility nonce |
| `heartbeat` | Keepalive/liveness trigger; may queue `queueStatus`; never required before sync |
| `packet` with `TEXT_MESSAGE_APP` | Validate broadcast primary-channel UTF-8 text up to 200 bytes, call the adapter text hook, and queue local `queueStatus` |
| `packet` with `POSITION_APP` | Valid app-originated positions are accepted as local-client location submissions; malformed or unsupported payloads return deterministic status |
| `packet` with `NODEINFO_APP` | Update transient display metadata only; no persistent Meshtastic identity writes |
| `packet` with `ADMIN_APP` read request | Deferred until `project-LICHEN-t2hn.23`; current firmware returns deterministic unsupported status. |
| `packet` with `ADMIN_APP` write/command | Reject or no-op deterministically; do not mutate LICHEN radio/security settings. |
| `packet` with unsupported portnum | Drop with deterministic status or empty response; never crash or desync the queue |
| `disconnect` | Clear connection-scoped queue/session state |

### Outbound (FromRadio)

| Field | Source |
|-------|--------|
| `my_info` | This node's LICHEN identity and synthetic Meshtastic node number |
| `node_info` | LICHEN peer table, including self and discovered peers |
| `config` | Synthetic config from LICHEN state; each `FromRadio.config` contains exactly one `Config` oneof section |
| `moduleConfig` | Synthetic module config defaults |
| `channel` | Synthetic primary channel plus disabled secondary channels when requested |
| `metadata` | Synthetic device metadata and firmware/version policy |
| `region_presets` | Region/preset constraints for current app sync; omission requires a separate tested safe-absence policy |
| `packet` | Incoming mesh messages, NodeInfo sync records with location-bearing positions, and `ROUTING_APP` ACK/NAK |
| `queueStatus` | Local send queue status only |
| `config_complete_id` | End marker that echoes the stage nonce |
| `clientNotification` | Optional advisory error/notice when a client requires visible feedback |

`queueStatus` is not a delivery receipt. It only tells the app whether the local adapter accepted or rejected work for
the local queue. Delivered/failed state that the app can show against a message must be represented as a `ROUTING_APP`
packet whose decoded `request_id` matches the original message request/id. If LICHEN cannot prove final delivery, the
adapter should report queued/local state only and avoid fabricating a final delivered ACK.

#### Queue preflight contract

The Zephyr adapter API allows `queue_free` to be omitted for custom/non-gateway
callers, but production gateway transports that expose a bounded FromRadio queue
SHOULD provide it. When `queue_free` is present, WantConfig bursts are
preflighted against the complete number of records before the first record is
enqueued. If `queue_free` accurately reports the same queue used by
`enqueue_from_radio` and the queue is not concurrently consumed, insufficient
space for the whole static sync, node DB sync, or legacy full sync burst makes
the adapter return `-ENOMEM`, increment `enqueue_fail_count`, and leave the
FromRadio queue unchanged.

`queue_free` is a preflight hook, not a reservation or rollback mechanism. If it
reports stale capacity, measures the wrong queue, or `enqueue_from_radio` later
fails mid-burst, earlier records can remain queued and the caller must handle
the partial burst as a recoverable degraded sync.

When `queue_free` is absent, the adapter deliberately falls back to best-effort
degraded behavior for compatibility with simple callers: records are enqueued in
order until `enqueue_from_radio` reports backpressure. The caller can then see a
partial sync burst and must recover by draining/resetting its transport queue
before requesting sync again. Do not rely on atomic WantConfig bursts unless the
caller supplies an accurate same-queue `queue_free` hook and serializes the
queue for the burst.

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

Peer-table RSSI/SNR/last-heard values are retained for native LICHEN status
and routing diagnostics, but the Meshtastic NodeDB sync does not emit them.
Only explicit peer hop distance maps to `NodeInfo.hops_away`.

### Port Number Mapping

Meshtastic uses `portnum` to identify message types. The adapter maps these to CoAP resources:

| Meshtastic Portnum | CoAP Uri-Path | Notes |
|--------------------|---------------|-------|
| `TEXT_MESSAGE_APP` (1) | `/msg/inbox` | Plain text messages |
| `POSITION_APP` (3) | local-client location provider | Valid app-originated positions update the LICHEN location provider |
| `NODEINFO_APP` (4) | `/node` | Node info exchange |
| `TELEMETRY_APP` (67) | `/telem` | Device telemetry |
| `TRACEROUTE_APP` (70) | N/A | Handled internally |

Unsupported portnums produce deterministic no-op/error behavior and never produce mesh side effects.

For unsupported app packets the behavior is deterministic: parse errors reject the `ToRadio` write at the transport
boundary when the BLE stack permits it; valid but unsupported portnums produce no mesh side effect and may enqueue a
`queueStatus` or `clientNotification` explaining the unsupported operation. Firmware must not leave partially decoded
state, advance config stages incorrectly, or mutate LICHEN keys, channels, radio settings, or routing state because of a
Meshtastic compatibility write.

## State Mapping

### Node Identity

| Meshtastic | LICHEN | Conversion |
|------------|--------|------------|
| `num` (u32) | IID (64-bit) | `iid & 0xFFFFFFFF` |
| `user.id` | IID hex | `!` + hex(iid)[0:8] |
| `user.long_name` | CoAP `/node` resource | Fetched from node |
| `user.short_name` | Derived | First 4 chars of long_name |
| `user.hw_model` | Fixed | `PRIVATE_HW` (255) |

### Position

| Meshtastic | LICHEN | Notes |
|------------|--------|-------|
| `latitude_i` | Local-client location latitude | Scaled by 1e7; required with longitude for app-originated Position ingestion |
| `longitude_i` | Local-client location longitude | Scaled by 1e7; required with latitude for app-originated Position ingestion |
| `altitude` | Local-client location altitude | Meters; optional, and only emitted back to NodeDB Position with valid lat/lon |
| `time` | Fix timestamp fallback | Unix epoch; only used when `timestamp` is absent |
| `location_source` | Local-client source name suffix | Does not change LICHEN trust/source class |
| `altitude_source` | Diagnostic provenance | Barometric altitude does not imply GNSS |
| `timestamp` | Fix timestamp | Preferred over `time`; below-build-epoch values are stripped |
| `gps_accuracy` | Raw GPS module accuracy constant | Millimeters; not exported as final horizontal accuracy without DOP |
| `sats_in_view` | GNSS satellites | Only emitted with valid lat/lon |
| `precision_bits` | Diagnostic precision metadata | Decoded but not mapped to app-visible accuracy |

### Channels

Meshtastic channels don't map directly to LICHEN. The adapter presents a synthetic channel:

| Meshtastic | Value |
|------------|-------|
| `index` | 0 |
| `role` | `PRIMARY` |
| `settings.name` | "LICHEN" |
| `settings.psk` | Empty (security handled differently) |

Additional channels are not creatable or mutable. When an app requests secondary channel reads, the adapter may return
disabled secondary channel records for compatibility. Config writes to channel settings are acknowledged but ignored.

## Config Sections

The adapter returns synthetic config matching Meshtastic's expected structure:

| Config Section | Handling |
|----------------|----------|
| `device` | Stubbed role and broadcast interval |
| `position` | Stubbed GPS-not-present defaults |
| `power` | Stubbed defaults |
| `network` | Stubbed (no WiFi) |
| `display` | Stubbed defaults |
| `lora` | Maps from LICHEN PHY config |
| `bluetooth` | Current BLE state |
| `security` | Remote admin and debug surfaces disabled |
| `device_ui` | Stubbed defaults |

Each `FromRadio.config` payload contains exactly one `Config` oneof variant. Config writes via ToRadio are acknowledged but most are no-ops. The LICHEN stack controls actual radio parameters.

The staged `want_config_id` sync path is the current read-only config surface.
Packet-level `ADMIN_APP` reads are deferred until `project-LICHEN-t2hn.23` and
currently return deterministic unsupported status.

Target packet-level admin subset:

| Admin request | Response |
|---------------|----------|
| `get_owner_request` | Synthetic `User` for this LICHEN node |
| `get_channel_request` | Primary `Channel` response or disabled secondary channel |
| `get_config_request` | Synthetic supported config section, empty safe default for unsupported sections |
| `get_device_metadata_request` | Synthetic device metadata and firmware version |

Config/channel/owner write requests are acknowledged only if the app requires a response, but they are no-ops unless a
future Bead explicitly maps the setting into the native LICHEN contract. Commands such as reboot, factory reset, and
node DB reset are unsupported in the MVP and must return a deterministic unsupported/no-op result.

## Message Flow Examples

### Sending a Text Message

```
App: ToRadio { packet: MeshPacket {
    to: 0xFFFFFFFF,
    decoded: Data { portnum: TEXT_MESSAGE_APP, payload: "Hello" }
}}

Adapter:
    1. Extracts destination (broadcast)
    2. Verifies the synthetic primary channel and UTF-8 text payload, with a 200-byte MVP payload limit
    3. Calls the adapter text hook
    4. Queues local queueStatus for the Meshtastic app

LICHEN: The app-compat layer does not emit Meshtastic RF packets. The gateway currently reports unsupported for text
send attempts until the concrete Zephyr `/msg/inbox` or local send contract is implemented in `project-LICHEN-t2hn.7.2`.
Directed Meshtastic node-number resolution is tracked by `project-LICHEN-t2hn.7.1`.
```

### Receiving a NodeDB Position Update

```
LICHEN: Reads local location snapshot with valid latitude and longitude

Adapter:
    1. Copies lat/lon and optional alt/time/satellites into local info
    2. Encodes NodeInfo.position during NodeDB sync
    3. Queues NodeInfo FromRadio record
    4. Increments FromNum, triggers notify

App: Reads NodeDB sync, displays local node position on map
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
4. NodeDB positions appear on the map only for records with latitude and longitude
5. Node list populates with peers
