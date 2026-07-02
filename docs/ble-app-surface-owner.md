<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# BLE App Surface Owner

LICHEN currently has three local BLE app surfaces in the Zephyr gateway:

| Surface | Current role | Current UUIDs | Payload contract |
|---------|--------------|---------------|------------------|
| Native LICHEN BLE | Local Client Interface over BLE GATT | LICHEN-specific native LCI UUIDs by default; legacy NUS only when explicitly enabled | SLIP-framed IPv6 packets |
| Meshtastic BLE | Meshtastic app compatibility | Meshtastic service and ToRadio/FromRadio/FromNum characteristics | Raw Meshtastic protobuf GATT values |
| MeshCore BLE | MeshCore app compatibility | NUS | Raw MeshCore command/response frames |

The current firmware deliberately builds at most one BLE app surface at a time.
Some gateway configurations build no BLE app surface. When a surface is enabled,
it owns `bt_enable()`, connection callbacks, and advertising restart. That is
acceptable for product-mode smoke testing, but it is not a shared BLE
architecture: two modules must not independently call `bt_le_adv_start()` or
race to restart advertising after a disconnect.

## Current Policy

The current Kconfig policy is:

- `CONFIG_LORA_LICHEN_BLE` enables native LICHEN BLE LCI over
  SLIP-framed IPv6. Its default GATT profile is the LICHEN-specific native LCI
  UUID set.
- `CONFIG_LORA_LICHEN_BLE_LEGACY_NUS` keeps native LICHEN BLE LCI on the
  legacy NUS UUID triplet for existing mutually exclusive native product
  images.
- `CONFIG_LORA_LICHEN_MESHTASTIC_BLE` enables the Meshtastic compatibility
  surface and depends on `!LORA_LICHEN_BLE`.
- `CONFIG_LORA_LICHEN_MESHCORE_BLE` enables the MeshCore compatibility surface
  and depends on `!LORA_LICHEN_BLE` and `!LORA_LICHEN_MESHTASTIC_BLE`.

Gateway board `.conf` fragments may currently select the default native LICHEN
BLE local-client surface for validated boards. Product or app configuration
fragments must override that default when selecting Meshtastic or MeshCore
compatibility surfaces. Zephyr board definitions and DTS overlays for T-Deck,
R1 Neo, T-Echo, and similar targets should describe BLE hardware capability
separately from app-compat product mode where practical.

This means simultaneous native LICHEN plus Meshtastic or MeshCore BLE is not
supported by the current firmware image. Native LICHEN legacy NUS mode and
MeshCore both use the NUS UUID triplet with incompatible payload semantics, so
legacy NUS mode must stay mutually exclusive with MeshCore.

## Native UUID Policy

Decision: native LICHEN BLE may keep the Nordic UART Service UUID triplet only
inside the current mutually exclusive native product mode. Any firmware image
that enables native LICHEN BLE together with a compatibility BLE surface MUST
first move native LICHEN BLE to LICHEN-specific service and characteristic
UUIDs. A combined native-plus-MeshCore image MUST NOT advertise two NUS
services with different payload contracts.

Rationale:

- MeshCore client compatibility depends on exact NUS UUIDs carrying raw
  MeshCore frames.
- Legacy native LICHEN BLE can use the same NUS UUIDs for SLIP-framed IPv6.
- BLE centrals discover and bind by UUID, so two incompatible services with the
  same UUID triplet create ambiguous client behavior.
- Preserving NUS for the mutually exclusive native mode avoids breaking the
  existing no-hardware and board-default native BLE path while compatibility
  product modes are still isolated.

Client and migration impact:

- Existing native BLE clients that know only NUS continue to work with
  product images that enable `CONFIG_LORA_LICHEN_BLE_LEGACY_NUS` while that
  mode remains exclusive.
- New native clients SHOULD learn the LICHEN-specific UUIDs before any
  coexistence image is shipped.
- During migration, native clients MAY probe LICHEN-specific UUIDs first and
  fall back to NUS only when no compatibility surface is active.
- Compatibility product images MUST NOT rely on native-client NUS fallback,
  even when the compatibility surface itself uses distinct UUIDs.
- MeshCore clients continue to see exact NUS UUIDs and the MeshCore
  compatibility name in MeshCore product mode.

## Direct Native BLE LCI Service

Decision: the direct native LICHEN BLE app surface is the Local Client
Interface (LCI) carried as SLIP-framed IPv6 packets over a LICHEN-specific GATT
service. It is not the Meshtastic or MeshCore app-compat surface, and it is not
the older CBOR native protocol draft in `spec/lichen-native/`. The BLE service
is transport for the standard LCI IPv6/CoAP contract described in
`spec/11-lci.md`.

The assigned native LCI UUIDs are UUIDv5 values and are treated as stable
protocol identifiers. They are derived by applying UUIDv5 to DNS namespace
`6ba7b810-9dad-11d1-80b4-00c04fd430c8` with name `lichen.mesh` to create the
LICHEN BLE namespace `d4b23c0e-2ffc-52b7-9ec6-b4b5baa32382`, then applying
UUIDv5 again with the attribute names below.

| Attribute | UUIDv5 name | UUID | Access | Semantics |
|-----------|-------------|------|--------|-----------|
| Service | `ble-lci-service` | `e665960c-7c84-5606-a8d3-884507d0b7a8` | Primary service | Native LICHEN BLE LCI service. |
| RX IPv6 SLIP | `ble-lci-rx-ipv6-slip` | `5e6e304a-29af-52d9-a813-306f0f888586` | Write without response | Client writes RFC 1055 SLIP-framed IPv6 packets to the gateway. |
| TX IPv6 SLIP | `ble-lci-tx-ipv6-slip` | `be4d4a23-876b-592b-b252-440367e18e43` | Notify | Gateway notifies RFC 1055 SLIP-framed IPv6 packets to the client. |
| Protocol version | `ble-lci-version` | `9158dca0-14ea-5e1c-8580-b97e7c6381b8` | Read | Two-byte little-endian native BLE LCI version. Initial value: `0x0001`. |
| Capabilities | `ble-lci-capabilities` | `3d3c63f3-ce23-5451-b357-738a12c20df7` | Read | Four-byte little-endian bitset of advertised LCI transport capabilities. |

Defined capability bits:

- Bit 0: RFC 1055 SLIP-framed IPv6 over RX/TX characteristics is supported.
- Bit 1: BLE LE Secure Connections pairing is required for non-read-only local
  operations.
- Bit 2: OSCORE-protected local CoAP operations are available when local OSCORE
  context provisioning is configured.

The initial capabilities value is exactly four octets and currently sets only
bit 0. Reserved or unsupported capability bits MUST be written as zero by the
gateway and ignored by clients. Clients SHOULD discover this service first.
They MAY fall back to NUS only when the native service is
absent and the image is known to be the legacy mutually exclusive native BLE
product mode. Clients MUST NOT use NUS fallback when MeshCore compatibility is
advertised, because MeshCore owns NUS payload semantics.

LCI payload rules:

- RX and TX values carry a byte stream split across BLE ATT writes and
  notifications. ATT value boundaries are fragmentation boundaries only; they
  are not IPv6 packet boundaries.
- Each IPv6 packet is delimited by RFC 1055 SLIP END bytes. ESC handling is the
  same as the USB/serial LCI transport.
- The gateway MUST reset SLIP reassembly state on connect and disconnect.
- The initial maximum decoded IPv6 packet size is 1280 octets. The gateway
  MUST reject oversize decoded packets instead of dispatching a truncated IPv6
  packet.
- The initial implementation preserves `CONFIG_BT_MAX_CONN=1`; multi-client
  BLE LCI requires separate per-connection reassembly, CCC state, and egress
  queues.

Security and access:

- Native BLE LCI follows the LCI security policy in `spec/11-lci.md`.
- Product images SHOULD require LE Secure Connections before enabling Standard
  or Admin local operations.
- Read-only discovery characteristics MAY remain readable before pairing.
- OSCORE remains the end-to-end protection for sensitive CoAP operations and is
  not replaced by BLE link encryption.

T-Deck boundary:

- The LilyGO T-Deck gateway image MUST NOT enable direct native BLE LCI until
  the LICHEN-specific service UUIDs are implemented and BLE egress from the
  gateway to the local client is wired.
- T-Deck native BLE LCI can be built and tested with native_sim/Twister for
  service shape, advertisement composition, SLIP ingress/egress, and
  unsupported mode rejection without physical hardware.
- Declaring T-Deck BLE-local capability still requires a physical BLE smoke
  test with a real central, ATT MTU evidence, connect/disconnect logs, and
  bidirectional LCI packet evidence.

## T-Deck BLE IP Transport Decision

Decision: the T-Deck native local-client MVP uses the direct native BLE LCI
service above: SLIP-framed IPv6 packets over LICHEN-specific GATT
characteristics. Do not select BLE IPSP/6LoWPAN for the T-Deck MVP, and do not
advertise legacy NUS as the default T-Deck native surface.

BLE IPSP remains the standards-track way to carry IPv6 over Bluetooth LE. RFC
7668 specifies IPv6 over BLE using 6LoWPAN techniques, and the Bluetooth IPSP
specification defines discovery and IPv6 packet exchange over Bluetooth LE. It
is a good future interoperability target when Zephyr, host OS tooling, and
client-app support are all proven for the selected board.

Current evidence does not make IPSP the lowest-risk T-Deck implementation path:

- Upstream Zephyr latest documentation lists ESP32-S3 Bluetooth LE hardware and
  Bluetooth HCI support for ESP32-S3-class boards, but the documented IPSP
  sample path is built and tested in those docs with `nrf52840dk/nrf52840`.
- The local pinned Zephyr v3.7.0 tree has the IP Support Service UUID and
  Bluetooth IPSP link-address definitions, but the Zephyr 3.7 release notes say
  IPSP support was removed and `CONFIG_NET_L2_BT` no longer exists. The pinned
  tree also does not contain the upstream `samples/bluetooth/ipsp` sample path
  used by the latest docs.
- The LICHEN firmware already has a transport contract for native BLE LCI:
  SLIP-framed IPv6 over RX/TX GATT values, version and capability
  characteristics, a 1280-octet decoded packet limit, and reset-on-session
  reassembly rules.
- The T-Deck board config currently disables both HAL BLE-local capability and
  SLIP advertising because the board must not advertise an incomplete
  local-client service.

Native app impact:

- Native clients SHOULD discover the LICHEN-specific native BLE LCI service
  first, read the version and capabilities characteristics, and then run the
  same LCI IPv6/CoAP contract used by serial/IP local transports.
- Native clients MAY fall back to legacy NUS only for known mutually exclusive
  native BLE images that advertise no compatibility surface. T-Deck product
  images should not rely on that fallback.
- IPSP support, if later added, is a separate transport option and must not
  change the LCI resource contract or bypass LCI security policy.

Advertising behavior:

- T-Deck MUST keep `CONFIG_LICHEN_HAS_BLE_LOCAL=n` and
  `CONFIG_LORA_LICHEN_BLE=n` for product images until the LICHEN-specific UUID
  service and bidirectional BLE egress pass no-hardware tests and physical
  T-Deck validation records a real central, ATT MTU, connect/disconnect logs,
  and bidirectional LCI packet evidence.
- When enabled, T-Deck native BLE LCI advertises the LICHEN-specific service
  UUID, not NUS, unless a deliberate legacy-only developer image explicitly sets
  `CONFIG_LORA_LICHEN_BLE_LEGACY_NUS=y`.
- A future IPSP experiment would need to restore or replace the removed Zephyr
  IPSP network L2 support, advertise the IP Support Service, and use the host's
  Bluetooth 6LoWPAN/IPSP path. It should be tracked separately from the T-Deck
  native BLE LCI product path.

References:

- Zephyr ESP32-S3 features: <https://docs.zephyrproject.org/latest/boards/espressif/common/soc-esp32s3-features.html>
- Zephyr ESP32-S3-DevKitC supported features: <https://docs.zephyrproject.org/latest/boards/espressif/esp32s3_devkitc/doc/index.html>
- Zephyr Bluetooth IPSP sample: <https://docs.zephyrproject.org/latest/samples/bluetooth/ipsp/README.html>
- RFC 7668, IPv6 over Bluetooth Low Energy: <https://www.rfc-editor.org/rfc/rfc7668.html>
- Bluetooth Internet Protocol Support Profile 1.0: <https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/IPSP_v1.0/out/en/index-en.html>

Blocked product modes:

- Native-plus-MeshCore BLE remains blocked until native LICHEN BLE has
  LICHEN-specific UUIDs, tests cover both UUID sets, and client discovery notes
  are updated.
- Native-plus-Meshtastic BLE remains blocked until native LICHEN BLE has
  LICHEN-specific UUIDs and until the single-session owner and
  `CONFIG_BT_MAX_CONN=1` policy are replaced with tested multi-surface session
  handling.
- Any future combined BLE product mode must keep advertising composition,
  connection arbitration, and per-surface queues under the shared owner.

The owner design does not make every BLE-capable board an app-compatible
product. STM32WL/Nucleo WL55JC remains serial/SLIP only because it has no BLE
radio. The nRF52840 DK is a useful BLE/CoAP shell but not a complete LoRa BLE
product unless paired with an external radio configuration. T-Deck BLE app
surfaces remain disabled until its local-client egress path is modeled. R1 Neo
and T-Echo currently enable native LICHEN BLE NUS, not Meshtastic or MeshCore
product modes. T1000-E uses USB CDC-ACM native protocol and must not be counted
as BLE-local evidence.

## Target Owner

A future shared owner should be the only module that calls `bt_enable()`,
`bt_le_adv_start()`, `bt_le_adv_stop()`, or product-mode advertising restart.
Individual app surfaces should register service descriptors and session hooks
with that owner, but they should not directly own advertising.

The owner should provide:

- BLE stack initialization and one advertising state machine.
- Advertising and scan-response composition from enabled app surfaces.
- A product-mode name policy that preserves existing app discovery behavior.
- Connection arbitration for the active local app client.
- Dispatch of connect, disconnect, MTU/security, and CCC events to the selected
  app surface.
- Explicit restart behavior after disconnect and after fatal session reset.

The first shared-owner implementation should preserve `CONFIG_BT_MAX_CONN=1`.
The Meshtastic and MeshCore surfaces store CCC state, read cursors, bounded
queues, and session epochs globally. Those data structures are connection
scoped in practice, not multi-client safe. Raising the connection count requires
separate per-client queue and CCC work.

## Advertising Composition

The owner should build legacy advertising and scan-response data from a single
source of truth:

- Flags: `BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR`.
- Service UUIDs required for discoverability by the selected product mode.
- A short or complete device name selected by product policy.

The owner must verify the encoded advertising and scan-response payload lengths
before starting advertising. If the selected app surfaces cannot fit in legacy
advertising, the owner must fail the build configuration or return a visible
startup error instead of silently dropping a service UUID that mobile apps need
for discovery.

Current app discovery expectations to preserve:

- Native LICHEN BLE advertises the LICHEN-specific native LCI UUID set for
  SLIP local-client access.
- Existing mutually exclusive native legacy images advertise NUS for SLIP
  local-client access.
- Meshtastic BLE advertises the Meshtastic service UUID and a LICHEN-branded
  compatibility name.
- MeshCore BLE advertises NUS and the MeshCore compatibility name.

Because MeshCore and native LICHEN legacy mode both advertise NUS, a combined
native-legacy-plus-MeshCore product mode is unsafe.

Public BLE identity must stay compatibility-scoped. Meshtastic metadata and
advertised names may help mobile apps find the local shim, but they must remain
LICHEN-branded and must not imply Meshtastic RF firmware. MeshCore names, PINs,
and channel/display records are compatibility-local state and must not expose or
derive native LICHEN security material.

Security policy is part of the product mode. MeshCore production mode requires
SMP, fixed passkey setup, and authenticated encrypted GATT access before
advertising. Meshtastic mode currently preserves upstream app compatibility with
plain characteristic permissions; adding pairing or bonding is a separate app
compatibility decision that needs real Android and iOS evidence. Native LICHEN
BLE carries the local IPv6 client interface and should follow the Local Client
Interface security policy rather than inherit Meshtastic or MeshCore settings.

## Session Boundaries

Each app surface keeps ownership of its protocol queues and payload validation,
but the shared owner should own the outer BLE session lifecycle.

Required invariants:

- Disconnect clears connection-scoped RX/TX queues for Meshtastic and MeshCore.
- Session epochs continue to reject stale responses that were produced for a
  prior connection.
- CCC state is reset on disconnect and does not leak across clients.
- Native LICHEN SLIP reassembly state is reset on connect and disconnect.
- MeshCore production builds install their passkey and authenticated encrypted
  GATT policy before advertising starts.
- MeshCore `DEVICE_INFO` PIN reporting must match the selected compatibility
  pairing PIN or follow a documented and tested policy that hides the PIN from
  clients. The owner must not set one PIN while the MeshCore adapter reports a
  different value.
- Unsupported product-mode combinations fail deterministically at Kconfig or
  startup; they must not register colliding services and hope client behavior is
  benign.

The owner should expose small hooks such as:

- `surface_prepare()`: validate settings and install pairing policy.
- `surface_connected(conn)`: acquire any per-session reference and reset RX
  cursors.
- `surface_disconnected(conn, reason)`: clear queues and CCC state.
- `surface_advertising(ad, sd)`: append required UUID/name entries.

The hook API should be internal to the gateway app until two production
surfaces use it. Avoid exporting a stable public ABI before the connection and
UUID policy has real callers.

## Implementation Beads

The shared owner should be implemented in small slices:

1. Add `ble_app_owner` with one `bt_enable()` and one advertising restart path,
   initially preserving the existing mutually exclusive product modes.
2. Move native LICHEN BLE advertising and connection callback ownership behind
   the owner without changing the NUS/SLIP payload contract.
3. Move Meshtastic BLE advertising and connection callback ownership behind the
   owner, preserving single-connection queues, FromNum behavior, and session
   epochs.
4. Move MeshCore BLE advertising, passkey setup, and connection callback
   ownership behind the owner, preserving authenticated encrypted access in
   production builds and keeping the selected compatibility PIN aligned with
   MeshCore `DEVICE_INFO` reporting.
5. Move native LICHEN BLE to LICHEN-specific UUIDs, update client discovery
   notes, and cover both legacy NUS-exclusive and LICHEN-specific native UUID
   paths before enabling any combined native-plus-compatibility product mode.
6. Add native_sim tests for advertising composition, unsupported Kconfig/product
   combinations, disconnect queue cleanup, and stale session rejection.

Physical app smoke tests remain separate validation. The owner can be designed
and unit-tested without radios, boards, displays, GNSS, battery ADCs, or mobile
phones, but declaring real app compatibility still requires the hardware and
client evidence tracked by the relevant smoke-test Beads.

For Meshtastic product mode, board validation must include ATT evidence that a
client can write one complete 504-byte `ToRadio` protobuf value and read one
complete 510-byte `FromRadio` protobuf value without serial StreamAPI framing.
MTU buffer settings alone are not enough to mark a board compatible.
