<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# BLE App Surface Owner

LICHEN currently has three local BLE app surfaces in the Zephyr gateway:

| Surface | Current role | Current UUIDs | Payload contract |
|---------|--------------|---------------|------------------|
| Native LICHEN BLE | Local Client Interface over BLE UART | Nordic UART Service (NUS) | SLIP-framed IPv6 packets |
| Meshtastic BLE | Meshtastic app compatibility | Meshtastic service and ToRadio/FromRadio/FromNum characteristics | Raw Meshtastic protobuf GATT values |
| MeshCore BLE | MeshCore app compatibility | NUS | Raw MeshCore command/response frames |

The current firmware deliberately builds at most one BLE app surface at a time.
Some gateway configurations build no BLE app surface. When a surface is enabled,
it owns `bt_enable()`, connection callbacks, and advertising restart. That is
acceptable for product-mode smoke testing, but it is not a shared BLE
architecture: two modules must not independently call `bt_le_adv_start()` or
race to restart advertising after a disconnect.

## Current Policy

The current Kconfig policy remains:

- `CONFIG_LORA_LICHEN_BLE` enables native LICHEN NUS/SLIP.
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
supported by the current firmware image. Native LICHEN and MeshCore also both
use the NUS UUID triplet with incompatible payload semantics, so they must stay
mutually exclusive until native LICHEN BLE moves to LICHEN-specific UUIDs or a
different discovery policy prevents clients from binding to the wrong service.

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

- Native LICHEN BLE advertises NUS for SLIP local-client access.
- Meshtastic BLE advertises the Meshtastic service UUID and a LICHEN-branded
  compatibility name.
- MeshCore BLE advertises NUS and the MeshCore compatibility name.

Because MeshCore and native LICHEN both advertise NUS today, a combined
native-plus-MeshCore product mode is unsafe until their discovery identity is
separated.

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
5. Decide whether native LICHEN BLE gets LICHEN-specific UUIDs before enabling
   any combined native-plus-MeshCore product mode.
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
