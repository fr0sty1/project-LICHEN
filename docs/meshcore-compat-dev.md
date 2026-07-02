<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# MeshCore Compatibility Development Notes

LICHEN's MeshCore surface is a local app-compatibility shim. It uses MeshCore
client transports and byte-command shapes so existing clients can inspect and
exercise a LICHEN node, but it does not make LICHEN RF packets MeshCore
compatible.

BLE advertising and product-mode ownership are tracked in
`docs/ble-app-surface-owner.md`. Current firmware builds keep native LICHEN BLE,
Meshtastic BLE, and MeshCore BLE mutually exclusive.

## Support Matrix

This matrix describes the implemented LICHEN MeshCore app-compatibility surface.
It is intentionally local-client compatibility only. LICHEN nodes do not join
MeshCore RF meshes, emit MeshCore LoRa frames, import MeshCore channel secrets,
or expose native LICHEN keys through MeshCore commands.

| Area | Current support | Evidence | Remaining gap |
|------|-----------------|----------|---------------|
| RF interoperability | Not supported. MeshCore clients talk to a local LICHEN node over the compatibility BLE surface only; mesh traffic remains LICHEN IPv6/SCHC/RPL/CoAP. | Unsupported RF/path/raw operations return explicit MeshCore errors in `lichen/tests/meshcore_adapter`; smoke test requires checking that no MeshCore RF transmit is logged. | None for MVP; any RF interoperability request is out of scope for this compatibility shim. |
| Transport | MeshCore-compatible BLE mode uses the Nordic UART Service UUID triplet and one raw MeshCore inner frame per NUS value. Native LICHEN BLE and Meshtastic BLE are mutually exclusive with MeshCore BLE in a single firmware build. | `lichen/tests/meshcore_ble`, `lichen/apps/gateway/src/ble_app_owner.c`, and `docs/meshcore-smoke-test.md`. | Physical discovery/pairing evidence remains blocked by `project-LICHEN-9c4y.20`. |
| BLE security | Product smoke policy requires authenticated encrypted pairing/passkey before RX writes and TX notifications. ztest/native_sim builds may use test-only permissions. | `docs/meshcore-smoke-test.md` records pairing evidence requirements and the development passkey policy. | Real client pairing validation is blocked by `project-LICHEN-9c4y.20`. |
| Identity and device info | `APP_START`/`SELF_INFO` and `DEVICE_INFO` return LICHEN-branded identity/status/config data. Without a published app identity, SELF_INFO is degraded but explicit; with app identity enabled, the public key is projected into SELF_INFO only. | `lichen/tests/meshcore_adapter` baseline and identity scenarios; production gateway self-identity publication from `project-LICHEN-9c4y.19`; `test/vectors/meshcore_app_compat.json`. | None for no-hardware MVP; physical app observation is covered by `project-LICHEN-9c4y.20`. |
| Contacts | Compatibility contact list is empty and deterministic: contacts start count `0`, then end count `0`. Peer/contact projection is not part of the MVP support claim. | `test/vectors/meshcore_app_compat.json` and `lichen/tests/meshcore_adapter`. | None for MVP. A future peer/contact feature must first define a compatibility-local mapping Bead. |
| Channels | Channel `0` is a synthetic public compatibility channel named `Public`; channel `n > 0` is not found. Secrets are absent or zero placeholders and never map to LICHEN OSCORE, link-layer, group, or routing state. | `test/vectors/meshcore_app_compat.json`; `lichen/tests/meshcore_adapter`. | `SET_CHANNEL` compatibility-local storage is tracked by `project-LICHEN-9c4y.21`. |
| Config reads | Read-only placeholders exist for battery/storage, device time, custom vars, auto-add config, and default flood scope. Placeholder values must be explicit and must not imply MeshCore RF behavior. | `test/vectors/meshcore_app_compat.json`; `docs/meshcore-smoke-test.md` startup/read checklist. | HAL-backed native status improvements are outside the MeshCore MVP matrix and should be handled by normal HAL/provider Beads before changing these placeholders. |
| Config writes/admin | Unsupported writes return `RESP_ERR + ERR_UNSUPPORTED_CMD` unless a feature has an implemented compatibility-local store. This includes advert name, channel, auto-add, default flood scope, device PIN, raw/radio/path operations, remote admin, factory reset, reboot, private-key, and signing flows. | `lichen/tests/meshcore_adapter` unsupported command coverage; `test/vectors/meshcore_app_compat.json`. | Compatibility-local stores are tracked by `project-LICHEN-9c4y.21`. |
| Message ingress | `SEND_CHANNEL_TXT_MSG` for channel `0`, plain text, and valid UTF-8 maps to the shared app-interface text submit boundary. It returns success only after the submit provider succeeds; without a provider it returns `ERR_UNSUPPORTED_CMD`. Direct peer text validates the 6-byte MeshCore peer prefix and UTF-8, then returns `ERR_NOT_FOUND` because no peer-prefix mapping exists. | `lichen/tests/meshcore_adapter`, `lichen/tests/meshcore_gateway_adapter`, `test/vectors/meshcore_app_compat.json`. | Gateway message-contract coverage is tracked by `project-LICHEN-t2hn.7.2.2`; direct peer mapping is tracked by `project-LICHEN-9c4y.22`. |
| Incoming events | Connected clients receive queued LICHEN app-interface text/status events via `MSG_WAITING` and `SYNC_NEXT_MESSAGE`. Events are scoped to the active BLE session epoch; reconnects do not inherit stale queued frames. | `lichen/tests/meshcore_adapter`, `lichen/tests/meshcore_gateway_adapter`, and `docs/meshcore-smoke-test.md`. | Physical client validation is blocked by `project-LICHEN-9c4y.8.2` and `project-LICHEN-9c4y.20`. |
| Raw-frame limits | BLE accepts raw MeshCore inner frames only. Serial/TCP length-prefixed `0x3c`/`0x3e` frames are rejected on BLE, oversized frames are rejected before adapter dispatch, and queue backpressure is deterministic. | `lichen/tests/meshcore_ble`; smoke-test raw-frame checklist. | None for no-hardware MVP; physical MTU/client behavior is part of `project-LICHEN-9c4y.20`. |
| Troubleshooting symptoms | Wrong BLE mode means the device may advertise native LICHEN or Meshtastic surfaces instead of MeshCore. Unsupported commands return explicit errors rather than hanging. No-provider message send returns unsupported. Bad channel/type/UTF-8 returns deterministic argument/not-found errors. | `docs/meshcore-smoke-test.md`; native_sim adapter tests. | Client-specific UI wording must be captured during `project-LICHEN-9c4y.20`. |

Any future expansion that changes an unsupported row to supported must add or
update Beads for the storage/provider/transport work, canonical vectors, and
native_sim or qemu tests before the support claim is advertised.

## Channel And Secret Policy

MeshCore channel records are compatibility-local views. They are not LICHEN
groups, multicast authorities, OSCORE contexts, link keys, DANE material, or
native provisioning state.

The MVP exposes one synthetic channel slot:

| Command | Policy |
|---------|--------|
| `GET_CHANNEL(0)` | Return a public compatibility channel named `Public`. Secret fields are zero/absent placeholders and MUST NOT contain native LICHEN secrets. |
| `GET_CHANNEL(n>0)` | Return `ERR_NOT_FOUND`. |
| `SET_CHANNEL` | Return `ERR_UNSUPPORTED_CMD` until a settings-backed compatibility-only channel store exists. MeshCore channel secrets MUST NOT be imported as native LICHEN security material. |
| `SEND_CHANNEL_TXT_MSG` | Validate channel `0`, plain text type, and UTF-8, then submit to the shared app-interface text ingress provider. Return `ERR_UNSUPPORTED_CMD` when no production submit provider is registered. |
| Incoming channel text | Use compatibility channel index `0` and no MeshCore path when surfacing queued LICHEN events to clients. |

Future support for `SET_CHANNEL` may persist a MeshCore-only display/channel
record for client UX. That store must be clearly labeled compatibility-local,
must be eraseable without affecting LICHEN membership or keys, and must never
derive or reveal OSCORE/link-layer material.

## Config Write Policy

Most MeshCore write commands describe MeshCore RF behavior that LICHEN does not
implement. The default write response is `RESP_ERR + ERR_UNSUPPORTED_CMD`.
Specific MVP write behavior:

| Command | Policy |
|---------|--------|
| `SET_ADVERT_NAME` | Unsupported until a compatibility-local display-name store exists. |
| `SET_AUTOADD_CONFIG` | Unsupported until a compatibility-local store exists; `GET_AUTOADD_CONFIG` returns disabled. |
| `SET_DEFAULT_FLOOD_SCOPE` | Unsupported; `GET_DEFAULT_FLOOD_SCOPE` returns a null/default placeholder. |
| `SET_DEVICE_PIN` | Unsupported until a settings-backed MeshCore PIN store exists. |
| Radio/path/raw packet writes | Unsupported; they would imply MeshCore RF interoperability or mutate LICHEN radio policy outside the native control path. |

Read-only placeholders are allowed only when they avoid implying MeshCore RF
interoperability. Writes may become `OK` only after the corresponding
compatibility-local store exists and has native_sim tests for persistence,
validation, and failure behavior.

## BLE PIN Policy

The current MeshCore BLE product mode can install a configured fixed passkey for
client compatibility. That passkey is a temporary product-mode compatibility
setting, not a LICHEN trust secret. Production policy is:

- Provision or generate a per-device MeshCore compatibility PIN.
- Persist it in a settings-backed store separate from native LICHEN keys.
- Reject invalid PIN writes with `ERR_ILLEGAL_ARG`.
- Return `ERR_UNSUPPORTED_CMD` for `SET_DEVICE_PIN` until that store exists.
- Never expose native provisioning secrets, OSCORE master secrets, link keys,
  or private keys through MeshCore `DEVICE_INFO`, channel records, or PIN flows.

`test/vectors/meshcore_app_compat.json` records the current deterministic MVP
behavior for the write commands above, and the `meshcore_adapter` native_sim
test consumes those vectors through a generated fixture header.

## Smoke Testing

Use `docs/meshcore-smoke-test.md` for MeshCore app/client smoke runs. It defines
the required no-hardware Twister preflight, BLE discovery and pairing evidence,
raw-frame checks, app-interface message ingress/egress checks, and the hardware
artifacts that must be recorded before declaring client compatibility tested.
