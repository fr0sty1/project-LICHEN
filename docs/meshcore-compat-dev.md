<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# MeshCore Compatibility Development Notes

LICHEN's MeshCore surface is a local app-compatibility shim. It uses MeshCore
client transports and byte-command shapes so existing clients can inspect and
exercise a LICHEN node, but it does not make LICHEN RF packets MeshCore
compatible.

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
