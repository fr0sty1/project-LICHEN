<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# MeshCore App Smoke Test

This procedure validates the LICHEN MeshCore-compatible local app surface. It is
not an RF interoperability test: a pass means a MeshCore client can use the
local BLE app interface to inspect and exercise a LICHEN node, not that LICHEN
frames can join a MeshCore radio mesh.

## Scope

Run this procedure whenever MeshCore BLE, MeshCore command handling, app
identity, or app-interface ingress/egress changes. The no-hardware preflight is
mandatory before any client run. The physical/client phase requires a BLE-capable
target and a real MeshCore app or command-line client.

Record all observed versions and logs in the Bead that requests the smoke run:

| Field | Required evidence |
|-------|-------------------|
| Firmware | Git commit, build command, board, overlay/conf fragments, Zephyr version, and whether `CONFIG_LORA_LICHEN_MESHCORE_BLE=y` is set. |
| Target | Board name, revision, bootloader or flashing path, and serial console device. |
| Client | App/tool name, version, source commit when available, phone/host OS, BLE adapter, and test date. |
| Pairing | Passkey behavior, encryption/authentication state, negotiated MTU when the client exposes it, and failure text for rejected pairing. |
| Logs | Firmware serial log from boot through disconnect plus client screenshots or CLI transcript for each checkpoint. |

## No-Hardware Preflight

Run these on the Linux Zephyr builder cache before flashing hardware:

```sh
. /mnt/lichen-zephyr/env.sh
cd /mnt/lichen-zephyr/work/project-LICHEN
# Override SMOKE_REF with the branch or commit under test.
SMOKE_REF=${SMOKE_REF:-origin/main}
tools/zephyr-clean-worktree.sh create project-LICHEN-meshcore-smoke "$SMOKE_REF"
cd /mnt/lichen-zephyr/work/project-LICHEN-meshcore-smoke
# If the changes under test are not in SMOKE_REF yet, apply the patch here.

west twister \
  -T lichen/tests/meshcore_codec \
  -T lichen/tests/meshcore_adapter \
  -T lichen/tests/meshcore_ble \
  -T lichen/tests/meshcore_gateway_adapter \
  -T lichen/tests/app_interface \
  -p native_sim/native/64 \
  --inline-logs \
  --outdir twister-out-meshcore-smoke-preflight \
  --extra-args ZEPHYR_EXTRA_MODULES="$PWD/lichen"

tools/zephyr-clean-worktree.sh verify-twister "$PWD" \
  twister-out-meshcore-smoke-preflight
```

Expected result: all selected configurations pass with no warnings. Do not
commit `twister-out-meshcore-smoke-preflight/`.

If the smoke run uses a newly enabled board, also build the gateway image before
flashing. Replace `<board>` and any extra overlays with the target-specific
values:

```sh
cat >/tmp/meshcore-smoke.conf <<'EOF'
CONFIG_LICHEN=y
CONFIG_LICHEN_MESHCORE_CODEC=y
CONFIG_LORA_LICHEN_BLE=n
CONFIG_LORA_LICHEN_MESHTASTIC_BLE=n
CONFIG_LORA_LICHEN_MESHCORE_BLE=y
CONFIG_BT=y
CONFIG_BT_PERIPHERAL=y
CONFIG_BT_MAX_CONN=1
CONFIG_BT_SMP=y
CONFIG_BT_FIXED_PASSKEY=y
EOF

west build -p always -b <board> lichen/apps/gateway -- \
  -DZEPHYR_EXTRA_MODULES=$PWD/lichen \
  -DEXTRA_CONF_FILE=/tmp/meshcore-smoke.conf
```

Do not continue to client testing if the build falls back to native NUS
(`CONFIG_LORA_LICHEN_BLE=y`) or Meshtastic BLE
(`CONFIG_LORA_LICHEN_MESHTASTIC_BLE=y`). MeshCore mode owns the BLE app surface
for this test.

## Firmware Boot Checks

1. Flash the image using the board-specific command and capture the full serial
   log from reset.
2. Confirm the log reports MeshCore BLE initialization and advertising:
   `MeshCore BLE advertising as "MeshCore-LICHEN"`, unless the Bead explicitly
   records a different test name.
3. Confirm there is no Meshtastic-compatible or native NUS advertising log in
   the same build.
4. Confirm the fixed passkey or product provisioning path is known before
   pairing. The default development passkey is `123456` unless the build or
   Bead overrides `CONFIG_LORA_LICHEN_MESHCORE_BLE_PASSKEY`.

Failure evidence: capture the first error line after boot, the Kconfig fragment
that selected the app surface, and the advertising payload if a BLE scanner can
read it.

## Discovery And Pairing

Use a BLE scanner, MeshCore app, or MeshCore-compatible CLI to verify:

1. The device advertises the MeshCore-compatible NUS service UUIDs and the name
   `MeshCore-LICHEN`.
2. A MeshCore client can discover the device in MeshCore mode.
3. A native LICHEN NUS/SLIP client and a Meshtastic client either do not list
   the device as compatible or fail with an expected wrong-mode symptom.
4. Pairing requires authenticated encrypted access in product builds. Plain
   unauthenticated GATT writes are allowed only in ztest/native_sim test builds.
5. The passkey prompt appears, the expected passkey succeeds, and an incorrect
   passkey fails without accepting RX writes or enabling TX notifications.
6. Record the negotiated ATT MTU. If the client remains at the default MTU, the
   status/config reads below must still complete within the accepted frame
   limits.

Failure evidence: scanner output, client error text, pairing state, and firmware
log from connection through disconnect.

## GATT Surface

Verify the MeshCore compatibility service is the Nordic UART Service UUID
triplet carrying MeshCore bytes:

| Attribute | UUID | Expected access |
|-----------|------|-----------------|
| Service | `6e400001-b5a3-f393-e0a9-e50e24dcca9e` | Advertised while MeshCore mode is active. |
| RX | `6e400002-b5a3-f393-e0a9-e50e24dcca9e` | Write or write-without-response after authenticated pairing in product builds. |
| TX | `6e400003-b5a3-f393-e0a9-e50e24dcca9e` | Notify after CCC subscription. |

Subscribe to TX notifications and capture the firmware log
`MeshCore TX notify enabled`. Disable notifications once and capture
`MeshCore TX notify disabled` if the client/tool exposes the CCC toggle.

## Startup And Read-Only Commands

Connect with the MeshCore client and verify the startup/read path:

| Action | Expected observation |
|--------|----------------------|
| Client starts session | Firmware logs `MeshCore BLE client connected`; raw startup command `010000000000000074` receives `SELF_INFO` for LICHEN identity or the documented degraded placeholder when identity is not configured. |
| Device query | Raw command `1603` receives `DEVICE_INFO`; protocol version is `3`; device metadata is LICHEN-branded and does not claim MeshCore RF compatibility. |
| Contact list | Empty compatibility contact table: start count `0`, end count `0`. |
| Channel `0` | One public compatibility channel named `Public`; secrets are absent/zero placeholders. |
| Channel `1` | Not found/error rather than synthetic extra channel data. |
| Battery/storage | Explicit placeholder values until HAL battery/storage providers are wired. |
| Device time | `GET_DEVICE_TIME` returns the implemented current-time response shape; record whether the value is a deterministic placeholder or board time source. |
| Custom vars | Empty compatibility response. |
| Auto-add config | Disabled response. |
| Default flood scope | Null/default placeholder. |

Capture the client screen or CLI bytes for each read. The canonical byte-level
oracles live in `test/vectors/meshcore_app_compat.json`.

## Message Ingress

1. Send a channel text message from the MeshCore client to channel `0`.
2. Verify the firmware dispatches through the LICHEN app-interface text ingress
   path, not a MeshCore RF path.
3. Expected MVP response:
   - If a submit provider is present, the client receives `OK` only after the
     submit path succeeds.
   - If no submit provider is registered, the client receives
     `ERR_UNSUPPORTED_CMD`.
4. Send invalid channel text cases:
   - Nonzero channel index.
   - Non-plain text type.
   - Invalid UTF-8 payload.
5. Send direct text with a known 6-byte MeshCore public-key prefix and verify
   the LICHEN message contract receives `has_to_iid=true` for the mapped peer
   IID.
6. Send direct text with no resolvable peer prefix and with an ambiguous prefix
   shared by more than one known peer.

Expected failures are explicit MeshCore errors. There must be no firmware log
claiming a MeshCore RF transmit.

## Incoming Event Egress

Inject or trigger a LICHEN app-interface incoming event while the client is
connected:

1. Text event: client first receives `MSG_WAITING`, then `SYNC_NEXT_MESSAGE`
   returns a channel message on compatibility channel `0`.
2. Status event: client receives `MSG_WAITING`, then `SYNC_NEXT_MESSAGE` returns
   the send-confirmed/status response.
3. Disconnect and reconnect, then confirm stale queued frames from the old
   session are not delivered to the new session.
4. Fill the pending-event queue if the test harness can inject enough events;
   the expected behavior is deterministic backpressure, not memory growth or
   dropped connection state.

Record both firmware logs and client-visible frames.

## Unsupported And Safety Checks

Verify the following operations fail explicitly and do not mutate native LICHEN
state:

| Operation | Expected result |
|-----------|-----------------|
| `SET_ADVERT_NAME` | `OK`; only MeshCore-local display metadata changes. |
| `SET_AUTOADD_CONFIG` | `OK`; only MeshCore-local auto-add metadata changes. |
| `SET_CHANNEL` | `OK` for the slot `0` local record shape; secret-bearing channel imports return `ERR_UNSUPPORTED_CMD`; no LICHEN group, multicast, OSCORE, or link material changes. |
| `SET_DEFAULT_FLOOD_SCOPE` | `OK` for empty clear or a 31-byte NUL-terminated name field plus 16-byte key; native flood/routing policy is unchanged. |
| `SET_DEVICE_PIN` | `OK` only when the BLE passkey hook accepts `0` or a six-digit PIN. |
| MeshCore radio/path/raw packet writes | `ERR_UNSUPPORTED_CMD`; no MeshCore RF packet path is invoked. |
| Unknown command IDs `0x00`, `0x42`, `0xff` | `ERR_UNSUPPORTED_CMD`. |

The smoke run fails if a compatibility-local write mutates native LICHEN
identity, security, group, radio, or routing state, or if `DEVICE_INFO` reports
a PIN that does not match the compatibility pairing policy.

## BLE Raw-Frame Checks

MeshCore BLE uses one raw MeshCore inner frame per NUS value. It must not accept
serial/TCP length framing on BLE.

Use a BLE tool capable of writing raw characteristic values and verify:

| Write value | Expected result |
|-------------|-----------------|
| `0a` | Valid raw `SYNC_NEXT_MESSAGE`; returns no-more-messages or the next queued event. |
| `3c01ff01` | Accepted as a raw command frame beginning with command `0x3c`; it is not a serial header because the little-endian length does not match the remaining payload. |
| `3e01ff01` | Accepted as a raw command frame beginning with command `0x3e`; it is not a serial header because the little-endian length does not match the remaining payload. |
| `3c01000a` | Rejected as serial/TCP framing on BLE, not treated as command `0x3c`. |
| `3e01000a` | Rejected as serial/TCP framing on BLE, not treated as command `0x3e`. |
| Frame longer than `CONFIG_LICHEN_MESHCORE_MAX_FRAME` | Rejected before reaching the adapter. |

If the client negotiates MTU 185, repeat one normal read/write at that MTU. If
the client remains at the default ATT MTU, record that value and confirm small
startup/read frames still pass.

## Disconnect Cleanup

1. Disconnect the client.
2. Confirm firmware logs `MeshCore BLE client disconnected`.
3. Reconnect and repeat `DEVICE_QUERY`.
4. Confirm RX, TX, read, and pending notification state from the previous
   session does not leak into the new session.

## Pass Criteria

A no-hardware preflight passes when the Twister command above passes with no
warnings. A full client smoke passes only when all BLE discovery, pairing,
read-only command, message ingress, incoming egress, unsupported-operation,
raw-frame, and disconnect checks have recorded evidence.

Any failure must create or update a Bead with:

- Exact firmware commit and build command.
- Client/app version and host device.
- Failing command or UI action.
- Expected and actual response bytes or screen text.
- Serial log excerpt from the same attempt.
- Whether the failure blocks documentation of the support matrix.
