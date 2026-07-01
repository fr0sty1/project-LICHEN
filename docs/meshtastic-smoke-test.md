<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Meshtastic App Smoke Test

This procedure validates the LICHEN Meshtastic-compatible local app surface
with unmodified Android and iOS Meshtastic clients. It is not an RF
interoperability test: a pass means the mobile app can use the local BLE app
interface to inspect and exercise a LICHEN node, not that LICHEN frames can join
a Meshtastic LoRa mesh.

## Scope

Run this procedure whenever Meshtastic BLE, the Meshtastic codec/adapter,
app-interface ingress/egress, BLE advertising policy, or metadata/config sync
changes. The no-hardware preflight is mandatory before any mobile-client run.
The mobile phase requires a BLE-capable target, one Android device, and one iOS
device with Meshtastic installed.

Record all observed versions and logs in the Bead that requests the smoke run:

| Field | Required evidence |
|-------|-------------------|
| Firmware | Git commit, build command, board, overlay/conf fragments, Zephyr version, and confirmation that `CONFIG_LORA_LICHEN_MESHTASTIC_BLE=y`. |
| Target | Board name, revision, bootloader or flashing path, serial console device, and whether this board already has Meshtastic ATT long-read/write evidence. |
| Android client | Meshtastic Android app version, source commit when available, Android version, phone model, BLE scanner/tool version, and test date. |
| iOS client | Meshtastic iOS app version, source commit when available, iOS version, device model, BLE scanner/tool version, and test date. |
| BLE session | Advertised name, service UUIDs, pairing/bonding prompts, negotiated ATT MTU when visible, and whether 504-byte writes plus 510-byte reads were proven. |
| Logs | Firmware serial log from boot through disconnect plus app screenshots, screen recordings, or scanner/client transcripts for each checkpoint. |

## No-Hardware Preflight

Run these on the Linux Zephyr builder cache before flashing hardware:

```sh
. /mnt/lichen-zephyr/env.sh
cd /mnt/lichen-zephyr/work/project-LICHEN
# Override SMOKE_REF with the branch or commit under test.
SMOKE_REF=${SMOKE_REF:-origin/main}
tools/zephyr-clean-worktree.sh create project-LICHEN-meshtastic-smoke "$SMOKE_REF"
cd /mnt/lichen-zephyr/work/project-LICHEN-meshtastic-smoke
# If the changes under test are not in SMOKE_REF yet, apply the patch here.

west twister \
  -T lichen/tests/meshtastic_codec \
  -T lichen/tests/meshtastic_adapter \
  -T lichen/tests/meshtastic_ble \
  -T lichen/tests/meshtastic_gateway_adapter \
  -T lichen/tests/app_interface \
  -T lichen/tests/app_identity \
  -p native_sim \
  --inline-logs \
  --outdir twister-out-meshtastic-smoke-preflight \
  --extra-args ZEPHYR_EXTRA_MODULES=$PWD/lichen

tools/zephyr-clean-worktree.sh verify-twister "$PWD" \
  twister-out-meshtastic-smoke-preflight
```

Expected result: all selected configurations pass with no warnings. Do not
commit `twister-out-meshtastic-smoke-preflight/`.

Run the Python vector/prototype drift checks that exercise the canonical
Meshtastic app-compat vectors:

```sh
cd /mnt/lichen-zephyr/work/project-LICHEN-meshtastic-smoke/python
PYTHONPATH=src python3 -m pytest \
  tests/test_vectors.py \
  tests/interface/meshtastic \
  tests/interface/test_meshtastic_address.py \
  tests/interface/test_meshtastic_translate.py \
  tests/interface/meshtastic/test_zephyr_unsupported_portnums.py
```

If the smoke run uses a newly enabled board, also build the gateway image before
flashing. Replace `<board>` and any extra overlays with the target-specific
values:

```sh
cat >/tmp/meshtastic-smoke.conf <<'EOF'
CONFIG_LICHEN=y
CONFIG_LICHEN_MESHTASTIC_CODEC=y
CONFIG_LORA_LICHEN_BLE=n
CONFIG_LORA_LICHEN_MESHTASTIC_BLE=y
CONFIG_LORA_LICHEN_MESHCORE_BLE=n
CONFIG_BT=y
CONFIG_BT_PERIPHERAL=y
CONFIG_BT_MAX_CONN=1
EOF

west build -p always -b <board> lichen/apps/gateway -- \
  -DZEPHYR_EXTRA_MODULES=$PWD/lichen \
  -DEXTRA_CONF_FILE=/tmp/meshtastic-smoke.conf
```

Do not continue to mobile testing if the build falls back to native LICHEN NUS
(`CONFIG_LORA_LICHEN_BLE=y`) or MeshCore BLE
(`CONFIG_LORA_LICHEN_MESHCORE_BLE=y`). Meshtastic mode owns the BLE app surface
for this test.

## Firmware Boot Checks

1. Flash the image using the board-specific command and capture the full serial
   log from reset.
2. Confirm the log reports `Meshtastic app adapter ready`.
3. Confirm the log reports Meshtastic BLE initialization and advertising:
   `Meshtastic BLE advertising as`.
4. Confirm there is no native LICHEN BLE UART or MeshCore BLE advertising log in
   the same build.
5. Confirm startup does not claim Meshtastic RF interoperability. The app
   surface is local compatibility only.

Failure evidence: capture the first error line after boot, the Kconfig fragment
that selected the app surface, and the advertising payload if a BLE scanner can
read it.

## BLE Discovery

Use nRF Connect, LightBlue, the mobile app's device picker, or an equivalent BLE
scanner on each phone before starting the app sync:

| Attribute | Expected observation |
|-----------|----------------------|
| Service | `6ba1b218-15a8-461f-9fa8-5dcae273eafd` is advertised or discoverable after connection. |
| `ToRadio` | `f75c76d2-129e-4dad-a1dd-7866124401e7`, acknowledged write required; record whether write-without-response is also present. |
| `FromRadio` | `2c55e69e-4993-11ed-b878-0242ac120002`, read. |
| `FromNum` | `ed9da18c-a800-4f66-a670-aa7547e34453`, read, write, and notify. |
| Name | LICHEN-branded compatibility name; it must not present the device as Meshtastic RF firmware. |

Record whether the phone prompts for pairing or bonding. Meshtastic mode
currently preserves upstream app compatibility with plain characteristic
permissions; adding mandatory pairing is separate work and requires new Android
and iOS evidence.

## Android Script

Run this with the Android app version recorded in the Bead evidence.

1. Remove any old bond/cache entry for the test device in Android Bluetooth
   settings and in the Meshtastic app device list.
2. Start serial log capture on the firmware.
3. Open the Meshtastic Android app and scan for the LICHEN-compatible device.
4. Connect to the device and record the app state until sync completes or fails.
5. Confirm firmware logs `Meshtastic BLE client connected`.
6. Confirm the app writes `ToRadio.want_config_id = 69420` for config/static
   metadata. The raw encoded field is `18ac9e04`. Heartbeat `3a00` before or
   between sync stages is allowed and must not be required.
7. Confirm the app can drain `FromRadio` after `FromNum` notification or after
   its proactive read path. The drain ends when `FromRadio` returns a
   zero-length value.
8. Confirm stage 1 returns this node's identity, synthetic DeviceMetadata,
   region presets, channel, config, module config, and `config_complete_id =
   69420`, in that order. The terminal encoded field is `38ac9e04`.
   DeviceMetadata must show LICHEN-branded firmware, `PRIVATE_HW`, and
   unsupported modules excluded where Meshtastic defines exclusion bits.
   Region presets must show only the tested conservative default profile unless
   a broader region table has landed. Module config and admin responses must not
   show enabled telemetry, MQTT, serial, store-forward, remote hardware, TAK,
   mesh beacon, or other unimplemented modules.
9. Confirm the app writes `ToRadio.want_config_id = 69421` for node database
   sync. The raw encoded field is `18ad9e04`. The app receives self/peer node
   records followed by `config_complete_id = 69421`; the terminal encoded field
   is `38ad9e04`.
10. Watch for post-sync `ADMIN_APP` reads, especially `get_owner_request` and
    session-passkey setup. Current firmware may still report deterministic
    unsupported behavior until `project-LICHEN-t2hn.23` lands; record whether
    the Android app continues usable read-only operation or blocks on that
    response. If the app blocks, the Android smoke fails and the blocker belongs
    on `project-LICHEN-t2hn.23` or a child Bead. If the app remains usable but
    admin reads are unsupported, record only a partial read-only smoke result;
    full mobile smoke requires supported admin read behavior.
11. Verify the app UI shows a LICHEN-branded device identity and does not show
    unsupported Meshtastic RF claims as working native radio features.
12. Send a broadcast primary-channel text message from the app, up to 200 bytes
    of valid UTF-8.
13. Confirm firmware logs the Meshtastic text ingress path and that the message
    reaches the LICHEN local message submit contract. If current firmware
    returns unsupported because no provider is configured, record that evidence
    but mark the text-send checkpoint failed until `project-LICHEN-t2hn.7.2` or
    an equivalent submit path lands.
14. Inject or trigger a LICHEN incoming text/status event while connected.
15. Confirm the app observes a `FromNum` change, drains `FromRadio`, and displays
    the incoming `TEXT_MESSAGE_APP` or app-visible status/ACK/NAK.
16. Disconnect from the app and confirm firmware logs
    `Meshtastic BLE client disconnected`.
17. Reconnect and repeat one `FromRadio` drain. Stale queued values from the
    previous session must not appear.

Android failure evidence must include the app screen or logcat text, firmware
serial log, sync stage reached, last observed `FromNum`, and whether the app was
waiting for `FromRadio`, `config_complete_id`, or node database records.

## iOS Script

Run this with the iOS app version recorded in the Bead evidence.

1. Remove any old bond/cache entry for the test device in iOS Bluetooth settings
   and in the Meshtastic app device list.
2. Start serial log capture on the firmware.
3. Open the Meshtastic iOS app and scan for the LICHEN-compatible device.
4. Connect to the device and record the app state until sync completes or fails.
5. Confirm firmware logs `Meshtastic BLE client connected`.
6. Confirm the app writes `ToRadio.want_config_id = 69420` and accepts heartbeat
   tolerance around the handshake.
7. Confirm the app subscribes to or otherwise observes `FromNum`, then drains
   one complete protobuf value per `FromRadio` read until a zero-length read.
8. Confirm stage 1 returns identity, synthetic metadata, region presets,
   channel, config, module config, and `config_complete_id = 69420`, in that
   order. The raw sync request/terminal fields are `18ac9e04` and `38ac9e04`.
   DeviceMetadata must show LICHEN-branded firmware, `PRIVATE_HW`, and
   unsupported modules excluded where Meshtastic defines exclusion bits; module
   config and admin responses must not expose enabled unimplemented modules;
   region presets must match the tested default region/preset policy.
9. Confirm the app writes `ToRadio.want_config_id = 69421` and receives node
   database records followed by `config_complete_id = 69421`. The raw sync
   request/terminal fields are `18ad9e04` and `38ad9e04`.
10. Watch for post-sync `ADMIN_APP` reads, especially `get_owner_request` and
    session-passkey setup. Current firmware may still report deterministic
    unsupported behavior until `project-LICHEN-t2hn.23` lands; record whether
    the iOS app continues usable read-only operation or blocks on that response.
    If the app blocks, the iOS smoke fails and the blocker belongs on
    `project-LICHEN-t2hn.23` or a child Bead. If the app remains usable but
    admin reads are unsupported, record only a partial read-only smoke result;
    full mobile smoke requires supported admin read behavior.
11. Verify the app UI shows a LICHEN-branded device identity and does not claim
    Meshtastic RF interoperability.
12. Send a broadcast primary-channel text message from the app, up to 200 bytes
    of valid UTF-8.
13. Confirm firmware logs the Meshtastic text ingress path and that the message
    reaches the LICHEN local message submit contract. If current firmware
    returns unsupported because no provider is configured, record that evidence
    but mark the text-send checkpoint failed until `project-LICHEN-t2hn.7.2` or
    an equivalent submit path lands.
14. Inject or trigger a LICHEN incoming text/status event while connected.
15. Confirm the app observes `FromNum`, drains `FromRadio`, and displays the
    incoming text or app-visible status/ACK/NAK.
16. Disconnect from the app and confirm firmware logs
    `Meshtastic BLE client disconnected`.
17. Reconnect and verify no old queued values leak into the new session.

iOS failure evidence must include the app screen or sysdiagnose/client log when
available, firmware serial log, sync stage reached, last observed `FromNum`, and
whether the failure is discovery, connect, subscribe, read, write, or app-model
rendering.

## ATT And Framing Checks

Run these with a BLE tool capable of raw characteristic access on at least one
phone, and on both phones when the Bead is specifically about Android/iOS ATT
behavior:

| Action | Expected result |
|--------|-----------------|
| Write one raw serialized `ToRadio.heartbeat` value to `ToRadio`. | Accepted and may queue `queueStatus`; no sync state corruption. |
| Observe optional heartbeat queue status. | `FromRadio.queueStatus` may appear; it is local accounting only. |
| Write one raw `ToRadio.want_config_id = 69420` value. | Accepted as one protobuf value; response queue starts stage 1. |
| Write a value with serial/TCP StreamAPI prefix `0x94 0xc3`. | Rejected before adapter dispatch; BLE must not use stream framing. |
| Write a 505-byte `ToRadio` value. | Rejected deterministically before decode. |
| Read a queued `FromRadio` value near the 510-byte budget if the test harness can produce one. | One complete protobuf value is returned; no app-level chunking. |
| Read `FromNum`. | Four-byte little-endian queue counter. |

Every queued `FromRadio` value increments `FromNum` modulo `2^32`. A zero-length
`FromRadio` read means the queue is drained and must not increment `FromNum`.

If a board/phone/stack cannot carry the 504-byte write and 510-byte read budget
through ATT long operations, do not mark that board Meshtastic-compatible. File
or update the ATT evidence Bead with the negotiated MTU, phone OS, client/tool,
and exact failing operation.

## Unsupported And Safety Checks

Verify these app-visible operations fail explicitly or no-op deterministically
without mutating native LICHEN radio, routing, or security state:

| Operation | Expected result |
|-----------|-----------------|
| Admin config write or command | Explicit no-op/error; no LICHEN settings mutation. |
| Secondary channel creation or PSK update | Not created; no OSCORE/link key changes. |
| LoRa region/frequency/power write | Rejected or compatibility-local no-op; native radio policy unchanged. |
| Store-and-forward query | Empty or deterministic unsupported response. |
| Range test, traceroute, audio | Deterministic unsupported or empty response. |
| Unknown/unsupported portnum | No crash, no queue desync, deterministic status or empty response. |

The smoke run fails if an unsupported write returns success without a matching
Bead documenting compatibility-local storage and native_sim tests.

## Pass Criteria

A no-hardware preflight passes when the Twister command above passes with no
warnings. A full mobile smoke passes only when Android and iOS both record BLE
discovery, connect, config sync, node DB sync, supported post-sync
admin/session-passkey behavior, text reaching the LICHEN local message submit
contract, incoming text/status, disconnect cleanup, ATT long-operation success,
and failure-triage evidence. Blocking or unsupported post-sync admin behavior,
unsupported text send, or failed 504-byte `ToRadio`/510-byte `FromRadio` ATT
operations are evidence for follow-up Beads, not passing app-compatibility
results.

Any failure must create or update a Bead with:

- Exact firmware commit and build command.
- Android or iOS app version and phone OS/device.
- Failing app action or raw BLE operation.
- Expected and actual app text, protobuf field, or response bytes.
- Serial log excerpt from the same attempt.
- Whether the failure blocks documenting Meshtastic app compatibility for that
  board.

Useful firmware log strings include:

- `Meshtastic app adapter ready`
- `Meshtastic BLE advertising as`
- `Meshtastic BLE client connected`
- `Meshtastic FromNum notify enabled`
- `Meshtastic FromNum notify disabled`
- `Meshtastic ToRadio rejected:`
- `Meshtastic TEXT_MESSAGE_APP ingress unsupported:`
- `Meshtastic ToRadio dispatch failed:`
- `Meshtastic ToRadio dequeue failed:`
- `Meshtastic BLE client disconnected`
