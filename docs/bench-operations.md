<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Hardware Bench Operations

Operational reference for the physical LICHEN test bench: device inventory,
port-safety rules, flash/OTA procedures, over-the-air verification, and the
findings that shaped current bench practice.

Detailed rationale for each finding lives in the referenced beads
(`bd show <id>`). This document is the how-to; the beads are the why.

---

## 1. Device inventory

Three nodes plus two debug tools. **Always address serial ports by their
`/dev/serial/by-id/` path, never `/dev/ttyACM*`/`/dev/ttyUSB*`** — the ACM/USB
numbers reshuffle across replug and reboot.

| Device | MCU + radio | Role | EUI-64 | USB serial (FICR/DEVICEID) |
|--------|-------------|------|--------|----------------------------|
| **T-Echo** (LilyGo) | nRF52840 + SX1262 | Puck (L2/CoAP) | `7a7ff09dc86c2c10` | `2BE0BCC87606D748` |
| **T1000-E** (Seeed) | nRF52840 + LR1110 | Puck (second radio) | `8a1a2c4b93812cab` | `891FA3226B7B0D14` |
| **Heltec V3** | ESP32-S3 + SX1262 | Gateway (CoAP server) | `ee452f74419cf281` | CP2102 bridge |
| PPK2 | Nordic Power Profiler | Current profiling | — | `Nordic_..._PPK2_C0EAA2789C9B` |
| WCH-Link | — | SWD debug | — | `wch.cn_WCH-Link_94FC8F0619D9` |

### EUI-64 derivation

A LICHEN node's EUI-64 is `SHA-256("LICHEN-EUI64-v1" || hwid)[0:8]`, then byte 0
gets `|0x02` (U/L = locally administered) and `&0xFE` (I/G = unicast). On nRF the
`hwid` is the FICR DEVICEID, printed verbatim as the USB serial. So any nRF
node's EUI is derivable from its by-id name:

```python
import hashlib
h = bytearray(hashlib.sha256(b"LICHEN-EUI64-v1" + bytes.fromhex(serial))[:8])
h[0] = (h[0] | 0x02) & 0xFE   # U/L set, I/G cleared
eui = bytes(h).hex()
```

The gateway's EUI is read from its boot log (`link-local ...ec45:2f74:419c:f281`).

### CDC interface map (differs per board — verify from the built DTS)

| Board | native/log port | SMP (mcumgr) | notes |
|-------|-----------------|--------------|-------|
| **T-Echo** | `if02` = console (log-only) | `if04` | `if00` = native-uart |
| **T1000-E** | `if00` = native (**wedge trigger**) | `if02` | LR1110 |

---

## 2. Port-safety rules (read before opening any port)

These are hard-won; violating them wedges a device or corrupts a flash.

- **NEVER open the T1000-E `if00` (native) port.** It is the proven trigger for
  the USB `-110` descriptor-read wedge (bd `1jqj`). Use `if02` (SMP) only.
- **NEVER write to the T-Echo `if02` console.** It is log-only with no input
  consumer; a write fills the CDC-OUT buffer and blocks the writer forever
  (`do_select`, S-state). Read-only probes only, with a `timeout` wrapper.
- **NEVER open a LICHEN native CDC port at 1200 baud** except as a deliberate
  DFU touch — 1200 baud reboots nRF boards into the UF2 bootloader.
- Heltec V3 gateway console now on UART1 (GPIO21/22); CP2102 open is non-destructive.
- **Never pipe a flasher through `head`/`tail`** — the `SIGPIPE` when the reader
  closes aborts the transfer mid-write.
- Opening the T1000-E `if02` SMP port is safe; it can wedge (CDC write timeout)
  only if a reset drops mid-SMP-transaction — recover with a DFU touch + reflash.

---

## 3. Build

Environment (use the SDK and Python environment configured by your Zephyr
workspace):

```bash
export ZEPHYR_SDK_INSTALL_DIR=/path/to/zephyr-sdk-0.16.8
# Activate the workspace virtual environment if west is not already on PATH.
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)   # build-epoch policy requires this
```

`ZEPHYR_SDK_INSTALL_DIR` may be omitted when the SDK is registered with CMake
and auto-detected by Zephyr.

- **T-Echo puck** (MCUboot + signed app): `./build-t_echo.sh`
  → `build_mcuboot_t_echo/zephyr/zephyr.bin` + `build_t_echo_puck/zephyr/zephyr.slot0.signed.bin`
- **T1000-E puck**: `./build-t1000e.sh` → `build_t1000e_puck/zephyr/zephyr.slot0.signed.bin`
- **Heltec gateway (WiFi 6LBR)**: `west build -b heltec_wifi_lora32_v3/esp32s3/procpu lichen/apps/gateway -d build_gw`. Verify prefix delegation, RPL root RA, CoAP bridging to upstream, /status backhaul field. See §8 for full test procedure.

---

## 4. Flash / OTA procedures

### T-Echo — UF2 mass-storage (reliable)

The signed app has no built-in bootloader, so combine MCUboot@0x26000 +
slot0@0x32000 into one image, then flash via the Adafruit UF2 bootloader:

```bash
# combine (pad mcuboot to 0xC000, then append slot0)
python3 - <<'EOF'
import struct
mcuboot = open("build_mcuboot_t_echo/zephyr/zephyr.bin","rb").read()
slot0   = open("build_t_echo_puck/zephyr/zephyr.slot0.signed.bin","rb").read()
combined = mcuboot + b"\xff"*(0xC000 - len(mcuboot)) + slot0
sp, rv = struct.unpack("<II", mcuboot[0:8])           # reset-vector sanity
assert 0x20000000 <= sp <= 0x20040000 and 0x26000 <= rv <= 0x32000
open("/tmp/t_echo_combined.bin","wb").write(combined)
EOF
python3 <path>/uf2conv.py /tmp/t_echo_combined.bin -c -f 0xADA52840 -b 0x26000 \
    -o /tmp/t_echo_combined.uf2

# enter bootloader: 1200-baud DFU touch on if00
python3 -c "import serial; serial.Serial('/dev/serial/by-id/usb-LICHEN_Project_LICHEN_Node_2BE0BCC87606D748-if00',1200,timeout=1).close()"
# mount TECHOBOOT (udisksctl mount -b /dev/sdX if it does not auto-mount), then:
cp /tmp/t_echo_combined.uf2 /media/$USER/TECHOBOOT/ && sync
```

`uf2conv.py` lives under the meshtastic firmware tree
(`.../firmware/bin/uf2conv.py`).

### T1000-E — SMP OTA (no bootloader button needed after first flash)

Sign with `--pad --confirm` so the swap trailer ships inside the image
(`smp-flash.py` does not send an SMP test/confirm command):

```bash
TMP=$(mktemp); dd if=build_t1000e_puck/zephyr/zephyr.bin bs=512 skip=1 of=$TMP
python3 bootloader/mcuboot/scripts/imgtool.py sign --header-size 0x200 --align 4 \
    --version 1.0.2+0 --slot-size 0x59000 --pad-header --pad --confirm $TMP /tmp/t1000e_ota.bin
python3 smp-flash.py /dev/serial/by-id/usb-LICHEN_Project_LICHEN_Node_891FA3226B7B0D14-if02 /tmp/t1000e_ota.bin
```

MCUboot copies the slot on the next boot (~19 s). Verify with an SMP image-list;
the previous image stays in slot 1, SMP-revertible.

### Heltec gateway — esptool

```bash
west flash -d build_gw --esp-device \
  /dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0
```

---

## 5. Over-the-air verification

Watch the **T-Echo `if02` console read-only** for the round trip. Success is a
`lichen_puck: CoAP 2.05 response, <N> B payload` line whose CBOR `uptime` field
**advances** between responses (proving live responses, not a cached duplicate).

**The reboot coin-flip (bd `3uhb`).** Each node picks a *random* epoch in
[128,255] at boot. A peer remembers this node's last `(epoch, seqnum)` in its
replay window, so if the fresh epoch is *lower* than the remembered one, every
frame after the reboot is rejected as a replay (`-120`) — a ~50 % coin flip per
reboot, per peer, and it is **silent on the sender** (the receiver just drops).
Any single-node reboot or reflash can trigger one-way deafness.

- **Fix (validated, enabled on the bench):** `CONFIG_LICHEN_LINK_EPOCH_PERSIST`
  persists the epoch and advances it +1 per boot (monotonic; half-space
  arithmetic handles the 255→0 wrap). Enabled in the T-Echo puck and gateway
  confs. Hardware-validated 2026-07-17: 8/8 T-Echo reboots produced **zero**
  gateway replay rejections (vs ~4/8 expected without it).
- **Manual recovery (older firmware without the fix):** reset *both* endpoints
  within ~2 s so their fresh windows adopt each other's new epochs on first
  exchange. The verified sequence: bounce the gateway CP2102 port, then
  SMP-reset the puck within ~2 s. This restored a stuck link to 9/13 immediately.

---

## 6. Dev provisioning & multi-peer (INSECURE, bench only)

`CONFIG_LICHEN_L2_DEV_PROVISIONING` gives every node a key **derived per-node**
as `SHA-256(dev_seed || EUI-64)` (bd `wp4o`). This is still insecure (the seed is
public) but each node has a *distinct* keypair, so signatures attribute frames to
the correct sender.

> **History:** the original dev seed was *shared* by all nodes. Because LICHEN
> frames omit sender identity, every node's signature verified as "the" pinned
> peer, collapsing all transmitters into one replay window per receiver — and the
> highest random epoch permanently starved the rest. That masqueraded as RF
> trouble for hours before per-node keys fixed it.

`CONFIG_LICHEN_L2_DEV_PEER_EUI64` is a **comma-separated** peer list. But:

- **Multi-peer pinning on nRF52840 is fixed** (bd `shbh`, validated). In *secure*
  builds the RX path Schnorr-verifies every frame against *all* pinned peers
  (constant-time). On the 64 MHz nRF52840 that made a second peer cost N verifies
  of radio-deafness per frame — round trips dropped from ~43 % to 0 %. The
  **dev-mode early-exit** (gated on dev provisioning, where the timing-side-channel
  defense is moot) stops at the first match. Hardware-validated 2026-07-17: two
  pinned peers now sustain 6/9 (67 %) round trips vs 0/24 before. List the most
  frequent responder (the gateway) first so its frames exit on iteration 1.
- **Three active nodes exceed the SF10 ALOHA airtime budget.** With the deaf
  T1000-E (bd `qpc0`) retransmitting every cycle, offered load approaches the
  duty limit and collisions climb. Keep the bench to two active nodes unless
  deliberately testing contention.

---

## 7. Soak methodology & results

**Method:** capture a timestamped, read-only log from the T-Echo `if02` console
with a serial terminal that has a read timeout. Tally
`GET /status sent` vs `CoAP 2.05 response` vs `no callback received`, plus
`replay`/`auth`/reconnect counters, one summary line per 10 min. Never touches
the gateway or T1000-E ports (opening the gateway port would reboot it and
reroll its epoch). Record the start/end timestamps, firmware revisions, node
set, radio settings, and counter totals with each run so the result is
reproducible without relying on a session-local script.

**2026-07-17 result (per-node keys, single-peer pinning, T1000-E free-running):**
steady **73–74 % CoAP round trips over 6+ hours, replay=0, reconnects=0**, with
timeout and auth-noise counts growing strictly *linearly* with GET count. That
last point matters: the ~26 % loss is **airtime contention** (SF10 ALOHA
collisions + the deaf T1000-E's traffic), not a firmware defect or a slow leak.
Recurring `LoRa TX failed (-16 / modem acquire timed out)` blips are the same
contention signature, absorbed by CoAP retransmit.

**What a longer soak will and will not show.** The metrics converge within the
first ~30 min and stay flat, so additional hours mainly re-confirm stability. In
12 h the interesting wrap events are *not* reached: at ~4 GETs/min the 16-bit
`tx_seq` wrap (65 536 frames) is ~11 days away, and the LRU `access_counter`
wrap is far beyond that. Watchdog-recovery correctness (bd `gald`) is also *not*
exercised unless a crash occurs — a clean soak proves stability but leaves the
recovery path untested. Plan wrap/recovery coverage as targeted tests, not as a
longer soak.

## 8. WiFi backhaul 6LBR validation (Heltec V3)

**Build/Flash:** `west build -b heltec_wifi_lora32_v3/esp32s3/procpu lichen/apps/gateway -d build_gw_6lbr`; flash via esptool. Configure WiFi STA in overlay or Kconfig (SSID, PSK, upstream prefix delegation via RA).

**Unit (prefix delegation):** Rust lichen-gateway tests in `rust/lichen-gateway/tests/` for TUN prefix handling, RPL root RA/DAO. Match test/vectors for SCHC-compressed IPv6.

**Integration (mesh-sim/Renode):** Extend `lichen/tests/meshcore_gateway_adapter/` or Renode sim with WiFi emulation; verify mesh CoAP reaches upstream IPv6, status reports backhaul/prefix.

**Hardware test procedure:**
1. Connect Heltec V3 to WiFi AP with internet (verify log: "WiFi connected, prefix fd00::/64 delegated").
2. Join T1000-E/T-Echo puck to DODAG (RPL root on gateway).
3. From puck: CoAP GET to external host via gateway (bridging works if response received).
4. Query /status from local client: confirm RPL root, backhaul active, prefix in response.
5. Interop: Rust `lichend` receives forwarded packets, /status reflects WiFi metrics.
6. Verify no prefix leakage, correct 6LoRH source routing for downward traffic.

Update `build-t1000e.sh` pattern to `./build-gateway-heltec.sh` if added. Close when all pass + CI green. (See beads sl32.* for details.)
