# T1000-E + T-Echo LoRa Bring-up — Engineering Notes

Debug log for getting the LICHEN puck firmware to reliably exchange LoRa beacons
between a **Seeed T1000-E** (nRF52840 + **LR1110**) and a **LilyGo T-Echo**
(nRF52840 + **SX1262**). Captures what worked, what didn't, and why — so the
next person doesn't repeat the dead ends.

**Goal:** both devices show `message_received` on their LICHEN Native `if00`
port, proving they receive each other's 5-byte announce beacons.

**Status (as of this writing):** ✅ Demo works — both boards receive each other.
Firmware is resilient: **headless operation = 0 reboots**; the one remaining
intermittent freeze happens *only while a host holds the USB-CDC port open* and
is auto-recovered by the watchdog. See "Open items".

---

## Hardware / boot facts (verified)

| | T1000-E | T-Echo |
|---|---|---|
| MCU / radio | nRF52840 + LR1110 | nRF52840 + SX1262 |
| Bootloader | Adafruit UF2 @ 0xF4000, **no SoftDevice**, APP_START **0x1000** | Adafruit UF2 + SoftDevice S140, APP_START **0x26000** |
| MCUboot | @0x1000, slot0 @0xD000 | @0x26000, slot0 @0x32000 |
| CDC ports | if00 = LICHEN Native **+ console** (shared!), if02 = mcumgr SMP | if00 = LICHEN Native, if02 = console/log |
| Radio clock | **TCXO** (needs `set_tcxo_mode`) | TCXO on DIO3 (`dio3-tcxo-voltage`) |
| DFU port name after touch | `Seeed_Studio_T1000-E_…` | `LilyGo_T-Echo_v1_…` |

- Always use `/dev/serial/by-id/` paths, never `/dev/ttyACM*` (they reorder).
- Zephyr errno: `ETIMEDOUT = 116`, so "beacon TX failed: -116" = a TX timeout.

---

## Root causes found (the wins)

### 1. Flash scripts silently never flashed (the big one)
`flash-t1000e.sh` / `flash-t_echo.sh` run
`adafruit-nrfutil dfu serial --touch 1200`, which does the 1200-bps touch
**and then reopens the same port path**. But after the touch the device
re-enumerates under a *different* name (`LICHEN_Node…` → `Seeed_Studio…` /
`LilyGo…`), so nrfutil hits "No such file or directory", **writes zero bytes**,
and the script prints "Done." anyway. For a long time every "reflash" silently
failed — the board kept running the *previous* firmware.

**Working procedure (used throughout):**
1. Touch separately in Python (open at 1200 baud, DTR de-asserted, close).
2. `sleep 3`; find the *new* DFU port name.
3. `adafruit-nrfutil dfu serial --package X.zip -p <DFU_PORT> -b 115200 --singlebank` **without** `--touch`.
4. Success = transfer progress bars + `Device programmed.`

**Fallback when serial DFU wedges (happened on T-Echo):** UF2 drag-drop —
`uf2conv.py -c -b 0x26000 -f 0xADA52840 combined.bin -o x.uf2`, mount the
`TECHOBOOT` volume (`udisksctl mount -b /dev/sda`), `cp x.uf2 <mnt>/`, `sync`.

### 2. LR1110 "TX hang" = missing TCXO init
The T1000-E clocks the LR1110 from a TCXO, but `lr1110_lora_config()` never
called `lr1110_system_set_tcxo_mode()`. Consequence chain, proven by
instrumenting `lr1110_system_get_errors()`:
- After `calibrate`, errors = **0x0020 = HF_XOSC_START** (HF crystal never started).
- RF PLL can't lock → `set_tx()` returns **CMDERR** (`irq` bit 22, `0x00400000`).
- TXDONE never fires; the old `k_sem_take(10s)` waited on a DIO9 edge that never
  came, and — combined with back-to-back SPI right after `set_tx` — hard-froze
  the CPU (so even the 10s timeout never fired).

**Fix:** `lr1110_system_set_tcxo_mode(dev, ..._1_8V, 4096)` **before**
`lr1110_system_calibrate()`. Then `set_tx errors=0x0000`, `irq=0x4` (TXDONE),
`beacon seq=N` logs, no freeze.

### 3. Radio SPI @ 8 MHz intermittently wedges the nRF52840 SPIM
Lowering `spi-max-frequency` **8 MHz → 2 MHz** on both boards markedly reduced
the intermittent transfer-hang freezes.

### 4. Resilience: SoC watchdog
`wdt0` armed in `main()` (20 s), fed each main-loop iteration. Any radio-driver
lockup now auto-resets instead of hanging forever. Also a great live diagnostic:
count re-enumerations in `dmesg` to measure freeze rate.

### 5. `wait_busy()` had no timeout (both drivers)
`lr1110_hal.c` `wait_busy()` and `zephyr/drivers/lora/sx126x.c`
`SX126xWaitOnBusy()` spun forever if the radio BUSY pin stuck high. Added a
500 ms deadline + hard radio reset. (Necessary but not sufficient on its own.)

---

## Things that did NOT work / were wrong turns

- **Autosuspend was NOT the connectivity-loss cause.** Both devices read
  `runtime_status=active`. The T-Echo (`power/control=on`, never suspended)
  still went silent. Autosuspend *does* drop the T1000-E's deferred logs
  (making it *look* dead), but the watchdog later proved main was alive. USB
  autosuspend reverts to `auto` on every re-enumeration (needs a udev rule or
  `echo on | sudo tee …/power/control` to persist; sudo needs a password here).
- **`CONFIG_LOG_MODE_IMMEDIATE=y`** to catch the last log before a freeze:
  deadlocked USB enumeration (synchronous logging re-enters the USB stack during
  bring-up) → board wouldn't enumerate (`-110`), needed double-tap recovery.
  Don't use immediate logging with a USB-CDC console on these boards.
- **Disable-in-ISR / re-enable-after DIO9 storm fix**: did not stop the freeze
  (freeze wasn't a GPIO interrupt storm).
- **Converting TX (then RX) to SPI polling instead of the DIO9 interrupt**:
  good change (kept), but did **not** by itself stop the freeze.
- **TCXO voltage sweep**: swept all 8 supply voltages (1.6–3.3 V); **every one**
  gave the same `0x0020` HF_XOSC_START at calibration time. So the residual
  `0x0020` is a benign timing artifact (TCXO is up by `set_tx` time); voltage is
  not the lever, and increasing the TCXO startup timeout (328 → 4096 steps)
  didn't clear it either.
- **Reducing SPI poll frequency** (1 ms → 10/20 ms): did not reduce the
  port-open freeze (it isn't poll-volume driven).
- **Shrinking the deferred-log burst**: `CONFIG_LOG_BUFFER_SIZE` is already 1024;
  the port-open burst is small, so it isn't a volume problem.

---

## The remaining freeze — fully characterized

Controlled A/B test (measured via `dmesg` re-enumeration counts):
- **Headless (no USB port open): 0 reboots** over 60 s on both boards.
- **Host holding the USB-CDC port open: ~2–3 watchdog-recovered reboots/min.**

Mechanism: main blocks **forever inside a radio SPI transaction** (Zephyr's nRF
SPIM sync API waits `K_FOREVER` on DMA-done) when **USB-CDC EasyDMA contends
with the radio SPIM EasyDMA**. It only triggers while a host is actively
attached over USB. The work queue stays alive (1200-bps touch still works),
confirming a main-thread-only hang, not a full lockup.

**To eliminate (not just recover) — the next-mile plan:**
- Bound the radio SPI: async SPI (`spi_transceive_signal`) + `k_poll` timeout so
  a stuck transfer returns an error instead of blocking main; reset the SPIM on
  timeout.
- Pair with a heartbeat-fed watchdog (feeder thread + freshness check) for ~3 s
  recovery instead of 20 s.
- Investigate nRF52840 USB + SPIM EasyDMA bus-arbitration (buffer placement /
  known anomalies).

---

## Reference: known-good commands

```bash
# Reflash T1000-E (device running LICHEN):
python3 -c "import serial,time; s=serial.Serial(); s.port='/dev/serial/by-id/usb-LICHEN_Project_LICHEN_Node_891FA3226B7B0D14-if00'; s.baudrate=1200; s.dtr=False; s.open(); time.sleep(0.3); s.close()"
sleep 3
DFU=$(ls /dev/serial/by-id/*Seeed_Studio_T1000-E_*-if00)
adafruit-nrfutil dfu serial --package /tmp/t1000e_combined_dfu.zip -p "$DFU" -b 115200 --singlebank

# T-Echo UF2 fallback (serial DFU wedged):
python3 zephyr/scripts/build/uf2conv.py -c -b 0x26000 -f 0xADA52840 /tmp/t_echo_combined.bin -o /tmp/t_echo.uf2
udisksctl mount -b /dev/sda && cp /tmp/t_echo.uf2 /media/$USER/TECHOBOOT/ && sync

# Measure freeze rate (re-enumerations = watchdog resets):
dmesg | grep -c "1-1.6: new full-speed"   # T1000-E hub
```

Serial numbers seen this session: T1000-E `891FA3226B7B0D14`, T-Echo
`2BE0BCC87606D748` (USB hubs `1-1.6` and `1-1.7` respectively).

---

## Upstream integration (merge of `upstream/main`)

Merged `upstream/main` into `feat/t1000e` (commit `f19ae25`). Upstream's LR1110
rework did **not** fix the TX hang (no TCXO, still interrupt-based); it added
HAL error propagation (`LR1110_RETURN_ON_HAL_ERROR`), a beacon CRC-MIC, and a
native.c refactor (zcbor CBOR + test helpers + init mutex). Both sides were
needed. Conflicts resolved to keep our hardware-proven behavior (TCXO, SPI
polling, watchdog, NEXT USB stack, 2 MHz SPI) and adopt upstream's additions.

### Gotcha: T-Echo "bricked" after the merge (silently-disabled subsystem)
Symptom: T-Echo flashed clean (serial-DFU CRC-verified) but **never enumerated
USB** — dead, no reboot loop. The T1000-E ran the merged firmware fine.

Root cause: upstream's native.c now uses **zcbor**, and its Kconfig gained
`depends on ZCBOR`. The T1000-E enables `CONFIG_ZCBOR` (for mcumgr); the T-Echo
did not. So `LICHEN_NATIVE` **silently dropped to `n`**, `native.c` (which does
USB-CDC enumeration via `SYS_INIT`) wasn't compiled, and USB never came up.

Fingerprints of a silently-disabled Kconfig subsystem:
- build warning `LICHEN_NATIVE ... was assigned the value 'y' but got 'n'`
- `No SOURCES given to Zephyr library: lichen_native`
- the app image is noticeably **smaller** (~8 KB here)

Fix: `CONFIG_ZCBOR=y` in `t_echo_nrf52840.conf`. Both boards then run the merged
firmware and exchange 9-byte MIC beacons.

Isolation method that nailed it: flashing the **known-good pre-merge build**
booted instantly → proved hardware/bootloader were fine and the fault was in the
merged firmware, not the (heavily re-flashed) T-Echo bootloader.

---

## USB-monitoring watchdog reboots — root cause & fix (USB-CDC-NEXT stack)

**Symptom:** the T1000-E watchdog-resets ~5–8×/90s *only while a host holds the
USB-CDC port open and reads continuously*. Headless = 0 reboots. Confirmed
WATCHDOG resets (`RESETREAS`=DOG); main/CPU stalls >4 s.

**A/B that nailed it:** swapping *only* the USB stack —
`CONFIG_USB_DEVICE_STACK_NEXT` → old `CONFIG_USB_DEVICE_STACK` — took reboots
from 5–8/90s to **0/90s**, both builds fully functional (TX+RX confirmed via the
T-Echo receiving the T1000-E's beacons). So the fault is in the **USB-CDC
`device_next` stack under sustained host reads**, not the radio.

**Ruled out** (none stopped the reboots): bounded async SPI + SPIM STOP abort;
**non-DMA SPI** (rules out SPIM↔USB EasyDMA bus contention); native-TX disabled;
**timer-ISR** watchdog feeder (rules out feeder-thread starvation); progress
bumps in every SPI wait + poll loop; SPI 8→2→1 MHz. The timer *ISR* being
starved too suggests a fault-that-spins or a hard CPU stall, not a thread block.

**Fix shipped:** T1000-E uses the old USB stack. `native.c` was refactored so
`buzz_n()` and the 1200-bps DFU-touch handler are gated by board features
(`CONFIG_LICHEN_NATIVE_BUZZER`, nRF+`UART_LINE_CTRL`) instead of the USB stack,
so the old stack keeps the buzzer and headless reflash. The **T-Echo stays on
NEXT** (the old stack reportedly fails on T-Echo+MCUboot) and relies on the
heartbeat watchdog's ~4 s auto-recovery.

**Couldn't capture the stall location:** the GPREGRET2 retention marker reads 0
at boot — the MCUboot chain clears it. A retention path that survives MCUboot
(reserved top-of-RAM or `CONFIG_RETENTION`) or an RTT/debugger probe is needed
to get the stall PC.

**Future work (bd `Investigate USB-CDC device_next…`):** fix the NEXT-stack
stall so both boards can share one modern stack. Leads: is it a fault-vs-lock in
`usbd_cdc_acm.c` under sustained bulk-IN; reproduce with the upstream Zephyr
`device_next` CDC-ACM sample; inspect `CDC_ACM_LOCK`/`tx_fifo_work`/`irq_cb_work`
interplay when the host reads fast.

---

## Round 3: US915 move + three-node exchange (Heltec V3 gateway) — Jul 1-2

**Goal reached:** all three nodes (T1000-E, T-Echo, Heltec V3 gateway) send and
receive LICHEN packets at **915 MHz** (US915; 868 was the EU default — both
`LORA_FREQ_HZ` defines moved, commit `2a1d102`). Gateway logs both pucks:
`lichen_l2: neighbor beacon epoch=N seq=M rssi=-21/-52 snr=8/9`.

### The Heltec deaf-radio chain (commit `929975f`)

Bringing the merged L2 gateway up on the Heltec surfaced **four stacked bugs**;
fixing each unmasked the next. Worth remembering as a debugging sequence:

1. **No MIC method → every L2 TX failed `-22`** (`2a1d102`): no AES-CCM link key
   and CRC32 fallback compiled out → `lichen_link_tx()` had no way to build any
    frame. (Signatures now mandatory; no insecure CRC32 option.)
2. **TX/RX modem arbitration** (`lora_l2.c`): the sx12xx `modem_acquire()` is
   non-blocking; the RX thread re-arms `lora_recv()` back-to-back so TX almost
   never wins, and RX logged the collision `-EBUSY` as a hardware error with a
   1 s deaf backoff. Fix: `tx_pending` flag RX yields to; `-EBUSY` treated as
   expected on both sides.
3. **TX-done sysworkq self-deadlock**: with `NET_TC_TX_COUNT=0`, boot ND/MLD
   sends run **on the system workqueue**, where `lora_send()` blocks waiting for
   a TX-done the sx126x driver delivers **via a work item on that same queue**
   → guaranteed `-11` after 2× airtime. Fix: `CONFIG_NET_TC_TX_COUNT=1`.
4. **RX side never configured** (`lora_l2.c`): Zephyr `lora_config(.tx=true)`
   only calls `SetTxConfig`; `SetRxConfig` was never invoked — the radio
   listened with unprogrammed modulation params. Fix: two-pass config (RX pass,
   then TX pass).
5. **The root deafness — ESP32-S3 SPI reads corrupt at 16 MHz** (board DTS):
   the LoRa SPI pins route through the GPIO matrix (not FSPI IOMUX); MISO read
   timing degrades above ~8 MHz while writes stay clean. Signature: **perfectly
   asymmetric radio — TX on-air fine (T-Echo decoded it at rssi −20), RX stone
   deaf**. Fix: `spi-max-frequency` 16 MHz → 2 MHz (RadioLib convention).
   Verified: RX 0 → 18 frames/48 s. *Any ESP32 board with TX-works/RX-deaf:
   check the SPI clock first.*

**Isolation method that found #5:** flash the *puck* app (known-good raw-LoRa
code on two nRF boards) onto the Heltec. Same code, same driver, deaf on ESP32
→ platform-level, not protocol-level. Beware two contaminations when doing
this: the puck defaults to 60 s beacons (`LICHEN_PUCK_BEACON_INTERVAL_MS`), and
with `NETWORKING=y` the L2 RX thread contends with the raw main loop for the
half-duplex modem (heltec puck conf now sets 5 s + `NETWORKING=n`; the
**T1000-E puck still has both L2 and raw RX enabled** — same latent contention,
untested because its USB is wedged; consider `NETWORKING=n` there too).

### Beacon recognition (`7ce1074`)

Puck beacons (9 B: `[len][LLSec=0x00][epoch][seq_hi][seq_lo][CRC32 LE]`) reach
the gateway but carry no SCHC/IPv6 payload, so `lichen_link_rx()` rejects them
with per-frame WRN spam. The L2 input failure branch now shape-checks, verifies
the CRC32, and logs `neighbor beacon` at INF. CRC32 = error detection only;
beacons are observational.

### Operational lessons (host-side)

- **Watchdog reboot on port-open — fixed** (`2a1d102`): old-stack CDC
  `uart_poll_out()` blocks when a host attaches (discards when detached); native
  TX runs on the main loop; heartbeat went stale → reset at ~8 s. `native.c` now
  pumps `lichen_radio_progress()` around each byte. Verified 45 s monitored
  read, zero reboots.
- **T1000-E USB `-110` wedge** (bd `lora_ipv6_mesh-1jqj`): repeated host
  open/close/DTR churn (especially overlapping readers) wedges the nRF USB into
  a descriptor-read `-110` loop; only a replug recovers. **The firmware keeps
  running** — its radio beacons throughout. Idle = stable 8–9 h.
- Beacon collision capture: both pucks at ~5.43 s period drift in and out of
  overlapping airtime; when aligned, the gateway only decodes the stronger
  (−21 dBm) — the weaker (−52 dBm) vanishes for minutes. Expected without CSMA.
- ESP32 auto-reset: *any* CP2102 port open resets the Heltec (RTS→EN). Every
  monitor session starts at boot. Use `dtr=False rts=False` before open and a
  deliberate RTS pulse for run-mode; sloppy opens can land in download mode.
- Test-harness hygiene: orphaned background serial readers (heredoc + outer
  `timeout`) hold the port, cause "multiple access" EIO, and can wedge the
  T1000-E USB. Use `timeout -s KILL` around a script file, not a heredoc.
