<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Firmware Board Capability Matrix

This matrix records the no-hardware board-support baseline for LICHEN firmware
work. It is a planning and partner-handoff document, not a statement that every
listed peripheral has been physically validated.

For the Muzi Works family, the current first-party target is specifically
`r1_neo_nrf52840` / Muzi Works R1 Neo. The original non-Neo R1, any SH1107
display variant, and any LR1121 radio variant are not part of the MVP unless a
separate board/driver task adds explicit devicetree, Kconfig, and build/test
evidence.

The HAL capability boundary is defined by `lichen_hal_capability` in
`lichen/subsys/lichen/hal/include/lichen/hal.h`. Board ports should advertise
capabilities through Kconfig and devicetree instead of app code matching on
board names.

## Capability States

| State | Meaning |
|-------|---------|
| `enabled` | The board or app overlay enables the peripheral for normal builds. |
| `modeled` | Devicetree or Kconfig describes the peripheral, but it is disabled until a focused bring-up task validates it. |
| `external` | Requires wiring or an attached module, not a built-in board feature. |
| `none` | No known on-board capability in the current repo evidence. |
| `unknown` | Hardware docs or board files are insufficient; do not claim support yet. |

## Reference Profiles

These are the four firmware profiles LICHEN should own first. They cover the
major product shapes without expanding the core team into every Meshtastic
variant.

| Profile | Reference target | Why this target | No-hardware status | Owner |
|---------|------------------|-----------------|--------------------|-------|
| Display + buttons + GNSS | LilyGO T-Echo (`t_echo/nrf52840`) | nRF52840, SX1262, USB, BLE-class MCU, user button, GDEW0154M10 e-ink hardware, L76K GPS UART model, PCF8563 RTC. | Board DTS exists. LoRa is enabled by app overlays; GPS UART is modeled but disabled pending focused validation; display bus is present but the e-ink child node still needs a bring-up overlay. | LICHEN reference |
| Display + buttons, no GNSS | Heltec WiFi LoRa 32 V3 (`heltec_wifi_lora32_v3_esp32s3_procpu`) | Cheap ESP32-S3 + SX1262 + SSD1306 OLED + PRG button target for the common screen-and-button class. | Board DTS exists. LoRa is modeled/enabled by overlays; OLED is modeled but disabled pending display bring-up. | LICHEN reference |
| Headless/module | RAK4631 (`rak4631/nrf52840`) with Muzi R1 Neo as the first custom sibling | nRF52840 + SX1262, USB/BLE-class local transport, comfortable memory, and minimal UI. R1 Neo adds project-owned board data. | RAK4631 uses upstream board support plus LICHEN overlays. R1 Neo DTS exists but radio reset, bootloader, GNSS, and battery paths need hardware validation. | LICHEN reference |
| Gateway/bridge | `native_sim`, `qemu_x86`, RAK4631 serial bridge, and nRF52840 DK BLE shell | Keeps local-client, gateway, simulator, and CI work unblocked without requiring production handheld hardware. | `native_sim` and `qemu_x86` exercise software paths; RAK4631 covers serial-to-LoRa bridge development; nRF52840 DK currently builds as a BLE/CoAP shell with no LoRa radio. | LICHEN reference |

## Target Matrix

| Target family / board | MCU / memory class | Radio | Display | Inputs | GNSS / time source | PMIC / battery | Local interfaces | Storage | Zephyr status in repo | Ownership |
|-----------------------|--------------------|-------|---------|--------|--------------------|----------------|------------------|---------|-----------------------|-----------|
| LilyGO T-Echo | nRF52840, 256 KB RAM / 1 MB flash | SX1262 modeled; enabled by overlays | GDEW0154M10 e-ink; SPI2 + child node in DTS (production ready, driver pending full validation) | One user button, LEDs | L76K GPS UART modeled, disabled pending TDMA sync; PCF8563 RTC enabled | Battery via ADC (path added in follow-up) | Native USB; BLE local transport is the intended nRF52840 app-compat path | Internal flash partitions with MCUboot+SMP OTA | First-party board under `lichen/boards/lilygo/t_echo`; puck/gateway configs, Renode/HW tests updated for scale | LICHEN reference for display+buttons+GNSS (production ready) |
| Heltec WiFi LoRa 32 V3 | ESP32-S3FN8, 8 MB flash class | SX1262 enabled in board/app path | SSD1306 OLED modeled, disabled | PRG button, LED | No on-board GNSS in repo evidence; uptime or mesh time | none | UART console; ESP32 BLE HCI modeled, BLE app path still needs validation | Internal flash partitions | First-party board under `lichen/boards/heltec/heltec_wifi_lora32_v3`; puck and gateway configs exist | LICHEN reference for display+buttons without GNSS |
| LilyGO T-Deck | ESP32-S3-WROOM-N16R8, 16 MB flash / 8 MB PSRAM | SX1262 enabled in board/app path | ST7789 modeled, disabled | PRG button; keyboard/trackball class not yet modeled in HAL | No GNSS in current DTS; uptime or mesh time | none | UART console; ESP32 BLE HCI modeled, BLE app path still needs validation | SD slot modeled, disabled; internal flash partitions | First-party board under `lichen/boards/lilygo/t_deck`; puck and gateway configs exist | LICHEN staged rich-handheld target after shared-SPI display/input validation |
| RAK4631 WisBlock | nRF52840, 256 KB RAM / 1 MB flash | SX1262 via upstream board and LICHEN overlay | none by default | Carrier-dependent buttons/LEDs | none by default; uptime or mesh time | Carrier-dependent | Native USB; BLE local transport target | QSPI/storage depends on carrier | Upstream Zephyr board with LICHEN puck overlay | LICHEN headless/module reference and partner template |
| Muzi Works R1 Neo | nRF52840, 256 KB RAM / 1 MB flash | SX1262 modeled, disabled by board DTS and enabled by overlays | none | One user button, LEDs | GNSS pins known but UART disabled pending hardware validation; RX8130CE RTC bus modeled | ADC and GPIO power holds exist; no `battery0`/`pmic0` telemetry node, and gateway HAL battery/PMIC capabilities are disabled | Native USB CDC; BLE-class MCU | Internal flash partitions, UF2-style layout modeled | First-party board under `lichen/boards/muzi/r1_neo`; hardware validation Beads remain blocked | LICHEN custom headless target, but not closure evidence until physical validation |
| ELECROW ThinkNode M6 | nRF52840 | LoRa/GPS chip unknown (check schematic for SX1262/LR1110); solar 6W, 7000mAh | unknown | unknown | unknown | I2C/ADC for battery? | USB/BLE | unknown | unknown | Blocked by hardware identification (project-LICHEN-1pav); partner target |
| Seeed SenseCAP T1000-E | nRF52840, 256 KB RAM / 1 MB flash | LR1110 modeled in board DTS and enabled by puck/gateway overlays; driver/hardware validation still pending | none | Board-specific controls not modeled as general HAL buttons | AG3335 GNSS modeled in board DTS and enabled by puck/gateway overlays; GNSS behavior still needs validation | Battery/charger not modeled in current DTS | Native USB CDC; BLE-class MCU | Internal flash partitions, UF2-style layout modeled | First-party board under `lichen/boards/seeed/t1000_e`; puck and gateway configs exist | LICHEN advanced tracker, gated by LR1110 and GNSS bring-up |
| STM32WL Nucleo / Wio-E5 / RAK3172 class | STM32WL55 constrained baseline, 64 KB RAM / 256 KB flash | Integrated Sub-GHz radio | none | Board/carrier-dependent | none by default; uptime or external time | none by default | UART/ST-LINK or carrier serial; no BLE hardware | Internal flash | `nucleo_wl55jc` configs exist; project memory budget was validated for Nucleo. Wio-E5/RAK3172 are family targets, not first-party board ports here | LICHEN constrained baseline on Nucleo; partner-owned scale-out to modules |
| TTGO LoRa32 / T-Beam v1 / Heltec V2 class | ESP32, older flash/RAM class | SX1276/78 | OLED on common variants | Buttons vary by board | T-Beam v1 class may have GNSS; board-specific validation required | Battery/PMIC varies | UART; ESP32 BLE path not selected for MVP | Internal flash | TTGO LoRa32 overlay exists; classic ESP32 family listed in top-level targets | Partner-owned long tail after SX127x path is stable |
| T-Beam Supreme | ESP32-S3 class | SX1262 expected | N/A (BLOCKED) | N/A | BLOCKED: no canonical Zephyr board (lichen/boards or upstream); use heltec_wifi_lora32_v3/esp32s3/procpu proxy. Evidence in project-LICHEN-w8rd. | N/A | N/A | N/A | Classified BLOCKED per w8rd resolution; puck fragments updated with explicit BLOCKED note. |
| Seeed XIAO ESP32-S3 + Wio-SX1262 | ESP32-S3 class | SX1262 via bridge fragment | N/A (BLOCKED) | N/A | BLOCKED: no canonical composite board/shield mapping. xiao_s3_wio_sx1262 fragment retired per project-LICHEN-2u26.10. Use heltec_wifi_lora32_v3/esp32s3/procpu proxy. | N/A | N/A | N/A | Classified FAIL (bridge audit m5m1.8); bridge fragment updated with explicit retirement note. |
| RAK11310 / RP2040 + SX126x | RP2040, 264 KB RAM / external flash class | SX1262 expected | Carrier-dependent | Carrier-dependent | none by default | Carrier-dependent | USB serial; no BLE on RP2040 | External flash | Top-level target family only; no concrete local board/overlay found | Partner-owned future target |
| Muzi Works original/non-Neo R1 variants | unknown until a separate board fact Bead exists | SX1262, LR1121, or other variant not confirmed in repo evidence | SH1107 or other display variants are not modeled | unknown | unknown | unknown | unknown | unknown | No first-party Zephyr board target; do not alias to `r1_neo_nrf52840` | Unsupported for MVP; add separate board/driver Beads before claiming display or LR1121 support |
| Linux gateway / simulator | Host-class | Simulated, external SPI, or serial-attached LoRa | Host UI, not firmware HAL | Host input, not firmware HAL | Host time, gpsd, or upstream time source | Host power, not firmware HAL | UDP/TUN/TAP, serial, TCP, BLE host tools | Host filesystem | Rust gateway/simulator, Zephyr `native_sim`/`qemu_x86`, RAK4631 serial bridge docs, and nRF52840 DK BLE shell cover no-hardware validation | LICHEN infrastructure reference |

## Partner-Owned Long Tail

The long tail is valuable, but it should scale through repeatable board intake
instead of core protocol work:

- Vendor variants in the same family as the references: Heltec V2/V3/T114,
  Wireless Tracker, Vision Master, T-Beam revisions, LoRa32 revisions, WisBlock
  carriers, and region-specific radio modules. Bridge-zephyr/boards/ fragments
    for     heltec_vision_master_e213, heltec_vision_master_e290,
    heltec_wireless_tracker, station_g2 and similar retired (STALE markers,
    no canonical Zephyr target) per project-LICHEN-2u26.* (see individual
    sub-beads like 2u26.2 for e213, 2u26.4 for heltec_wireless_tracker, 2u26.9 for station_g2).

- RP2040 + SX126x boards such as RAK11310 until a concrete Zephyr board file,
  pin map, and storage layout are present in the repo.
- STM32WL modules beyond Nucleo-WL55JC until memory gates, serial transport,
  and bootloader constraints are rechecked per module.
- SX127x ESP32 boards after the SX126x path is stable, because the radio family
  needs a separate receive/transmit validation path.
- Any board whose display, keyboard, GNSS, PMIC, charger, fuel gauge, or flash
  device is not represented by a devicetree node or HAL capability yet.
- Muzi Works original/non-Neo R1 variants, including possible SH1107 display or
  LR1121 radio variants, until separate board files and driver work prove the
  exact hardware boundary.

Partner ports should contribute board files, overlays, and at least one
board-agnostic build/test result before requesting ownership transfer into the
LICHEN reference set.

## Implementation Notes

- `CONFIG_LICHEN_HAS_*` symbols should only be enabled when devicetree exposes
  the matching device or alias and the app is ready to use it.
- Meshtastic-compatible app metadata must stay synthetic. Do not report
  board-specific Meshtastic hardware enum values for T-Beam, Heltec, RAK, or
  similar targets; use LICHEN-branded private hardware identity.
- STM32WL remains the constrained baseline. Keep Zephyr builds in the budget
  before adding optional app-compat, display, or storage code.
- BLE local-client work should start on nRF52840 targets. ESP32-S3 BLE remains
  possible, but should be treated as a separate validation task.
- Hardware-blocked claims must stay explicit. R1 Neo radio reset, bootloader,
  GNSS, battery, and USB flashing evidence cannot be closed without physical
  hardware or vendor confirmation.
- R1 Neo support must not imply support for original/non-Neo R1 hardware. Do
  not reuse the R1 Neo board target for a non-Neo R1 unless the hardware facts,
  devicetree compatible string, and app overlays are updated under a separate
  Bead.

## Source Evidence

- Target families and Zephyr-first strategy: `README.md`
- Build examples and STM32WL memory budget: `lichen/README.md`
- HAL contract: `docs/firmware-hal-contract.md`
- HAL capability API: `lichen/subsys/lichen/hal/include/lichen/hal.h`
- HAL Kconfig/devicetree contract: `lichen/subsys/lichen/hal/Kconfig`
- Meshtastic app-compat board-identity policy:
  `docs/meshtastic-compat-dev.md`
- First-party board files:
  - `lichen/boards/lilygo/t_echo/t_echo_nrf52840.dts` (provides `t_echo/nrf52840`)
  - `lichen/boards/heltec/heltec_wifi_lora32_v3/heltec_wifi_lora32_v3_procpu.dts`
  - `lichen/boards/lilygo/t_deck/t_deck_esp32s3_procpu.dts`
  - `lichen/boards/muzi/r1_neo/r1_neo_nrf52840.dts`
  - `lichen/boards/seeed/t1000_e/t1000_e_nrf52840.dts`
- App overlays and board configs under `lichen/apps/puck/boards/` and
  `lichen/apps/gateway/boards/`
- Serial-to-LoRa bridge evidence: `firmware/bridge/README.md`
