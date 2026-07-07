<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Firmware HAL Contract

This document defines the Zephyr firmware HAL boundary used by LICHEN
application, protocol, and compatibility code. The public C API lives in
`lichen/subsys/lichen/hal/include/lichen/hal.h`; this document explains how
board ports and consumers use that API without matching on board names.

## Ownership Boundary

The HAL owns board capability discovery and the translation from Zephyr
Kconfig/devicetree facts into stable LICHEN firmware services. Board ports and
app overlays provide `CONFIG_LICHEN_HAS_*` capability symbols, selected radio,
UI, location, and time provider choices, plus the devicetree `chosen` nodes or
aliases required by `lichen/subsys/lichen/hal/Kconfig`.

Application and protocol consumers should use `lichen_hal_*` APIs for covered
services. New code must not use `CONFIG_BOARD`, board-name string matching, or
board-specific devicetree aliases to decide whether a LoRa radio, display,
button, GNSS receiver, power provider, storage device, or local-client
transport exists. Board quirks stay in board files, overlays, driver bindings,
and HAL code.

The LoRa L2 path uses the HAL LoRa device and identity boundary. Driver-level
samples may still use Zephyr radio APIs directly, but should use `chosen
zephyr,lora` rather than board aliases.

The board capability matrix in `docs/firmware-board-capability-matrix.md`
records target-specific evidence. It is a planning and partner-handoff document;
the HAL API is the runtime and build-time contract.

Capability state vocabulary:

| State | Contract |
|-------|----------|
| Mandatory | Core HAL identity, capability, status, and deterministic unavailable behavior are present whenever `CONFIG_LICHEN_HAL=y`. |
| Optional | A `LICHEN_HAL_CAP_*` bit and service-specific status/device API are present, but the capability may be disabled in a given build. |
| Stubbed/unavailable | The API exists and returns `-ENOTSUP` or a snapshot with provider availability false; consumers must handle this without falling back to board names. |
| Compile-time disabled | The build omits the Zephyr driver or local-client service. HAL status reports unsupported or unavailable rather than applications probing board files directly. |

## Initialization And Threading

The core capability and identity getters require no explicit initialization.
They are derived from Kconfig/devicetree constants and Zephyr device readiness.
Consumers may call them after normal Zephyr device initialization.

Location and time provider state is process-global and protected internally by
Zephyr mutexes. Submit, clear, and snapshot calls are safe to use from firmware
threads. Interrupt handlers should hand samples to a work item or thread before
calling provider APIs.

The HAL does not initialize LICHEN link security, RPL, OSCORE, CoAP, BLE
services, or app-specific sockets. Those subsystems keep the initialization
order documented in `AGENTS.md`.

## Error Model

HAL functions use negative errno values and deterministic zeroed outputs:

| Return | Meaning |
|--------|---------|
| `0` | Capability or snapshot is available and the output is initialized. |
| `-EINVAL` | Caller passed a null output, invalid enum, invalid source class, malformed sample, or unauthenticated/invalid provision value. |
| `-ENOTSUP` | The capability is not enabled for this build or the provider class is unsupported. |
| `-ENODEV` | The capability is enabled but the required Zephyr device or driver is absent or not ready. |
| `-ERANGE` | A time sample is below the accepted epoch floor. |
| `-ETIME` | A time sample is too stale to establish the current wall clock. |
| `-EALREADY` | A lower-trust time sample cannot move an accepted wall clock backward. |

Device getters clear output pointers before returning errors. GPIO getters clear
`gpio_dt_spec` outputs before returning errors. Snapshot getters initialize the
whole snapshot and then mark only known fields valid. Consumers must check the
corresponding `*_valid` bit before reading optional fields.

## Capability Discovery

`lichen_hal_capabilities_get()` returns a static capability record containing:

- `flags`: a bitmask of `LICHEN_HAL_CAP_*` capabilities enabled for this build.
- `radio`: one of `NONE`, `SX126X`, `SX127X`, `LR1110`, `STM32WL`, `SIM`,
  `LOOPBACK`, or `RENODE`.
- `ui`: `HEADLESS`, `TRACKER`, or `HANDHELD`.
- `location`: currently `NONE` or `GNSS`.
- `time`: currently `UPTIME` or `GNSS`.

`lichen_hal_has_capability()` answers bitmask membership only. A true result
does not prove the Zephyr device is ready; call the service-specific status or
device getter before use. `lichen_hal_capability_status()` accepts exactly one
known capability bit and returns the same status that the service-specific
status function would return.

`lichen_hal_identity_get()` reports the user-facing `CONFIG_LICHEN_BOARD_NAME`
when set, otherwise `CONFIG_BOARD`, plus the Zephyr board id and capability
record. Compatibility layers may expose this as LICHEN identity, but must not
claim Meshtastic or MeshCore RF hardware identity from it.

Some Zephyr registration macros require a compile-time device expression instead
of a runtime getter. HAL-owned macros such as `LICHEN_HAL_GNSS_DEVICE` are the
allowed escape hatch for that case. If another subsystem needs compile-time
device registration, add a HAL-owned macro or file a follow-up rather than
opening a new application-level board or alias probe.

## Service Contracts

| Service | Kconfig/devicetree contract | Consumer contract |
|---------|-----------------------------|-------------------|
| LoRa radio | `CONFIG_LICHEN_HAS_LORA=y`, `CONFIG_LORA=y`, and `chosen zephyr,lora` with the selected radio model compatible. | Use `lichen_hal_lora_status()` and `lichen_hal_lora_device_get()`. Radio framing and protocol policy remain outside HAL. |
| BLE local transport | `CONFIG_LICHEN_HAS_BLE_LOCAL=y` with Bluetooth peripheral/HCI enabled. | Use `lichen_hal_ble_local_status()` as capability readiness. BLE service ownership remains in app/local-client modules. |
| Serial local transport | `CONFIG_LICHEN_HAS_SERIAL_LOCAL=y` with `lichen,native-uart`, `zephyr,uart-pipe`, `zephyr,slip-uart`, `zephyr,shell-uart`, or `zephyr,console`. | Use `lichen_hal_serial_device_get()`; precedence is encoded in HAL and tested separately. |
| GNSS device | `CONFIG_LICHEN_HAS_GNSS=y` and okay `gnss0` alias. | Use `lichen_hal_gnss_device_get()` for the hardware device. Feed location and time samples into the provider APIs instead of exposing raw GNSS state directly. |
| Location provider | `LICHEN_LOCATION_PROVIDER_NONE` or `GNSS`, with freshness controlled by `CONFIG_LICHEN_LOCATION_FRESHNESS_MAX_AGE_S`. | Submit one sample per source class with `lichen_hal_location_submit()`. Snapshots select the highest-priority fresh usable fix and suppress stale position fields. |
| Time provider | `LICHEN_TIME_PROVIDER_UPTIME` or `GNSS`, with build/provision epoch policy from `docs/firmware-time-provider.md`. | Submit wall-clock samples with `lichen_hal_time_submit()`. Uptime never synthesizes Unix time. Below-floor samples are diagnostic only. |
| Battery | `CONFIG_LICHEN_HAS_BATTERY=y` and okay `battery0` alias backed by a Zephyr voltage-divider or fuel-gauge driver. | Use `lichen_hal_power_snapshot_get()` and check `battery_*_valid` fields; do not assume percent and voltage are both present. |
| PMIC/charger | `CONFIG_LICHEN_HAS_PMIC=y` and okay `pmic0` alias backed by charger, PMIC, or board power device support. | Use `lichen_hal_power_snapshot_get()` and check `charging_valid` and `external_power_valid`. |
| Buttons and LEDs | `CONFIG_LICHEN_HAS_BUTTONS` requires okay `sw0` GPIO; `CONFIG_LICHEN_HAS_LEDS` requires okay `led0` GPIO. | Use `lichen_hal_button_get()` and `lichen_hal_led_get()` for the first common control. Rich keypads, trackballs, or multi-button maps require additional HAL/API work. |
| Display | `CONFIG_LICHEN_HAS_DISPLAY=y` and okay `chosen zephyr,display` or `display0` alias. | Use `lichen_hal_display_device_get()` for readiness. UI profile is coarse; rendering policy belongs to UI code. |
| External flash/storage | `CONFIG_LICHEN_HAS_EXTERNAL_FLASH=y` and okay `external-flash0` alias. | Use `lichen_hal_external_flash_device_get()` before storage features assume external media. SD cards and filesystems require separate storage-layer policy. |
| Reset diagnostics | Optional Zephyr `CONFIG_HWINFO` for reset cause and `CONFIG_REBOOT` for reboot requests. | Use `lichen_hal_reset_diagnostics_snapshot_get()` for reset-cause/reboot capability state and `lichen_hal_reset_request()` for cold/warm reboot requests. Warm reboot is best-effort because Zephyr support is platform-dependent. Reset-cause clearing, factory reset, and retained crash records are explicit unsupported fields until later work proves safe backend support. |

## Source Providers

Location source classes are onboard hardware, external hardware, network, local
client, and manual/static. The provider keeps at most one sample per class.
Snapshot precedence is manual/static, local client, network, external hardware,
then onboard hardware. Fresh 2D/3D fixes outrank no-fix/error metadata; stale
high-priority fixes fall back to lower-priority fresh fixes. Stale snapshots may
preserve source and age metadata but suppress coordinates, altitude, fix time,
satellites, and accuracy fields.

Time source classes are monotonic/internal, internal RTC, GNSS, network, local
client, and manual/static. The time provider applies the effective epoch floor
before trust/precedence. Firmware build epoch and authenticated board provision
epoch are freshness floors, not authoritative clocks. Rejected samples can be
reported through snapshot diagnostics without setting `wall_clock_valid`.

## Reset And Diagnostics

The reset diagnostic surface exposes reboot support, best-effort warm reboot
availability, factory-reset support, reset-cause read availability, supported
reset-cause masks, retained diagnostic support, and retained crash metadata
validity. Unsupported providers are represented by false `*_supported` and
`*_valid` fields rather than by board-specific probing in applications. Public
reset-cause masks use `LICHEN_HAL_RESET_CAUSE_*` bits; raw Zephyr `hwinfo`
masks are preserved only in diagnostic `*_raw` fields.

`lichen_hal_reset_request()` accepts cold and warm reboot requests when
`CONFIG_REBOOT` is enabled. Warm reboot requests are best-effort: platforms may
treat them as cold reset or ignore the warm/cold distinction. Reset-cause
clearing returns `-ENOTSUP` until `project-LICHEN-h7t5.1.1.2` proves a
non-destructive backend support policy. Factory reset returns `-ENOTSUP`
because LICHEN does not yet define what state should be erased or preserved.
Retained crash/watchdog records and diagnostic dump APIs are tracked by
`project-LICHEN-h7t5.1.1.1`; code needing those features must extend the HAL
rather than adding board-specific branches in applications.

## No-Hardware Validation

HAL contract changes that only update documentation should run:

```sh
git diff --check
rg -n '#if.*CONFIG_BOARD|CONFIG_BOARD|DT_ALIAS|DT_CHOSEN' lichen/apps lichen/subsys/lichen | rg -v 'subsys/lichen/hal|CONFIG_BOARD_NAME'
```

LoRa L2 uses the HAL LoRa device boundary; non-HAL matches in applications or
protocol subsystems should either be moved behind HAL or documented as a
driver-level exception with a follow-up Bead.

API, Kconfig, devicetree, or behavior changes require Zephyr validation on the
Linux builder, at minimum:

```sh
west twister -T lichen/tests/hal -p native_sim -p qemu_x86
west twister -T lichen/tests/hal_serial_precedence -p qemu_x86
```

Location/time behavior changes should also run the affected gateway status,
app-interface, inbound LCI location, and puck location tests.
