<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Validation Summary: native_posix BLE Ingress Build (no link.35.6)

**Bead:** project-LICHEN-2auf.59.4.1.3.2.2.2.4
**Date:** 2026-07-23 (UTC)
**Result:** BUILD PASS (exit 0, 187/187 steps) — artifacts hashed in `artifacts-2auf.59.4.1.3.2.2.2.4.txt`

## Configuration Used

| Item | Value |
|------|-------|
| Board | `native_sim/native/64` (Zephyr 3.7 successor to deprecated `native_posix`) |
| App | `lichen/apps/gateway` |
| DTC overlay | `boards/native_posix_ble_ingress.overlay` (deletes `lora_sim` node; no `zephyr,lora` chosen) |
| Extra conf | `boards/native_posix_ble_ingress.conf` |
| Extra modules | `-DZEPHYR_EXTRA_MODULES=$PWD/lichen` |
| Epoch | `-DLICHEN_RELEASE_EPOCH_UNIX=1722470400`, `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)` |
| Build dir | `build/ble-native-posix-ingress-59-4-final6` |
| Exit-code record | `build-exit-2auf.59.4.1.3.2.2.2.4.txt` = `0` |

Key Kconfig selection (from `native_posix_ble_ingress.conf`):
- **BLE on:** `BT=y`, `BT_PERIPHERAL=y`, `BT_MAX_CONN=1`, `LORA_LICHEN_BLE=y` (selects `NET_L2_DUMMY` + `APP_INTERFACE`)
- **Link.35.6 off:** `LICHEN_LINK=n`, `LICHEN_LORA_L2=n`, `LICHEN_L2=n`, `LICHEN_HAS_LORA=n`, `LICHEN_RADIO_MODEL_NONE=y`, `LICHEN_ROUTING=n`, `LICHEN_RPL=n`, `GNSS=n`
- **Unrelated gateway services off:** MCUMGR, CoAP, OSCORE, SenML, SLIP transport, FS all `=n`
- **Net:** `NETWORKING=y`, `NET_IPV6=y` (+ND, nbr cache), `NET_UDP=y`, `NET_L2_DUMMY=y`, `NET_IF_MAX_IPV6_COUNT=2`

## Build Result

- 187/187 ninja steps completed; `zephyr/zephyr.elf` (9,263,784 B) and `zephyr/zephyr.exe` (4,335,456 B native runner) produced.
- **No `zephyr.bin`/`zephyr.hex`** — expected on host-native targets (the ELF/exe *is* the runnable image).
- Cross-check: generated `zephyr.dts` SHA256 (`e71b936d…dd32e9`) is identical to the clean-EBS-worktree build recorded in `artifacts-2auf.59.4.1.3.2.2.2.3.txt`, confirming devicetree/config determinism across trees. ELF hashes differ (embedded build paths differ between trees).

## Test Evidence

- `net.lichen.ble_ingress` twister run: **4/4 PASS** (`test-logs-…2.4-twister.log`, `…-ble-ingress-run.log`): LCI iface configured for SLIP link, IPv6 injection into RX path, malformed-packet rejection (null / IPv4 / bad payload length / no netif), reply egress via BLE LCI path.

## Observed Issues (BLE ingress on native_posix, no link.35.6)

Iterated through 6 numbered attempts + 6 "final" candidates before the green build (logs `build-logs-…2.4-*.log`):

1. **Board qualification (attempt6):** plain `native_sim` defaults to 32-bit and hard-fails on this aarch64 host: *"CONFIG_64BIT=n but this Aarch64 machine has a 64-bit userspace"*. Fix: target `native_sim/native/64`. (`native_posix` itself is deprecated in Zephyr 3.7 and x86-32 only.)
2. **CMake var misuse (attempt2):** passing the DTC overlay via `OVERLAY_CONFIG=` (a Kconfig fragment var) instead of `DTC_OVERLAY_FILE=` breaks configuration.
3. **Kconfig warnings-as-errors (first, attempts 3–5):** stray assignments for symbols whose dependencies were disabled (e.g. `NET_ROUTE` with routing off) abort configuration under `-Werror`-style Kconfig strictness; the final conf drops them.
4. **Link-layer-exclusion hygiene in tree (final):** with `LICHEN_HAS_LORA=n`, `hal.c` BUILD_ASSERTs still demanded an okay `zephyr,lora` chosen node, and `lora_loopback.c` tripped `-Werror=unused-function/const-variable`. Also `app_interface/hal_bridge.c` used `strnlen` without `<string.h>`, and `rpl/routing.c` had undeclared identifiers (`workspace`, `staged_count`, `finish_group`, `candidate_equal`) when compiled in this config.
5. **Unguarded gateway app sources (final3, final5):** `announce_ingest.c`/`main.c` include `lichen/routing/announce.h`, `lichen/rpl_dodag.h`, and `ble_uart.c` includes `lichen/transport/slip_transport.h` even when those subsystems are configured out — missing `#ifdef` guards or source-list conditioning.
6. **Duplicate NUS GATT service definition (final4, the key BLE ingress finding):** link error — `nus_svc` / `attr_nus_svc` defined both by `subsys/lichen/transport/ble_ipsp_transport.c:342` and `apps/gateway/src/ble_uart.c:230` when both BLE paths are compiled together. Resolved in the final configuration (`LICHEN_BLE_TRANSPORT=n`, `LICHEN_BLE_SLIP=n` with the gateway's own `ble_uart` path), but the duplicate symbol remains a latent conflict if both transports are ever enabled simultaneously — worth a follow-up bead if that combination is ever wanted.
7. **IPSP L2 unavailable:** Zephyr 3.7 has no usable `NET_L2_BT`/IPSP L2 for this target, so BLE ingress runs over `NET_L2_DUMMY` with the BLE LCI netif code-driven (`NET_DEVICE_INIT(ble_lci…)`), per the conf header notes. Real IPSP-attached routing is therefore not exercisable on native_sim; the BLE ingress path is validated at the LCI/netif boundary only.
8. **`net.lichen.app_interface` on native_sim/native/64: twister Build failure** (`test-logs-…2.4-app-interface-final.log`) — pre-existing, outside this bead's BLE-ingress scope; not caused by the ingress overlay.

## Related Beads

- `…2.2.2.1` (Kconfig research) — findings embodied in `native_posix_ble_ingress.conf` header comments; still open at time of writing.
- `…2.2.2.2` (overlay/conf creation) — closed; produced the overlay + conf used here.
- `…2.2.2.3` (verbose clean-worktree build) — exit 0, manifest `artifacts-2auf.59.4.1.3.2.2.2.3.txt`; issue file shows open on disk after a later bd sync revert.
- Parent `…2.2.2` closed as "Decomposed into subtasks".
