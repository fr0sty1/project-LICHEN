<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Supported Board Build Matrix

Derived from repository tree inventory, CI configuration, and retained build
provenance for bead `project-LICHEN-2auf.31` (generated 2026-08-28). This is
the **build/package** matrix for Zephyr applications and declared Rust bridge
targets. It is distinct from the peripheral-capability matrix in
`docs/firmware-board-capability-matrix.md` and makes **no hardware-validation
claims**: a build pass is not a hardware bring-up.

Statuses are derived only from evidence visible in this repository. Unknowns
and blockers are recorded explicitly rather than silently reduced.

## Evidence sources

| ID | Source |
|----|--------|
| S1 | First-party board definitions: `lichen/boards/**` (`board.yml`, `.dts`) |
| S2 | App/sample board overlays: `lichen/apps/puck/boards/`, `lichen/apps/gateway/boards/`, `lichen/apps/test_blink/boards/`, `lichen/samples/lora_ping/boards/` |
| S3 | CI: `.github/workflows/{renode-firmware.yml,renode.yml,ec2-arm64.yml,interop.yml}` |
| S4 | Retained provenance log `build-provenance-2auf.31.1.log` (nRF52840 rows; worktree commit `0b8cbf2b`; Zephyr v3.7.0; Zephyr SDK 0.16.8; `arm-zephyr-eabi-gcc` 12.2.0; west 1.5.0; CMake 3.30.0; EC2 EBS builder `vol-0a95eee8d1d8461eb`, us-west-2c) |
| S5 | Beads `project-LICHEN-2auf.31.1`–`.31.5` (closed; rows .31.2–.31.5 have no retained log/artifact in this repo) |
| S6 | Declared row list `scripts/build-nrf52840-matrix.sh` |
| S7 | Blocked/retired classifications in `docs/firmware-board-capability-matrix.md` and board config headers |

## Build-status legend

| Level | Meaning |
|-------|---------|
| `CI` | Built by GitHub Actions on push/PR (S3) |
| `EBS pass (log)` | Built on the EBS builder, exit 0, sizes + SHA-256 retained in S4 |
| `EBS record` | Bead-closed build record only; **no** retained log/artifact in repo (S5) |
| `Unverified` | Board/app files present in tree; no build evidence found in tree, CI, or beads |
| `Blocked` / `Failed` | Explicit in-tree BLOCKED classification or retained log failure |

## Link / signature column

* `LICHEN_LORA_L2` is `default y` when its dependencies are satisfied and
  `select`s `LICHEN_LINK`; `LICHEN_LINK_SCHNORR` (48-byte Schnorr link
  signatures, `draft-lichen-schnorr-00`) is `default y`
  (`lichen/subsys/lichen/l2/Kconfig:45`, `lichen/subsys/lichen/link/Kconfig:20`).
* Gateway additionally sets `CONFIG_LICHEN_LORA_L2=y` and
  `CONFIG_LICHEN_LINK=y` explicitly (`lichen/apps/gateway/prj.conf:30,41`).
* `lichen/samples/lora_ping` is a raw `CONFIG_LORA` sample with **no** LICHEN
  link/signing (`lichen/samples/lora_ping/prj.conf`).

## nRF52840 family

| Board | Target (`west -b`) | SoC | LoRa radio | Link / signature | Build status (evidence) | Notes |
|-------|--------------------|-----|------------|------------------|-------------------------|-------|
| LilyGO T-Echo | `t_echo/nrf52840` | nRF52840 | SX1262 (S1: DTS:132) | LICHEN L2 + Schnorr-48 (default y) | puck: `CI` (S3: renode.yml:176, renode-firmware.yml:67) + `EBS pass (log)` w/ Renode console overlay — FLASH 44.05% / RAM 26.99%; gateway: `EBS pass (log)` — FLASH 24.43% / RAM 30.84% (S4) | Retained SHA-256 for ELF/BIN in S4 |
| RAK4631 WisBlock | `rak4631/nrf52840` | nRF52840 | SX1262 (per S7; **board def not present in this checkout**) | LICHEN L2 + Schnorr-48 (default y) | puck: `EBS pass (log)` w/ Renode overlay — FLASH 14.76% / RAM 26.25%; lora_ping: `EBS pass (log)` + `CI` (S3: renode-firmware.yml:61) — FLASH 4.12% (S4) | No first-party `board.yml`; upstream Zephyr v3.7.0 does not ship `rak4631` — board-file provenance unverifiable in this checkout. Puck conf/overlay in S2; no gateway conf |
| Seeed SenseCAP T1000-E | `t1000_e/nrf52840` | nRF52840 | LR1110 (S1: DTS:73) | LICHEN L2 + Schnorr-48 (default y) | puck: `EBS pass (log)` — FLASH 53.20% / RAM 32.23%; gateway: `EBS pass (log)` — FLASH 52.44% / RAM 29.68% (S4) | Renode row **excluded**: LR1110 incompatible with `nrf52840_lichen` SX1262 platform (S6). `test_blink` overlay exists (S2) |
| Muzi Works R1 Neo | `r1_neo/nrf52840` | nRF52840 | SX1262 (S1: DTS:144) | LICHEN L2 + Schnorr-48 (default y) | gateway: `EBS pass (log)` — FLASH 25.64% / RAM 33.84%; **puck: `Failed`** — exit 1 at commit `0b8cbf2b`: `lichen/coap_client.h` include not on path, `CONFIG_COAP_SERVICE_OBSERVERS` undeclared (S4) | Include path now exists in tree (`lichen/subsys/lichen/coap/include/lichen/coap_client.h`); no verified puck pass found. Retained log ends "Some builds had issues" — .31.1 close reason ("all rows built") is contradicted for this row; blocker recorded here per fail-closed design |
| Nordic nRF52840 DK | `nrf52840dk_nrf52840` | nRF52840 | none on DK (BLE/serial shell class, S7) | gateway sets `LICHEN_LINK=y` | gateway: `EBS pass (log)` — FLASH 20.36% / RAM 28.14% (S4) | Gateway conf only (S2); no puck conf |
| ELECROW ThinkNode M3 | `thinknode_m3/nrf52840` | nRF52840 | LR1110 (S1: DTS:122) | app confs present | `Unverified` — no build evidence in tree, CI, or beads | Puck + gateway confs/overlays exist (S2) |

## STM32WL family

| Board | Target (`west -b`) | SoC | LoRa radio | Link / signature | Build status (evidence) | Notes |
|-------|--------------------|-----|------------|------------------|-------------------------|-------|
| ST Nucleo WL55JC | `nucleo_wl55jc` | STM32WL55 (64 KB RAM / 256 KB flash baseline) | Integrated Sub-GHz | gateway: `LICHEN_LORA_L2=y` + `LICHEN_LINK=y`; puck: L2 default y | `EBS record` (S5: .31.2 closed, close reason "Already fixed"; **no retained log in repo**); STM32WL memory-fit also reported by .31.4/.31.5 close notes | Puck + gateway confs/overlays, lora_ping conf+overlay in S2; Renode platform + custom peripherals (`LichenSubGHz.cs` etc.) under `lichen/boards/renode/nucleo_wl55jc/`; no CI build of this target |
| Wio-E5 / RAK3172 module class | — | STM32WL55/WLE5 | SX126x-class integrated | — | Not a first-party Zephyr port; family target only (S7). Rust target row below | Partner-owned scale-out per S7 |

## ESP32 / ESP32-S3 family

| Board | Target (`west -b`) | SoC | LoRa radio | Link / signature | Build status (evidence) | Notes |
|-------|--------------------|-----|------------|------------------|-------------------------|-------|
| Heltec WiFi LoRa 32 V3 | `heltec_wifi_lora32_v3/esp32s3/procpu` | ESP32-S3 | SX1262 (S1: DTS:133) | LICHEN L2 + Schnorr-48 (default y) | `EBS record` (S5: .31.3 closed, close reason "Already fixed"; **no retained log in repo**) | `procpu` + `appcpu` variants defined (S1); app confs/overlays cover `procpu` (S2); no CI build of this target |
| LilyGO T-Deck | `t_deck/esp32s3` (app selector `t_deck_esp32s3_procpu`) | ESP32-S3 | SX1262 (S1: DTS:160) | LICHEN L2 + Schnorr-48 (default y) | `EBS record` (S5: .31.3; no retained log) | Gateway also carries `display_validation` and `sd_validation` conf/overlay variants (S2); no CI build of this target |
| TTGO LoRa32 | no canonical board def | ESP32 | SX1276/78 class | — | `Unverified` — puck overlay `ttgo_lora32_esp32_procpu` exists (S2); no `board.yml` in tree; Renode platform only | Partner long tail (S7) |
| T-Beam Supreme | no canonical board | ESP32-S3 | SX1262 expected | — | `Blocked` — explicit BLOCKED marker in `lichen/apps/puck/boards/tbeam_supreme.conf`; proxy = heltec V3 procpu (S7, bead `project-LICHEN-w8rd`) | Overlay present for reference only |
| Seeed XIAO ESP32-S3 + Wio-SX1262 | — | ESP32-S3 | SX1262 | — | `Blocked`/retired — composite bridge fragment retired per bead `project-LICHEN-2u26.10` (S7) | Use heltec V3 proxy |
| ELECROW ThinkNode M7 | `thinknode_m7/esp32s3/{procpu,appcpu}` | ESP32-S3 | LR1110 (S1: DTS:76) | — | `Unverified` — board def exists; no app confs/overlays; no build evidence | — |

## Host / simulated targets

| Board | Target (`west -b`) | SoC | LoRa radio | Link / signature | Build status (evidence) | Notes |
|-------|--------------------|-----|------------|------------------|-------------------------|-------|
| native_sim (puck, gateway) | `native_sim` | POSIX host | none (simulated path) | gateway sets `LICHEN_LINK=y` | `EBS record` (S5: .31.4 closed; no retained log). CI uses `native_sim` for link_crypto/SCHC **twister test suites**, not the app builds (S3: interop.yml:164) | Puck + gateway confs/overlays in S2; `native_posix_ble_ingress` gateway variant present but `Unverified` (S2) |
| native_sim 64-bit | `native_sim/native/64` | POSIX host (64-bit) | none | as above | `CI` — gateway + puck built `--pristine` (S3: ec2-arm64.yml:61,64) + `EBS record` (.31.4) | — |
| qemu_x86 | `qemu_x86` | x86 | none | gateway conf only | `Unverified` — gateway conf exists (S2); no build evidence | — |

## Samples / test apps

| App | Boards covered | Link / signature | Build status (evidence) | Notes |
|-----|----------------|------------------|-------------------------|-------|
| `lichen/samples/lora_ping` | `t_echo/nrf52840`, `rak4631/nrf52840` (Renode console overlay, S3/S4); overlays also present for `t1000_e_nrf52840`, `nucleo_wl55jc` (S2) | none — raw `CONFIG_LORA` sample | t_echo: `CI` (renode-firmware.yml:61) + `EBS pass (log)` FLASH 4.42% / RAM 2.73%; rak4631: `EBS pass (log)` FLASH 4.12%; t1000_e / nucleo rows: `Unverified` | — |
| `lichen/apps/test_blink` | `t1000_e_nrf52840` overlay (S2) | none | `Unverified` | — |

## Declared Rust bridge targets (bead .31.5)

| Target | Crate | Notes | Build status (evidence) |
|--------|-------|-------|-------------------------|
| `thumbv7em-none-eabi` (STM32WL55 / Wio-E5) | `rust/lichen-firmware/wio-e5` (embassy-stm32, `stm32wle5jb`) | Target pinned in `rust/lichen-firmware/wio-e5/.cargo/config.toml` | `EBS record` (.31.5 closed; generic close note; no retained log in repo) |
| ESP32 / nRF52840 Rust bridge triples | declared by .31.5 acceptance text | No `.cargo/config.toml` or pinned target found anywhere under `rust/` in this checkout | `Unverified` — no in-tree target configuration visible; per-bead record only |

## Renode virtual platforms (not Zephyr boards)

`lichen/boards/renode/` carries Renode `.repl`/`.resc` platforms — these are
simulation platforms, not `west -b` targets; firmware is always built against
the real board target (see S3 comment in renode-firmware.yml):
`nrf52840_lichen`, `esp32s3_lichen`, `esp32_lichen`, `t_echo`, `rak4631`,
`t1000_e`, `t_deck`, `ttgo_lora32`, `heltec_wifi_lora32_v3`, `nrf52840dk`,
`nucleo_wl55jc`.

## Recorded discrepancies and unknowns

1. **R1 Neo puck failed in the retained .31.1 log** (exit 1, missing
   `lichen/coap_client.h` include path and undeclared `COAP_SERVICE_OBSERVERS`
   symbols at commit `0b8cbf2b`) while the .31.1 close reason claims all
   nRF52840 rows built. The include file is present in the current tree, but no
   verified puck pass exists in any retained evidence. Treated as **Failed /
   unverified** here, per the fail-closed design of this matrix.
2. `.31.2` (STM32WL) and `.31.3` (ESP32) closed with close reason
   "Already fixed" and no retained build logs or artifact hashes in the repo —
   their rows are recorded at `EBS record` confidence only.
3. `.31.4`/`.31.5` closed with generic notes; no retained logs; Rust
   ESP32/nRF52840 bridge target configs are not visible in the tree.
4. `rak4631` has no first-party board definition and is not shipped by upstream
   Zephyr v3.7.0; its build provenance on the EBS builder cannot be reconciled
   against this checkout.
5. The Renode test-harness subdirectories contain committed `__pycache__`
   artifacts (`lichen/boards/renode/esp32s3_lichen/__pycache__/`,
   `lichen/boards/renode/nrf52840_lichen/__pycache__/`) — hygiene issue, not a
   build-status item.
6. `docs/firmware-board-capability-matrix.md` currently contains unresolved
   git-conflict markers (lines 39–43, 52–56) — pre-existing, outside this
   bead's scope, and not modified here.

## Reproduction

EBS-builder commands are recorded verbatim in
`build-provenance-2auf.31.1.log` (pattern:
`west build -b <target> lichen/apps/<app> -d <dir> -p always --
-DZEPHYR_EXTRA_MODULES=<repo>/lichen -DBOARD_ROOT=<repo>/lichen
[-DEXTRA_DTC_OVERLAY_FILE=... -DEXTRA_CONF_FILE=...]` with Zephyr v3.7.0,
SDK 0.16.8). CI definitions live in `.github/workflows/`.
