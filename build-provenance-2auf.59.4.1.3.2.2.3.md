<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Build Provenance Report: native_posix BLE Ingress Artifacts

**Bead:** project-LICHEN-2auf.59.4.1.3.2.2.3
**Date:** 2026-07-23 (UTC)
**Result:** PROVENANCE CAPTURED — build exit 0, all artifact SHA256s recomputed and verified identical to build-time records

## 1. Scope

Capture, for the native_posix BLE-ingress validation effort (parent epic
`…2.2`, grandparent `…2`): the exact build commands, full stdout/stderr build
logs, exit codes, and SHA256 digests of `zephyr.elf`, `zephyr.bin`, and all
other key artifacts — consolidated into a single provenance report.

The green build itself was executed under sibling bead `…2.2.2.4` (full
history: 6 numbered attempts + 6 final candidates, all logs committed). This
bead re-verified the artifacts and records the canonical provenance.

## 2. Build Identity

| Item | Value |
|------|-------|
| App | `lichen/apps/gateway` |
| Board | `native_sim/native/64` |
| Build dir | `build/ble-native-posix-ingress-59-4-final6` |
| Worktree | `/mnt/lichen-zephyr/work/project-LICHEN-worker1` |
| Build-time HEAD | `0af295b3864d7ff06872a8ebc361d0b122221bb3` (commit epoch 1784830823) |
| Capture-time HEAD | `0f508c9eb86d8ebb03e52f26a666f18763afbbf4` |
| Exit code | **0** (187/187 ninja steps) |
| Full build log | `build-logs-2auf.59.4.1.3.2.2.2.4-final6.log` (committed) |
| Exit-code records | `build-exit-2auf.59.4.1.3.2.2.2.4.txt`, `build-exit-2auf.59.4.1.3.2.2.3.txt` |
| Artifact manifest | `artifacts-2auf.59.4.1.3.2.2.3.txt` |

**Board note:** `native_posix` is deprecated in Zephyr 3.7 and is 32-bit-x86
only; it cannot build on this aarch64 host. `native_sim/native/64` is its
Zephyr 3.7 successor and is the board used for all "native_posix BLE"
validation rows in this epic.

**Exact build command:**

```sh
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
west build -b native_sim/native/64 --pristine=always lichen/apps/gateway \
  -d build/ble-native-posix-ingress-59-4-final6 -- \
  -DDTC_OVERLAY_FILE=boards/native_posix_ble_ingress.overlay \
  -DEXTRA_CONF_FILE=boards/native_posix_ble_ingress.conf \
  -DZEPHYR_EXTRA_MODULES=$PWD/lichen \
  -DLICHEN_RELEASE_EPOCH_UNIX=1722470400
```

Merged Kconfig: `native_sim_64_defconfig` + `prj.conf` +
`boards/native_sim_native_64.conf` + `boards/native_posix_ble_ingress.conf` +
generated `lichen/build_epoch.conf`.

## 3. Build Environment

| Tool | Version |
|------|---------|
| Zephyr | 3.7.0 (`/mnt/lichen-zephyr/work/zephyr`) |
| Zephyr SDK | 0.16.8 |
| west | 1.5.0 |
| CMake | 3.30.0 |
| Host gcc | 11.5.0 (Red Hat 11.5.0-5) |
| Python | 3.9.25 (`/mnt/lichen-zephyr/venv`) |
| Host | aarch64, Amazon Linux 2023 (EC2, us-west-2c, LICHEN EBS builder cache `vol-0a95eee8d1d8461eb`) |

Reproducibility knobs: `SOURCE_DATE_EPOCH` pinned to build-time HEAD commit
epoch; `LICHEN_RELEASE_EPOCH_UNIX=1722470400` pinned for the LICHEN build-epoch
config.

## 4. Artifact Digests (SHA256, recomputed by this bead)

| Artifact | SHA256 (prefix) | Size (bytes) |
|----------|-----------------|--------------|
| `zephyr/zephyr.elf` | `ee06d7f0…17272e` | 9,263,784 |
| `zephyr/zephyr.exe` (native runner) | `643ac72f…dbfacc` | 4,335,456 |
| `zephyr/.config` (merged Kconfig) | `e3810102…4202cb` | 79,461 |
| `zephyr/zephyr.dts` | `e71b936d…dd32e9` | 4,233 |
| `zephyr/zephyr.map` | `7e09015b…d9f67d` | 790,601 |
| `zephyr/zephyr.stat` | `d5b5e284…9d1259` | 426,927 |
| `CMakeCache.txt` | `146ed513…2900f6f1` | 23,827 |
| `zephyr_modules.txt` | `7d207d19…a7b9307` | 5,002 |

Full 64-hex digests: `artifacts-2auf.59.4.1.3.2.2.3.txt`.

**`zephyr.bin` / `zephyr.hex`: not produced.** Verified absent from the build
directory. Host-native targets (`native_sim`, formerly `native_posix`) link a
directly runnable ELF plus the `zephyr.exe` native runner; there is no raw
flash image. The bead's "zephyr.bin" item is therefore N/A for this target —
`zephyr.elf`/`zephyr.exe` are the binary artifacts of record.

## 5. Integrity Verification

All 8 artifact SHA256s recomputed by this bead on 2026-07-23 ~20:20 UTC are
**byte-for-byte identical** to the values recorded at build time (~17:41 UTC)
in `artifacts-2auf.59.4.1.3.2.2.2.4.txt`. The artifacts have not been modified
since the green build. Build-input config fragments were also hashed
(`prj.conf`, `native_posix_ble_ingress.conf`, `native_posix_ble_ingress.overlay`)
— digests in the manifest.

Cross-tree determinism note (from `…2.2.2.4`): generated `zephyr.dts` is
identical to the clean-EBS-worktree build (`artifacts-2auf.59.4.1.3.2.2.2.3.txt`);
ELF hashes differ across trees only via embedded build paths.

## 6. Failed Precursor Attempt (this bead, earlier session)

`build-provenance-2auf.59.log` (committed with this report) records an earlier
attempt under this bead to build `lichen/tests/ble_ipsp_transport` for
`native_sim`: **exit 1**, CMake configure failure — Kconfig dependency loop
(`UART_INTERRUPT_DRIVEN` ↔ `MCUMGR`/`ZCBOR`/`LICHEN_COAP_KEYS` chain). Full
stdout/stderr is inside that log; the raw capture also lives at
`build-logs-2auf.59/native_sim_ble_ipsp.log` (gitignored `build-*` dir).

Consequence: `lichen/apps/gateway` with the `native_posix_ble_ingress`
conf/overlay became the canonical BLE-ingress build vehicle (per `…2.2.2.4`),
and the `ble_ipsp_transport` test-app Kconfig loop remains a known issue for
any future direct build of that app on native targets.

## 7. Evidence Index (all committed)

| File | Content |
|------|---------|
| `build-logs-2auf.59.4.1.3.2.2.2.4-final6.log` | Full stdout/stderr of green build (cmake configure → `[187/187]`) |
| `build-logs-2auf.59.4.1.3.2.2.2.4-*.log` (14 files) | All precursor attempt logs |
| `build-exit-2auf.59.4.1.3.2.2.2.4.txt` / `…2.3.txt` | Exit code 0 records |
| `artifacts-2auf.59.4.1.3.2.2.3.txt` | This bead's full manifest |
| `build-provenance-2auf.59.log` | Failed `ble_ipsp_transport` attempt (this bead, earlier session) |
| `validation-summary-2auf.59.4.1.3.2.2.2.4.md` | Sibling bead's configuration/issue analysis |
| `validation-summary-2auf.59.4.1.3.2.2.4.md` | Sibling bead's runtime test evidence (twister 4/4 PASS) |

## 8. Conclusion

Provenance for the native_posix (native_sim/native/64) BLE-ingress build is
fully captured: exact command, environment, exit code 0, complete logs, and
verified SHA256 digests of every key artifact. No discrepancies found between
build-time and capture-time digests.
