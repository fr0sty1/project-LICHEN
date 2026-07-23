<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Provenance: project-LICHEN-2auf.59.4.1.3.2.1.3

Task: Capture full logs, exit codes, artifact SHA256 sums, and document the
EC2 validation workflow for MeshCore BLE native/64-bit clean-worktree
validation runs.

## Worktree

- Path: `/mnt/lichen-zephyr/work/project-LICHEN-mcble-213-evidence`
- Created via: `tools/zephyr-clean-worktree.sh create project-LICHEN-mcble-213-evidence origin/main`
- Ref: `1b8878780b66372882e144db9a2ca9ce939235b4` (`origin/main`; clean tree,
  0 modified paths under `lichen/`)
- Cache links: `zephyr`, `modules`, `bootloader` symlinked from
  `/mnt/lichen-zephyr/work/project-LICHEN` per script design.
- Nested `.west` removed after `create` (host convention: the script-written
  nested workspace cannot resolve `import: true` on this host; removing it
  lets `west` climb to the host workspace at `/mnt/lichen-zephyr/work/.west`,
  matching every other functioning validation worktree here). Module
  isolation is unaffected — it is enforced by
  `-DZEPHYR_EXTRA_MODULES=<worktree>/lichen` and checked by
  `verify-twister` (exit 0 below).

## Environment

- Host: `ip-172-31-5-236.us-west-2.compute.internal` (aarch64, Amazon Linux
  2023, Linux 6.1.176-221.360.amzn2023.aarch64)
- West v1.5.0, Python 3.9.25, Zephyr v3.7.0, Zephyr SDK 0.16.8
- Run date: 2026-07-23 22:15:20–22:15:24 UTC

## Validation run

Command (exactly as documented in `docs/zephyr-ec2-clean-worktree.md`):

```bash
. /mnt/lichen-zephyr/env.sh
cd /mnt/lichen-zephyr/work/project-LICHEN-mcble-213-evidence
west twister \
  -T lichen/tests/meshcore_codec \
  -T lichen/tests/meshcore_adapter \
  -T lichen/tests/meshcore_ble \
  -T lichen/tests/meshcore_gateway_adapter \
  -T lichen/tests/app_interface \
  -p native_sim/native/64 \
  --inline-logs \
  --outdir twister-out-meshcore-ble \
  --extra-args ZEPHYR_EXTRA_MODULES="$PWD/lichen"
tools/zephyr-clean-worktree.sh verify-twister "$PWD" twister-out-meshcore-ble
```

Full command output: `build-logs-2auf.59.4.1.3.2.1.3.log`
(SHA256 `dd7cf6a630d9ef5fcb72a828e174fe4575634ef5285c6b2c2d6ff4728a607368`).

### Exit codes

| Step | Exit code |
|------|-----------|
| `west twister` | 1 |
| `tools/zephyr-clean-worktree.sh verify-twister` | 0 |

Recorded in `build-exit-2auf.59.4.1.3.2.1.3.txt`.

### Test results (twister.json)

| Suite | Result |
|-------|--------|
| net.lichen.meshcore_codec | error — 9/9 testcases |
| net.lichen.meshcore_adapter | error — 32/32 testcases |
| net.lichen.meshcore_adapter.identity | error — 32/32 testcases |
| net.lichen.meshcore_ble | error — 10/10 testcases |
| net.lichen.meshcore_gateway_adapter | error — 26/26 testcases |
| net.lichen.meshcore_gateway_adapter.settings_nvs | error — 26/26 testcases |
| net.lichen.app_interface | error — 24/24 testcases |
| **Total** | **159 error, 0 passed, 0 failed, 0 skipped** |

### Failure signature

All 7 suites fail identically at the cmake/Kconfig stage: kconfig.py reports
a **Kconfig dependency loop** through `UART_INTERRUPT_DRIVEN` /
`UART_MCUMGR` / modem select chains, and cmake aborts at
`kconfig.cmake:389` ("command failed with return code: 1"). No compilation
is reached; no `zephyr.elf`/`zephyr.exe` binaries are produced (verified
absent). Module isolation itself is clean (`verify-twister` exit 0), so this
is a tree state issue on `origin/main`, not an environment issue.

The same failure is visible in the stale `twister-out-meshcore-ble/` of the
sibling worktree `project-LICHEN-2auf-59-mcble-213`; the build fixes are
tracked by the open sibling bead
**project-LICHEN-2auf.59.4.1.3.2.1.2** ("Implement MeshCore BLE ingress test
builds in clean worktree for native_sim and 64-bit targets"). This bead
records the pre-fix baseline; once .2.1.2 lands, the same documented command
re-run in a fresh clean worktree produces the post-fix evidence.

### Artifacts and hashes

No binaries were produced. SHA256 sums of the master log, twister reports,
and all 7 per-suite `build.log` files are recorded in
`artifacts-2auf.59.4.1.3.2.1.3.txt`.

## Documentation

`docs/zephyr-ec2-clean-worktree.md` gained an "Evidence capture" subsection
under "MeshCore BLE native/64-bit Validation" with the exact reproducible
commands for recording full logs, exit codes, test results, and SHA256 sums,
plus the repo-root evidence-file naming convention used by this and prior
validation beads.

Status: evidence captured and workflow documented. Validation itself is
blocked on the Kconfig dependency loop fixed under
project-LICHEN-2auf.59.4.1.3.2.1.2.
