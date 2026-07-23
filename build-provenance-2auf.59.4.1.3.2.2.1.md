<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Provenance: project-LICHEN-2auf.59.4.1.3.2.2.1

Task: Setup clean EBS worktree for BLE ingress native_posix validation. Verify setup.

## Worktree

- Path: `/mnt/lichen-zephyr/work/project-LICHEN-ble-posix-validate`
- Created via: `tools/zephyr-clean-worktree.sh create project-LICHEN-ble-posix-validate 805b5e033`
- Ref: `805b5e033c4b5acbfc9fc15dcfbc0eec66b12d32` (worktree-worker1 HEAD; the
  state from which the parent-bead native BLE ingress builds were run)
- Cache links: `zephyr`, `modules`, `bootloader` symlinked from
  `/mnt/lichen-zephyr/work/project-LICHEN` per script design.

### Ref selection note

`6caeab8fa` (the `project-LICHEN-2auf-59-ble-ingress` worktree HEAD) was tried
first and rejected: its `lichen/boards/elecrow/thinknode_m7/board.yml` is
malformed for the Zephyr 3.7 board schema (`full_name`, board-level `variants`,
`dt` keys), so *any* board build with `ZEPHYR_EXTRA_MODULES` pointing at that
tree fails during board enumeration. `805b5e033` has a valid board.yml and the
`lichen/tests/ble_ingress` test.

### Nested `.west` removal note

The script writes `.west/config` (manifest path = lichen). On this host that
nested workspace is unusable: `west` cannot resolve the `import: true` of
zephyr's west.yml (`manifest-rev` refs do not exist; running `west update`
would mutate the shared cache clones). The host's actual west workspace is
`/mnt/lichen-zephyr/work/.west` (manifest = zephyr @ HEAD). Removing the
worktree's nested `.west` lets `west` climb to the host workspace, matching the
documented `cd <worktree> && west build ...` flow and the pattern used by every
other functioning worktree on this host (none have `.west`). Module isolation
is still guaranteed by `-DZEPHYR_EXTRA_MODULES=<worktree>/lichen` and checked
by the script's `verify` command.

## Verification

1. Build (host is aarch64; `native_posix/native/64` is the 64-bit qualifier
   for the native_posix board in Zephyr 3.7):

   ```
   cd /mnt/lichen-zephyr/work/project-LICHEN-ble-posix-validate
   . /mnt/lichen-zephyr/env.sh
   west build -b native_posix/native/64 lichen/tests/ble_ingress \
     -d build/ble_ingress_native_posix --pristine -- \
     -DZEPHYR_EXTRA_MODULES=$PWD/lichen
   ```

   Exit code: 0. Artifact: `build/ble_ingress_native_posix/zephyr/zephyr.elf`
   sha256: `1f919a04a950b8ce73195d92a82c29be7b36c96ee70ec487125860329d662d69`

2. Module isolation:

   ```
   tools/zephyr-clean-worktree.sh verify $PWD build/ble_ingress_native_posix
   ```

   Output: `Verified LICHEN module isolation in
   .../build/ble_ingress_native_posix/zephyr_modules.txt`
   (`"lichen":"/mnt/lichen-zephyr/work/project-LICHEN-ble-posix-validate/lichen"`,
   no references to the dirty cache workspace).

3. Runtime test:

   ```
   ./build/ble_ingress_native_posix/zephyr/zephyr.exe
   ```

   `SUITE PASS - 100.00% [ble_ingress]: pass = 4, fail = 0, skip = 0`
   (`PROJECT EXECUTION SUCCESSFUL`; the post-summary `stack smashing detected`
   on process teardown is a pre-existing native_posix host quirk, after all
   tests passed).

Status: worktree ready for BLE ingress native_posix validation.
