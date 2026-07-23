<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# EC2 Zephyr Clean Worktrees

Use `tools/zephyr-clean-worktree.sh` for EC2 Zephyr validation when the
prepared EBS primary workspace may be dirty. The helper creates a detached Git
worktree, links the cached Zephyr checkout and west modules, writes the local
`.west/config`, and verifies that the LICHEN Zephyr module resolves through the
clean worktree under test.

## Workflow

```bash
. /mnt/lichen-zephyr/env.sh
cd /mnt/lichen-zephyr/work/project-LICHEN

tools/zephyr-clean-worktree.sh create project-LICHEN-validate origin/main
cd /mnt/lichen-zephyr/work/project-LICHEN-validate

# Optional: apply the patch being validated.
# git apply /tmp/change.patch

west build -b native_sim lichen/tests/link_crypto \
  -d build/link_crypto --pristine -- \
  -DZEPHYR_EXTRA_MODULES="$PWD/lichen"
west build -d build/link_crypto -t run

tools/zephyr-clean-worktree.sh verify "$PWD" build/link_crypto
```

The `link_crypto` native_sim build is the required Zephyr verification for C
link framing changes. It is not available in the macOS worktree; run the
commands above on the prepared EC2 Zephyr workspace and record the build/run
result with the change.

For Twister, pass the same module path:

```bash
west twister -T lichen/tests/link_crypto -p native_sim \
  --outdir twister-out-link-crypto \
  --extra-args ZEPHYR_EXTRA_MODULES="$PWD/lichen"
tools/zephyr-clean-worktree.sh verify-twister "$PWD" twister-out-link-crypto
```

## MeshCore BLE native/64-bit Validation

MeshCore BLE, meshcore_adapter, and related tests require `native_sim/native/64` (32-bit native_sim fails to link BLE HCI device ordinal). Full sequence combining EC2 mount (AGENTS.md), script help, and meshcore-smoke-test:

```bash
# EC2 mount and env setup (from AGENTS.md AWS Zephyr Builder section)
aws ec2 attach-volume --profile personal --region us-west-2 \
  --volume-id vol-0a95eee8d1d8461eb --instance-id <instance-id> --device /dev/sdf

sudo /mnt/lichen-zephyr/scripts/mount-volume.sh vol-0a95eee8d1d8461eb /mnt/lichen-zephyr
/mnt/lichen-zephyr/scripts/bootstrap-host.sh  # idempotent
. /mnt/lichen-zephyr/env.sh
cd /mnt/lichen-zephyr/work/project-LICHEN

# Create isolated clean worktree (exact from zephyr-clean-worktree.sh --help)
tools/zephyr-clean-worktree.sh create project-LICHEN-meshcore-ble-validate origin/main
cd /mnt/lichen-zephyr/work/project-LICHEN-meshcore-ble-validate
# git apply /tmp/change.patch  # if validating uncommitted changes

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

Record full command output, west manifest, Zephyr version, hashes, and verification result in validation beads. Cleanup: `git -C /mnt/lichen-zephyr/work/project-LICHEN worktree remove --force /mnt/lichen-zephyr/work/project-LICHEN-meshcore-ble-validate` (do not commit twister-out/).

### Evidence Capture (required for every validation run)

Every MeshCore BLE validation run — pass or fail — must capture complete
evidence. Use a runner script so the full output, both exit codes, and the
environment provenance land in one master log:

```bash
cd /mnt/lichen-zephyr/work/project-LICHEN-meshcore-ble-validate
. /mnt/lichen-zephyr/env.sh
BEAD=<bead-id-suffix>   # e.g. 2auf.59.4.1.3.2.1.3
{
  echo "Date(UTC): $(date -u)"; echo "Host: $(hostname) ($(uname -m))"
  echo "Git HEAD: $(git rev-parse HEAD)"
  west --version; grep -E 'VERSION_(MAJOR|MINOR|PATCHLEVEL)' zephyr/VERSION
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
  echo "twister exit code: $?"
  tools/zephyr-clean-worktree.sh verify-twister "$PWD" twister-out-meshcore-ble
  echo "verify-twister exit code: $?"
} > "validation-$BEAD.log" 2>&1
```

Then record results and hashes:

```bash
# Per-suite results from the machine-readable report
python3 - <<'PY'
import json
with open("twister-out-meshcore-ble/twister.json") as f:
    d = json.load(f)
for s in d["testsuites"]:
    n = {}
    for tc in s["testcases"]:
        n[tc["status"]] = n.get(tc["status"], 0) + 1
    print(s["name"], n)
PY

# SHA256 of binaries (when produced) and of all logs/reports
sha256sum twister-out-meshcore-ble/native_sim_native_64/*/zephyr/zephyr.elf \
          twister-out-meshcore-ble/native_sim_native_64/*/zephyr/zephyr.exe 2>/dev/null
sha256sum "validation-$BEAD.log" twister-out-meshcore-ble/twister.log \
          twister-out-meshcore-ble/twister.json \
          twister-out-meshcore-ble/native_sim_native_64/*/build.log
```

Commit the evidence at the repository root with the fix commit, using the
established naming convention:

| File | Content |
|------|---------|
| `build-logs-<bead-id>.log` | The complete master log (command output, both exit codes, environment). |
| `build-exit-<bead-id>.txt` | `twister=<code>` and `verify-twister=<code>`. |
| `artifacts-<bead-id>.txt` | Command, ref, host, per-suite results, and SHA256 sums of binaries (or "NOT PRODUCED" when the run fails before link) and of every log/report. |
| `build-provenance-<bead-id>.md` | Narrative: worktree path, ref, environment, commands, exit codes, results table, failure signature, and cross-references to related beads. |

A failing run is still valid evidence: record the failure signature (for
example the first `CMake Error`/`Dependency loop` lines from a suite
`build.log`) verbatim. Never rerun with weakened flags to force a pass. The
reference example is bead `project-LICHEN-2auf.59.4.1.3.2.1.3`.

## Why This Matters

The EBS cache keeps `/mnt/lichen-zephyr/work/project-LICHEN` as the primary west
workspace. That tree may intentionally be dirty with cached modules, old build
outputs, or in-progress validation state. A clean Git worktree alone is not
enough: without local Zephyr metadata and an explicit `ZEPHYR_EXTRA_MODULES`
path, CMake can resolve the `lichen` Zephyr module through the dirty primary
workspace.

The verification step reads `zephyr_modules.txt` from the build directory and
fails if the `lichen` module points at the primary cache workspace instead of
the clean worktree.

## Cleanup

Remove temporary worktrees through Git so the primary workspace does not retain
stale worktree records:

```bash
git -C /mnt/lichen-zephyr/work/project-LICHEN worktree remove --force \
  /mnt/lichen-zephyr/work/project-LICHEN-validate
```

Do not commit `twister-out/` or other generated build directories.

## Native/64-bit MeshCore BLE + BLE Ingress Validation (project-LICHEN-2auf.59.4.1.3.2.1)

For non-link MeshCore rows and BLE ingress on native_sim/native/64 (64-bit) with full logging:

```bash
. /mnt/lichen-zephyr/env.sh
cd /mnt/lichen-zephyr/work/project-LICHEN
tools/zephyr-clean-worktree.sh create project-LICHEN-meshcore-ble-validate origin/main
cd /mnt/lichen-zephyr/work/project-LICHEN-meshcore-ble-validate
# git apply patch if validating uncommitted changes
west twister \
  -T lichen/tests/ble_ingress \
  -T lichen/tests/meshcore_ble \
  -T lichen/tests/meshcore_adapter \
  -T lichen/tests/meshcore_codec \
  -p native_sim/native/64 \
  --inline-logs \
  --outdir twister-out-meshcore-ble-validation \
  --extra-args ZEPHYR_EXTRA_MODULES=$PWD/lichen
tools/zephyr-clean-worktree.sh verify-twister "$PWD" twister-out-meshcore-ble-validation
```

Use the same pattern for native_posix if supported. Always verify clean worktree resolution. Do not commit generated outputs.
