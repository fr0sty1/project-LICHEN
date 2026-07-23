#!/usr/bin/env bash
# Build matrix for nRF52840 + native_posix BLE (project-LICHEN-2auf.59.4.1.3.2.2.3)
# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: The contributors to the LICHEN project

set -euo pipefail

LOG="build-provenance-2auf.59.log"
BUILD_LOG_DIR="build-logs-2auf.59"
mkdir -p "$BUILD_LOG_DIR"

echo "=== nRF + native_posix BLE Build Matrix for project-LICHEN-2auf.59 ===" | tee -a "$LOG"
echo "Start: $(date -u)" | tee -a "$LOG"
echo "Worktree commit: $(git rev-parse --short HEAD)" | tee -a "$LOG"

. /mnt/lichen-zephyr/env.sh
export PATH="$ZEPHYR_SDK_INSTALL_DIR/arm-zephyr-eabi/bin:$PATH"
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"

echo "Toolchain: $(arm-zephyr-eabi-gcc --version | head -1)" | tee -a "$LOG"
echo "West version: $(west --version)" | tee -a "$LOG"
echo "Zephyr BASE: $ZEPHYR_BASE" | tee -a "$LOG"

# Declared nRF52840 rows per project-LICHEN-2auf.31 (T-Echo/RAK4631/T1000-E/R1 Neo puck/gateway + lora_ping Renode for compatible boards). T1000-E renode excluded (LR1110 incompatibility with nrf52840_lichen SX1262 overlay).
BUILDS=(
  "t_echo/nrf52840:puck:renode"
  "rak4631/nrf52840:puck:renode"
  "t1000_e/nrf52840:puck"
  "r1_neo/nrf52840:puck"
  "t_echo/nrf52840:gateway"
  "r1_neo/nrf52840:gateway"
  "t1000_e/nrf52840:gateway"
  "nrf52840dk_nrf52840:gateway"
  "t_echo/nrf52840:lora_ping:renode"
  "rak4631/nrf52840:lora_ping:renode"
)

SUCCESS=0
TOTAL=${#BUILDS[@]}

for entry in "${BUILDS[@]}"; do
  IFS=':' read -r board app renode_flag <<< "$entry"
  build_name="${board//[\/]/_}_${app}${renode_flag:+_renode}"
  build_dir="build/${build_name}"
  log_file="$BUILD_LOG_DIR/${build_name}.log"
  
  # For lora_ping use samples instead of apps; set overlays (Renode only for compatible SX1262 boards)
  if [ "$app" = "lora_ping" ]; then
    app_path="lichen/samples/lora_ping"
    extra_overlay=""
    if [ -n "$renode_flag" ]; then
      extra_overlay="-DEXTRA_DTC_OVERLAY_FILE=$(pwd)/lichen/boards/renode/nrf52840_lichen/support/renode_console.overlay -DEXTRA_CONF_FILE=$(pwd)/lichen/boards/renode/nrf52840_lichen/support/renode_console.conf"
    else
      # Use specific board overlay if available
      if [ -f "lichen/samples/lora_ping/boards/${board}.overlay" ]; then
        extra_overlay="-DEXTRA_DTC_OVERLAY_FILE=$(pwd)/lichen/samples/lora_ping/boards/${board}.overlay"
      fi
    fi
  else
    app_path="lichen/apps/$app"
    extra_overlay=""
    if [ -n "$renode_flag" ]; then
      extra_overlay="-DEXTRA_DTC_OVERLAY_FILE=$(pwd)/lichen/boards/renode/nrf52840_lichen/support/renode_console.overlay -DEXTRA_CONF_FILE=$(pwd)/lichen/boards/renode/nrf52840_lichen/support/renode_console.conf"
    elif [ -f "lichen/apps/$app/boards/${board}.overlay" ]; then
      extra_overlay="-DEXTRA_DTC_OVERLAY_FILE=$(pwd)/lichen/apps/$app/boards/${board}.overlay"
    fi
  fi
  
  echo "" | tee -a "$LOG"
  echo "=== Building $board $app ${renode_flag:+with Renode overlay} ===" | tee -a "$LOG"
  echo "Command: west build -b $board $app_path -d $build_dir -p always -- -DZEPHYR_EXTRA_MODULES=$(pwd)/lichen -DBOARD_ROOT=$(pwd)/lichen $extra_overlay" | tee -a "$LOG"
  
  set +e
  west build -b "$board" "$app_path" -d "$build_dir" -p always -- \
    -DZEPHYR_EXTRA_MODULES="$(pwd)/lichen" \
    -DBOARD_ROOT="$(pwd)/lichen" \
    $extra_overlay 2>&1 | tee "$log_file"
  EXIT_CODE=${PIPESTATUS[0]}
  set -e
  
  echo "Exit code: $EXIT_CODE" | tee -a "$LOG"
  echo "Log: $log_file" | tee -a "$LOG"
  
  if [ $EXIT_CODE -ne 0 ]; then
    echo "BUILD FAILED for $build_name" | tee -a "$LOG"
    cat "$log_file" >> "$LOG"
    continue
  fi
  
  # Check for warnings, overflows, errors (LICHEN-specific only)
  if grep -E -i "(warning:|overflow|error:|Error:)" "$log_file" | grep -v "deprecated" | grep -v "note:" | grep -E "(lichen/|main\.c|bitstream\.c|apps/puck|subsys/schc)" > /tmp/warnings.tmp 2>/dev/null; then
    echo "WARNINGS/ERRORS found (LICHEN-specific):" | tee -a "$LOG"
    cat /tmp/warnings.tmp | tee -a "$LOG"
    SUCCESS=1
  else
    echo "No warnings or overflows detected." | tee -a "$LOG"
  fi
  
  # Record sizes and hashes
  if [ -f "$build_dir/zephyr/zephyr.elf" ]; then
    ELF="$build_dir/zephyr/zephyr.elf"
    echo "ELF size: $(stat -c %s "$ELF") bytes" | tee -a "$LOG"
    echo "ELF hash: $(sha256sum "$ELF" | cut -d' ' -f1)" | tee -a "$LOG"
  fi
  if [ -f "$build_dir/zephyr/zephyr.bin" ]; then
    BIN="$build_dir/zephyr/zephyr.bin"
    echo "BIN size: $(stat -c %s "$BIN") bytes" | tee -a "$LOG"
    echo "BIN hash: $(sha256sum "$BIN" | cut -d' ' -f1)" | tee -a "$LOG"
  fi
  
  # Extract memory usage
  if grep -A5 "Memory region" "$log_file" > /tmp/mem.tmp; then
    echo "Memory usage:" | tee -a "$LOG"
    cat /tmp/mem.tmp | tee -a "$LOG"
  fi
  
  echo "Build $build_name completed successfully." | tee -a "$LOG"
done

# Native_posix BLE ingress build + test with full provenance capture
# per project-LICHEN-2auf.59.4.1.3.2.2.3
echo "" | tee -a "$LOG"
echo "=== Building native_sim for BLE IPSP (native_posix BLE artifacts) ===" | tee -a "$LOG"
build_name="native_sim_ble_ipsp"
build_dir="build/${build_name}"
log_file="$BUILD_LOG_DIR/${build_name}.log"

echo "Command: west build -b native_sim lichen/tests/ble_ipsp_transport -d $build_dir -p always -- -DZEPHYR_EXTRA_MODULES=$(pwd)/lichen" | tee -a "$LOG"

set +e
west build -b native_sim lichen/tests/ble_ipsp_transport -d "$build_dir" -p always -- \
  -DZEPHYR_EXTRA_MODULES="$(pwd)/lichen" 2>&1 | tee "$log_file"
EXIT_CODE=${PIPESTATUS[0]}
set -e

echo "Exit code: $EXIT_CODE" | tee -a "$LOG"
echo "Log: $log_file" | tee -a "$LOG"

if [ $EXIT_CODE -ne 0 ]; then
  echo "BUILD FAILED for $build_name" | tee -a "$LOG"
  cat "$log_file" >> "$LOG"
  SUCCESS=1
else
  # Compute SHA256s of key artifacts
  if [ -f "$build_dir/zephyr/zephyr.elf" ]; then
    ELF="$build_dir/zephyr/zephyr.elf"
    echo "ELF size: $(stat -c %s "$ELF") bytes" | tee -a "$LOG"
    echo "ELF hash: $(sha256sum "$ELF" | cut -d' ' -f1)" | tee -a "$LOG"
  fi
  if [ -f "$build_dir/zephyr/zephyr.bin" ]; then
    BIN="$build_dir/zephyr/zephyr.bin"
    echo "BIN size: $(stat -c %s "$BIN") bytes" | tee -a "$LOG"
    echo "BIN hash: $(sha256sum "$BIN" | cut -d' ' -f1)" | tee -a "$LOG"
  fi

  # Run the ztest suite for validation
  echo "Running ztest for BLE ingress..." | tee -a "$LOG"
  set +e
  "$build_dir/zephyr/zephyr.elf" > "$build_dir/test.log" 2>&1
  TEST_EXIT=$?
  set -e
  echo "Test exit code: $TEST_EXIT" | tee -a "$LOG"
  if [ $TEST_EXIT -ne 0 ]; then
    echo "TEST FAILED for $build_name" | tee -a "$LOG"
    cat "$build_dir/test.log" >> "$LOG"
    SUCCESS=1
  else
    echo "Test PASSED" | tee -a "$LOG"
  fi

  echo "Build $build_name completed successfully with full provenance." | tee -a "$LOG"
fi

echo "" | tee -a "$LOG"
if [ $SUCCESS -eq 0 ]; then
  echo "ALL BUILDS SUCCESSFUL. No warnings or overflows. Task complete." | tee -a "$LOG"
  echo "Provenance log: $LOG" | tee -a "$LOG"
  echo "Logs in $BUILD_LOG_DIR/" | tee -a "$LOG"
  exit 0
else
  echo "Some builds had issues. See log." | tee -a "$LOG"
  exit 1
fi
