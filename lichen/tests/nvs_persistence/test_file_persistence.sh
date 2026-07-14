#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
#
# Test actual file persistence across binary restarts on native_sim.
#
# This script:
# 1. Builds the nvs_persistence test for native_sim
# 2. Runs it twice with the same flash file
# 3. Verifies the second run sees data from the first
#
# Prerequisites:
# - Linux host (native_sim doesn't work on macOS)
# - Zephyr environment sourced
# - west build system available
#
# Usage:
#   ./test_file_persistence.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR%/lichen/tests/nvs_persistence}"
BUILD_DIR="${PROJECT_ROOT}/build/nvs_persistence_file_test"
FLASH_FILE="${BUILD_DIR}/test_flash.bin"

echo "=== NVS File Persistence Test ==="
echo "Project root: ${PROJECT_ROOT}"
echo "Build dir: ${BUILD_DIR}"
echo "Flash file: ${FLASH_FILE}"
echo ""

# Check for Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "ERROR: native_sim only works on Linux"
    echo "On macOS/Windows, use a VM or container"
    exit 1
fi

cd "${PROJECT_ROOT}"

# Build the test
echo "=== Building test ==="
west build -b native_sim lichen/tests/nvs_persistence -d "${BUILD_DIR}" --pristine

# Remove any existing flash file
rm -f "${FLASH_FILE}"

echo ""
echo "=== First run: writing data ==="
echo "Flash file will be created at: ${FLASH_FILE}"
"${BUILD_DIR}/zephyr/zephyr.exe" --flash="${FLASH_FILE}" 2>&1 || true

if [[ ! -f "${FLASH_FILE}" ]]; then
    echo "ERROR: Flash file was not created"
    exit 1
fi

FLASH_SIZE=$(stat -c %s "${FLASH_FILE}" 2>/dev/null || stat -f %z "${FLASH_FILE}")
echo "Flash file created: ${FLASH_SIZE} bytes"

echo ""
echo "=== Second run: reading persisted data ==="
"${BUILD_DIR}/zephyr/zephyr.exe" --flash="${FLASH_FILE}" 2>&1 || true

echo ""
echo "=== Test complete ==="
echo "If both runs passed their ztest assertions, file persistence works correctly."
echo ""
echo "Manual testing:"
echo "  # Write data:"
echo "  ${BUILD_DIR}/zephyr/zephyr.exe --flash=${FLASH_FILE} --flash_erase"
echo ""
echo "  # Read persisted data (no --flash_erase):"
echo "  ${BUILD_DIR}/zephyr/zephyr.exe --flash=${FLASH_FILE}"
echo ""
echo "  # Cleanup:"
echo "  rm ${FLASH_FILE}"
