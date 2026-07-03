#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/build/hal-negative}"
BOARD="${BOARD:-native_sim}"
EXTRA_MODULES="${ZEPHYR_EXTRA_MODULES:-$ROOT_DIR/lichen}"

run_negative_build() {
	local name="$1"
	local expected="$2"
	shift 2

	local build_dir="$OUT_DIR/$name"
	local log_file="$build_dir/build.log"
	local conf_file="$build_dir/negative.conf"
	local overlay_file="${OVERLAY_FILE:-}"

	rm -rf "$build_dir"
	mkdir -p "$build_dir"
	printf '%s\n' "$@" >"$conf_file"

	set +e
	local cmake_args=(
		-DZEPHYR_EXTRA_MODULES="$EXTRA_MODULES"
		-DEXTRA_CONF_FILE="$conf_file"
	)
	if [ -n "$overlay_file" ]; then
		cmake_args+=(-DDTC_OVERLAY_FILE="$overlay_file")
	fi

	west build -p always -b "$BOARD" "$ROOT_DIR/lichen/tests/hal" -d "$build_dir" -- \
		"${cmake_args[@]}" >"$log_file" 2>&1
	local status=$?
	set -e

	if [ "$status" -eq 0 ]; then
		echo "FAIL $name: build unexpectedly succeeded"
		return 1
	fi

	if ! grep -Fq "$expected" "$log_file"; then
		echo "FAIL $name: expected diagnostic not found: $expected"
		echo "Log: $log_file"
		return 1
	fi

	echo "PASS $name"
}

run_negative_build "lora-missing-chosen" \
	"CONFIG_LICHEN_HAS_LORA requires an okay chosen zephyr,lora" \
	"CONFIG_LORA=y" \
	"CONFIG_LORA_LOOPBACK=y" \
	"CONFIG_LICHEN_HAS_LORA=y"

run_negative_build "battery-missing-alias" \
	"CONFIG_LICHEN_HAS_BATTERY requires an okay battery0 alias" \
	"CONFIG_SENSOR=y" \
	"CONFIG_LICHEN_HAS_BATTERY=y"

OVERLAY_FILE="$ROOT_DIR/lichen/tests/hal/boards/native_sim_lora_loopback.overlay" \
	run_negative_build "radio-model-mismatch" \
	"LICHEN_RADIO_MODEL_SX126X requires chosen zephyr,lora to be semtech,sx1261 or semtech,sx1262" \
	"CONFIG_LORA=y" \
	"CONFIG_LORA_LOOPBACK=y" \
	"CONFIG_LICHEN_HAS_LORA=y" \
	"CONFIG_LICHEN_RADIO_MODEL_SX126X=y"

echo "HAL negative build checks passed"
