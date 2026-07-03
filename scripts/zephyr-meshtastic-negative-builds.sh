#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/build/meshtastic-negative}"
BOARD="${BOARD:-native_sim}"
EXTRA_MODULES="${ZEPHYR_EXTRA_MODULES:-$ROOT_DIR/lichen}"

run_negative_build() {
	local name="$1"
	local expected="$2"
	shift 2

	local build_dir="$OUT_DIR/$name"
	local log_file="$build_dir/build.log"
	local conf_file="$build_dir/negative.conf"

	rm -rf "$build_dir"
	mkdir -p "$build_dir"
	printf '%s\n' "$@" >"$conf_file"

	set +e
	west build -p always -b "$BOARD" \
		"$ROOT_DIR/lichen/tests/meshtastic_gateway_adapter" \
		-d "$build_dir" -- \
		-DZEPHYR_EXTRA_MODULES="$EXTRA_MODULES" \
		-DEXTRA_CONF_FILE="$conf_file" >"$log_file" 2>&1
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

run_negative_build "app-interface-payload-drift" \
	"CONFIG_LICHEN_APP_INTERFACE_MAX_PAYLOAD must match LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX" \
	"CONFIG_LICHEN_APP_INTERFACE_MAX_PAYLOAD=199"

echo "Meshtastic negative build checks passed"
