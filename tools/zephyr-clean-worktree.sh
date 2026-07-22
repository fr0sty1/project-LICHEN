#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# SPDX-FileCopyrightText: The contributors to the LICHEN project

set -euo pipefail

DEFAULT_CACHE_WORKSPACE="/mnt/lichen-zephyr/work/project-LICHEN"
DEFAULT_WORK_ROOT="/mnt/lichen-zephyr/work"

usage() {
	cat <<'USAGE'
Usage:
  tools/zephyr-clean-worktree.sh create <name-or-path> [ref]
  tools/zephyr-clean-worktree.sh setup <worktree>
  tools/zephyr-clean-worktree.sh verify <worktree> <build-dir>
  tools/zephyr-clean-worktree.sh verify-twister <worktree> <twister-out-dir>

Create an isolated LICHEN Git worktree for EC2 Zephyr validation while reusing
the prepared EBS Zephyr checkout and west modules. This keeps the dirty primary
cache workspace untouched and makes the LICHEN Zephyr module resolve to the
clean worktree under test.

Environment:
  LICHEN_ZEPHYR_CACHE_WORKSPACE  default: /mnt/lichen-zephyr/work/project-LICHEN
  LICHEN_ZEPHYR_WORK_ROOT        default: /mnt/lichen-zephyr/work
  LICHEN_CLEAN_WORKTREE_REPLACE  set to 1 to remove an existing destination

Example:
  tools/zephyr-clean-worktree.sh create project-LICHEN-validate origin/main
  cd /mnt/lichen-zephyr/work/project-LICHEN-validate
  # git apply /tmp/change.patch
  . /mnt/lichen-zephyr/env.sh
  west build -b native_sim lichen/tests/link_crypto -d build/link_crypto --pristine -- \
    -DZEPHYR_EXTRA_MODULES="$PWD/lichen"
  west build -d build/link_crypto -t run
  tools/zephyr-clean-worktree.sh verify "$PWD" build/link_crypto
USAGE
}

die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

abs_path() {
	local path=$1

	case "$path" in
		/*) printf '%s\n' "$path" ;;
		*) printf '%s/%s\n' "$PWD" "$path" ;;
	esac
}

normalize_abs_path() {
	local path=$1
	local old_ifs=$IFS
	local part
	local -a parts
	local -a normalized
	local result

	[ "${path#/}" != "$path" ] || die "path must be absolute: $path"
	IFS=/
	read -r -a parts <<< "$path"
	IFS=$old_ifs
	normalized=()
	for part in "${parts[@]}"; do
		case "$part" in
			''|.) ;;
			..)
				if [ "${#normalized[@]}" -gt 0 ]; then
					unset 'normalized[${#normalized[@]}-1]'
				fi
				;;
			*)
				normalized+=("$part")
				;;
		esac
	done

	result=/
	for part in "${normalized[@]}"; do
		if [ "$result" = / ]; then
			result="/$part"
		else
			result="$result/$part"
		fi
	done
	printf '%s\n' "$result"
}

canonical_path() {
	local path

	path=$(abs_path "$1")
	if [ -e "$path" ]; then
		(cd "$path" && pwd -P)
	else
		(cd "$(dirname "$path")" && printf '%s/%s\n' "$(pwd -P)" "$(basename "$path")")
	fi
}

cache_workspace() {
	canonical_path "${LICHEN_ZEPHYR_CACHE_WORKSPACE:-$DEFAULT_CACHE_WORKSPACE}"
}

work_root() {
	canonical_path "${LICHEN_ZEPHYR_WORK_ROOT:-$DEFAULT_WORK_ROOT}"
}

resolve_worktree() {
	local requested=$1

	case "$requested" in
		/*) printf '%s\n' "$requested" ;;
		*) printf '%s/%s\n' "$(work_root)" "$requested" ;;
	esac
}

path_is_under_work_root() {
	local path=$1
	local root=$2

	case "$path" in
		"$root"/*) return 0 ;;
		*) return 1 ;;
	esac
}

path_is_under() {
	local path=$1
	local root=$2

	case "$path" in
		"$root"/*) return 0 ;;
		*) return 1 ;;
	esac
}

canonical_destination() {
	local path
	local parent
	local parent_base
	local missing_suffix
	local root

	path=$(normalize_abs_path "$(abs_path "$1")")
	parent=$(dirname "$path")
	root=$(work_root)
	case "$parent" in
		"$root"|"$root"/*) ;;
		*) die "destination parent must be under $root" ;;
	esac

	parent_base=$parent
	missing_suffix=
	while [ ! -e "$parent_base" ]; do
		missing_suffix="/$(basename "$parent_base")$missing_suffix"
		parent_base=$(dirname "$parent_base")
	done
	parent_base=$(canonical_path "$parent_base")
	case "$parent_base" in
		"$root"|"$root"/*) ;;
		*) die "destination parent must resolve under $root" ;;
	esac
	mkdir -p "$parent_base$missing_suffix"
	canonical_path "$path"
}

validate_destination() {
	local dest=$1
	local cache=$2

	[ "$dest" != "$cache" ] || die "destination must not be the primary cache workspace"
	! path_is_under "$dest" "$cache" ||
		die "destination must not be inside the primary cache workspace"
	path_is_under_work_root "$dest" "$(work_root)" ||
		die "destination must be under $(work_root)"
}

write_west_config() {
	local dest=$1

	mkdir -p "$dest/.west"
	cat > "$dest/.west/config" <<'CONFIG'
[manifest]
path = lichen
file = west.yml

[zephyr]
base = zephyr
CONFIG
}

link_cached_path() {
	local cache=$1
	local dest=$2
	local name=$3
	local source="$cache/$name"
	local target="$dest/$name"

	[ -e "$source" ] || return 0
	if [ -L "$target" ]; then
		ln -sfn "$source" "$target"
	elif [ -e "$target" ]; then
		die "$target exists and is not a symlink; refusing to replace it"
	else
		ln -s "$source" "$target"
	fi
}

ensure_loramac_lr1110_submodule() {
	local cache=$1
	local loramac="$cache/modules/lib/loramac-node"
	local lr1110_path="src/radio/lr1110/lr1110_driver"
	local required="$loramac/$lr1110_path/src/lr1110_radio.c"

	[ -d "$loramac/.git" ] || [ -f "$loramac/.git" ] || return 0
	[ -f "$loramac/.gitmodules" ] || return 0
	if [ -f "$required" ]; then
		return 0
	fi

	printf 'Initializing loramac-node LR1110 driver submodule in cache...\n'
	git -C "$loramac" submodule update --init --recursive "$lr1110_path"
	[ -f "$required" ] ||
		die "loramac-node LR1110 driver submodule did not provide $required"
}

setup_worktree() {
	local dest
	local cache

	dest=$(abs_path "$1")
	cache=$(cache_workspace)
	dest=$(canonical_path "$dest")

	[ -d "$dest/.git" ] || [ -f "$dest/.git" ] || die "$dest is not a Git worktree"
	[ -d "$cache/zephyr" ] || die "$cache/zephyr is missing"
	validate_destination "$dest" "$cache"

	write_west_config "$dest"
	link_cached_path "$cache" "$dest" zephyr
	link_cached_path "$cache" "$dest" modules
	link_cached_path "$cache" "$dest" bootloader
	ensure_loramac_lr1110_submodule "$cache"

	printf 'Prepared clean Zephyr worktree: %s\n' "$dest"
	printf 'Use: -DZEPHYR_EXTRA_MODULES=%s/lichen\n' "$dest"
}

create_worktree() {
	local requested=$1
	local ref=${2:-HEAD}
	local dest
	local cache

	cache=$(cache_workspace)
	dest=$(resolve_worktree "$requested")
	dest=$(canonical_destination "$dest")

	[ -d "$cache/.git" ] || [ -f "$cache/.git" ] || die "$cache is not a Git workspace"
	validate_destination "$dest" "$cache"

	if [ -e "$dest" ]; then
		if [ "${LICHEN_CLEAN_WORKTREE_REPLACE:-0}" = "1" ]; then
			git -C "$cache" worktree remove --force "$dest" ||
				die "failed to remove existing Git worktree $dest"
		else
			die "$dest already exists; set LICHEN_CLEAN_WORKTREE_REPLACE=1 to replace it"
		fi
	fi

	git -C "$cache" worktree add --detach "$dest" "$ref"
	setup_worktree "$dest"
}

verify_worktree() {
	local dest
	local build_dir
	local modules_file
	local kconfig_modules
	local kconfig_sources
	local settings_file
	local build_ninja
	local compile_commands
	local cache
	local expected
	local forbidden

	dest=$(resolve_worktree "$1")
	dest=$(canonical_path "$dest")
	build_dir=$(canonical_path "$2")
	modules_file="$build_dir/zephyr_modules.txt"
	kconfig_modules="$build_dir/Kconfig/Kconfig.modules"
	kconfig_sources="$build_dir/zephyr/kconfig/sources.txt"
	settings_file="$build_dir/zephyr_settings.txt"
	build_ninja="$build_dir/build.ninja"
	compile_commands="$build_dir/compile_commands.json"
	cache=$(cache_workspace)
	expected="\"lichen\":\"$dest/lichen\":"
	forbidden="$cache/lichen"

	[ -f "$modules_file" ] || die "$modules_file does not exist; run a Zephyr build first"
	if ! grep -Fq "$expected" "$modules_file"; then
		die "LICHEN module did not resolve to clean worktree ($expected)"
	fi
	if grep -Fq "$forbidden" "$modules_file"; then
		die "LICHEN module resolved through dirty cache workspace in $modules_file"
	fi

	if [ -f "$kconfig_modules" ]; then
		grep -Fq "menu \"lichen ($dest/lichen)\"" "$kconfig_modules" ||
			die "Kconfig module menu does not use $dest/lichen"
		if grep -Fq "$forbidden" "$kconfig_modules"; then
			die "Kconfig modules reference dirty cache LICHEN path"
		fi
	fi

	if [ -f "$kconfig_sources" ]; then
		grep -Fq "$dest/lichen/" "$kconfig_sources" ||
			die "Kconfig sources do not reference $dest/lichen"
		if grep -Fq "$forbidden" "$kconfig_sources"; then
			die "Kconfig sources reference dirty cache LICHEN path"
		fi
	fi

	if [ -f "$settings_file" ]; then
		grep -Fq "\"BOARD_ROOT\":\"$dest/lichen\"" "$settings_file" ||
			die "BOARD_ROOT does not include $dest/lichen"
		grep -Fq "\"DTS_ROOT\":\"$dest/lichen\"" "$settings_file" ||
			die "DTS_ROOT does not include $dest/lichen"
		if grep -Fq "$forbidden" "$settings_file"; then
			die "Zephyr settings reference dirty cache LICHEN path"
		fi
	fi

	if [ -f "$build_ninja" ]; then
		grep -Fq "$dest/lichen" "$build_ninja" ||
			die "build.ninja does not reference $dest/lichen"
		if grep -Fq "$forbidden" "$build_ninja"; then
			die "build.ninja references dirty cache LICHEN path"
		fi
	fi

	if [ -f "$compile_commands" ]; then
		grep -Fq "$dest/lichen" "$compile_commands" ||
			die "compile_commands.json does not reference $dest/lichen"
		if grep -Fq "$forbidden" "$compile_commands"; then
			die "compile_commands.json references dirty cache LICHEN path"
		fi
	fi

	printf 'Verified LICHEN module isolation in %s\n' "$modules_file"
}

verify_twister() {
	local dest
	local outdir
	local plan_file
	local expected_file
	local expected_list
	local found=0

	dest=$(canonical_path "$1")
	outdir=$(canonical_path "$2")
	plan_file="$outdir/testplan.json"

	[ -d "$outdir" ] || die "$outdir does not exist"
	[ -f "$plan_file" ] || die "$plan_file does not exist"
	expected_list=$(mktemp)
	python3 - "$outdir" "$plan_file" >"$expected_list" <<'PY'
import json
import glob
import os
import sys

outdir, plan_file = sys.argv[1:3]
with open(plan_file, encoding="utf-8") as f:
    plan = json.load(f)
for suite in plan.get("testsuites", []):
    if not suite.get("runnable", True):
        continue
    platform = suite.get("platform")
    name = suite.get("name")
    if not platform or not name:
        raise SystemExit(f"runnable Twister suite missing platform/name: {suite!r}")
    platform = platform.replace("/", "_")
    exact = os.path.join(outdir, platform, name, "zephyr_modules.txt")
    if os.path.exists(exact):
        print(exact)
        continue
    matches = sorted(
        glob.glob(os.path.join(outdir, platform, "**", name, "zephyr_modules.txt"),
                  recursive=True)
    )
    if matches:
        print(matches[0])
    else:
        print(exact)
PY
	while IFS= read -r expected_file; do
		found=1
		[ -f "$expected_file" ] ||
			die "missing Twister build metadata $expected_file"
		verify_worktree "$dest" "$(dirname "$expected_file")"
	done < "$expected_list"
	rm -f "$expected_list"
	[ "$found" -eq 1 ] || die "no runnable Twister scenarios found in $plan_file"
}

main() {
	local cmd=${1:-}

	case "$cmd" in
		create)
			[ $# -ge 2 ] || { usage >&2; exit 2; }
			create_worktree "$2" "${3:-HEAD}"
			;;
		setup)
			[ $# -eq 2 ] || { usage >&2; exit 2; }
			setup_worktree "$2"
			;;
		verify)
			[ $# -eq 3 ] || { usage >&2; exit 2; }
			verify_worktree "$2" "$3"
			;;
		verify-twister)
			[ $# -eq 3 ] || { usage >&2; exit 2; }
			verify_twister "$2" "$3"
			;;
		-h|--help|help)
			usage
			;;
		*)
			usage >&2
			exit 2
			;;
	esac
}

main "$@"
