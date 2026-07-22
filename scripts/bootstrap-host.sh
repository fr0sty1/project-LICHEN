#!/bin/bash
# Bootstrap LICHEN Zephyr builder host packages on fresh Amazon Linux 2023
# Installs git and dev tools needed for west, CMake, Twister, etc.
# Idempotent; run only if packages are missing per AGENTS.md.
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

set -euo pipefail

echo "=== LICHEN Zephyr Builder Bootstrap (Amazon Linux 2023) ==="

dnf update -y --refresh

dnf install -y \
    git \
    cmake \
    ninja-build \
    meson \
    gcc \
    gcc-c++ \
    python3 \
    python3-pip \
    python3-devel \
    dtc \
    ccache \
    gperf \
    xz \
    which \
    jq \
    ripgrep \
    tree \
    htop \
    tmux \
    picocom \
    minicom \
    socat \
    nmap-ncat \
    usbutils \
    pciutils \
    lcov \
    gcovr \
    valgrind \
    ShellCheck \
    awscli-2 \
    gh

# Ensure west is available (plus Zephyr Twister deps like pykwalify)
if ! command -v west >/dev/null 2>&1; then
    python3 -m pip install --user --upgrade pip setuptools wheel
    python3 -m pip install --user west pykwalify pyyaml intelhex
fi

# Setup ccache symlink if missing
if [ ! -x /usr/local/bin/ccache ] && [ -x /usr/bin/ccache ]; then
    ln -sf /usr/bin/ccache /usr/local/bin/ccache
fi

echo "Bootstrap complete. Source the environment with:"
echo "  . /mnt/lichen-zephyr/env.sh"
echo "Then cd to the worktree and run west commands."
