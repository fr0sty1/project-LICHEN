# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(app_identity)

# Zephyr 4.1's ztest-selected minimal logger expands valid LOG_* calls into
# GCC 12 macro branches that -Wduplicated-branches cannot distinguish.
zephyr_compile_options(-Wno-error=duplicated-branches)

target_sources(app PRIVATE src/main.c src/identity_store.c)
