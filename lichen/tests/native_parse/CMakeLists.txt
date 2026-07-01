# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(native_parse)

zephyr_compile_definitions(LICHEN_NATIVE_TEST_PARSE=1 LICHEN_NATIVE_TEST_TX=1)
target_sources(app PRIVATE src/main.c)
