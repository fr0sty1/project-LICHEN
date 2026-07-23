# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(hal)

target_sources(app PRIVATE src/main.c)

if(CONFIG_FUEL_GAUGE)
  target_compile_options(app PRIVATE -Wno-error=sign-compare)
endif()
