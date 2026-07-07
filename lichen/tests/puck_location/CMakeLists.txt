# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(puck_location)

target_include_directories(app PRIVATE
	../../apps/puck/src
	../../lib/native/include
)

target_sources(app PRIVATE
	src/main.c
	../../apps/puck/src/puck_location.c
)
