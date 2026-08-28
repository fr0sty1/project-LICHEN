# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(airtime)

set(LICHEN_HAL_DIR ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/hal)

target_sources(app PRIVATE
  src/main.c
  ${LICHEN_HAL_DIR}/hal_airtime.c
)
target_include_directories(app PRIVATE ${LICHEN_HAL_DIR}/include)
