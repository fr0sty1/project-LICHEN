# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(util)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/l2
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

target_sources(app PRIVATE
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/l2/lichen_util.c
  # lichen_hash_32 is defined in the link module (subsys/lichen/link/hash32.c),
  # which this test does not enable; compile it in directly.
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/hash32.c
)
