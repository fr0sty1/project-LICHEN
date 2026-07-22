# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(link_crypto)

target_sources(app PRIVATE src/main.c)

# Include LICHEN L2 directory for ipv6_addr.h (used by yggdrasil test vector)
target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/l2
)
