# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(time_source_class)

set(LICHEN_LINK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link)

target_sources(app PRIVATE
  src/main.c
  ${LICHEN_LINK_DIR}/time_sync.c
)
target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${LICHEN_LINK_DIR}/include
)
target_compile_definitions(app PRIVATE
  CONFIG_LICHEN_CCP_TIME_SYNC=1
  CONFIG_LICHEN_LINK_LOG_LEVEL=0
  CONFIG_LICHEN_LINK_MAX_NEIGHBORS=16
  CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX=1700000000
  CONFIG_LICHEN_TIME_BUILD_EPOCH_SOURCE_FIXED=1
)
