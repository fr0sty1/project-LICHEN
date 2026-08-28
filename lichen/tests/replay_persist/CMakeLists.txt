# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(replay_persist)

set(LICHEN_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
target_sources(app PRIVATE
  src/main.c
  ${LICHEN_ROOT}/subsys/lichen/link/replay.c
  ${LICHEN_ROOT}/subsys/lichen/link/replay_persist.c
  ${LICHEN_ROOT}/subsys/lichen/link/replay_settings.c
  ${LICHEN_ROOT}/subsys/lichen/crypto/monocypher.c
)
target_include_directories(app PRIVATE
  ${LICHEN_ROOT}/subsys/lichen/link/include
  ${LICHEN_ROOT}/subsys/lichen/crypto
)
target_compile_definitions(app PRIVATE CONFIG_LICHEN_LINK_MAX_NEIGHBORS=4)
