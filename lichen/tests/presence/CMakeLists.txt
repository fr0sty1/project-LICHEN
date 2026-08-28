# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# Presence unit tests - standalone build

cmake_minimum_required(VERSION 3.20)
project(presence_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

# Include paths
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/coap/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

# Build test executable
add_executable(presence_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/coap/presence.c
)

lichen_test_target(presence_test)

include(CTest)
add_test(NAME presence COMMAND presence_test)
