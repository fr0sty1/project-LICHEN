# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# Trickle timer unit tests - standalone build

cmake_minimum_required(VERSION 3.20)
project(trickle_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

# Include paths
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/include
)

# Build test executable
add_executable(trickle_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/trickle.c
)

lichen_test_target(trickle_test)

enable_testing()
add_test(NAME trickle_test COMMAND trickle_test)
