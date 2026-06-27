# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# Trickle timer unit tests - standalone build

cmake_minimum_required(VERSION 3.20)
project(trickle_test C)

# Include paths
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/include
)

# Build test executable
add_executable(trickle_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/trickle.c
)

# Enable warnings
target_compile_options(trickle_test PRIVATE -Wall -Wextra -Werror)
