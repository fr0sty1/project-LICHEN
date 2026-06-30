# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# SCHC unit tests - standalone build

cmake_minimum_required(VERSION 3.20)
project(schc_test C)

# Include paths
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/schc/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/schc/include
)

# Build test executable
add_executable(schc_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/schc/bitstream.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/schc/schc.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/schc/schc.c
)

# Enable warnings
target_compile_options(schc_test PRIVATE -Wall -Wextra -Werror)
