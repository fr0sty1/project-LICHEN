# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# SenML unit tests - standalone build

cmake_minimum_required(VERSION 3.20)
project(senml_test C)

# Include paths
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/senml/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

# zcbor stubs for standalone test (Zephyr provides these in full builds)
set(ZCBOR_STUB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/zcbor_stub)
include_directories(${ZCBOR_STUB_DIR})

# Build test executable
add_executable(senml_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/senml/senml.c
  ${ZCBOR_STUB_DIR}/zcbor_encode.c
)

# Enable warnings
target_compile_options(senml_test PRIVATE -Wall -Wextra -Werror)
