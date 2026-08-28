# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# SCHC unit tests - standalone build

cmake_minimum_required(VERSION 3.20)
project(schc_test C)

include(../cmake/test_common.cmake)

add_executable(schc_test
  main.c
  ../../subsys/schc/bitstream.c
  ../../subsys/schc/schc.c
  ../../subsys/lichen/schc/schc.c
  ../../subsys/lichen/schc/schc_checksum.c
  ../../subsys/lichen/schc/schc_compress.c
  ../../subsys/lichen/schc/schc_decompress.c
  ../../subsys/lichen/schc/schc_helpers.c
)
target_include_directories(schc_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/schc/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/schc/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/schc
)
lichen_test_target(schc_test)

enable_testing()
add_test(NAME schc_test COMMAND schc_test)
