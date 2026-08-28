# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(schc_rule5_compress_test C)

include(../cmake/test_common.cmake)

add_executable(schc_rule5_compress_test
  main.c
  ../../subsys/schc/bitstream.c
  ../../subsys/schc/schc.c
  ../../subsys/lichen/schc/schc.c
  ../../subsys/lichen/schc/schc_checksum.c
  ../../subsys/lichen/schc/schc_compress.c
  ../../subsys/lichen/schc/schc_decompress.c
  ../../subsys/lichen/schc/schc_helpers.c
)
target_include_directories(schc_rule5_compress_test PRIVATE
  ../../subsys/schc/include
  ../../subsys/lichen/schc/include
  ../../subsys/lichen/schc
)
lichen_test_target(schc_rule5_compress_test)
target_compile_options(schc_rule5_compress_test PRIVATE
  -Wno-error=implicit-int-conversion
)

enable_testing()
add_test(NAME schc_rule5_compress_test COMMAND schc_rule5_compress_test)
