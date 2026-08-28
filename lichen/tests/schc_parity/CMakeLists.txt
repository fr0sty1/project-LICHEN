# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(schc_parity_test C)

include(../cmake/test_common.cmake)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(VECTORS_JSON ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/schc_compression.json)
set(VECTORS_HEADER ${CMAKE_CURRENT_BINARY_DIR}/schc_parity_vectors.h)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  ${VECTORS_JSON}
  ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
)
execute_process(
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          ${VECTORS_JSON} ${VECTORS_HEADER}
  RESULT_VARIABLE GENERATOR_RESULT
  ERROR_VARIABLE GENERATOR_ERROR
)
if(NOT GENERATOR_RESULT EQUAL 0)
  message(FATAL_ERROR "SCHC parity vector generation failed: ${GENERATOR_ERROR}")
endif()

add_executable(schc_parity_test
  main.c
  ../../subsys/schc/bitstream.c
  ../../subsys/schc/schc.c
  ../../subsys/lichen/schc/schc.c
  ../../subsys/lichen/schc/schc_checksum.c
  ../../subsys/lichen/schc/schc_compress.c
  ../../subsys/lichen/schc/schc_decompress.c
  ../../subsys/lichen/schc/schc_helpers.c
)
target_include_directories(schc_parity_test PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ../../subsys/schc/include
  ../../subsys/lichen/schc/include
  ../../subsys/lichen/schc
)
lichen_test_target(schc_parity_test)
target_compile_options(schc_parity_test PRIVATE -Wno-error=implicit-int-conversion)

enable_testing()
add_test(NAME schc_parity_test COMMAND schc_parity_test)
