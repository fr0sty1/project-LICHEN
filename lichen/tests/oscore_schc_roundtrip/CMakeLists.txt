# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(oscore_schc_roundtrip)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(VECTOR_JSON ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/oscore_schc_roundtrip.json)
set(VECTOR_HEADER ${CMAKE_CURRENT_BINARY_DIR}/oscore_schc_vectors.h)
execute_process(
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/generate_vectors.py
          ${VECTOR_JSON} ${VECTOR_HEADER}
  RESULT_VARIABLE GENERATE_RESULT
)
if(NOT GENERATE_RESULT EQUAL 0)
  message(FATAL_ERROR "failed to generate OSCORE/SCHC vector fixture")
endif()

target_sources(app PRIVATE src/main.c)
target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/schc
)
