# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(checkin_rollcall_test C)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(VECTORS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors)
set(GENERATED_VECTORS_H ${CMAKE_CURRENT_BINARY_DIR}/checkin_vectors.h)

add_custom_command(
  OUTPUT ${GENERATED_VECTORS_H}
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          --vectors-dir ${VECTORS_DIR}
          --output ${GENERATED_VECTORS_H}
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
    ${VECTORS_DIR}/checkin_rollcall.json
  VERBATIM
)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/coap/include
  ${CMAKE_CURRENT_BINARY_DIR}
)

add_executable(checkin_rollcall_test
  main.c
  ${GENERATED_VECTORS_H}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/coap/checkin.c
)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)
lichen_test_target(checkin_rollcall_test)

enable_testing()
add_test(NAME checkin_rollcall COMMAND checkin_rollcall_test)
