# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(loadng_vectors_test C)

set(SEQ_JSON ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/loadng.json)
set(MSG_JSON ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/loadng_messages.json)
set(VECTOR_HDR ${CMAKE_CURRENT_BINARY_DIR}/loadng_vectors.h)

add_custom_command(
  OUTPUT ${VECTOR_HDR}
  COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/generate_vectors.py
          ${SEQ_JSON} ${MSG_JSON} ${VECTOR_HDR}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/generate_vectors.py ${SEQ_JSON} ${MSG_JSON}
  COMMENT "Generate loadng_vectors.h"
)

add_executable(loadng_vectors_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/routing/loadng.c
  ${VECTOR_HDR}
)

target_include_directories(loadng_vectors_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/routing/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../loadng/stub
  ${CMAKE_CURRENT_BINARY_DIR}
)
target_compile_definitions(loadng_vectors_test PRIVATE
  CONFIG_LICHEN_LOADNG_ROUTE_CACHE_SIZE=32
  CONFIG_LICHEN_LOADNG_SEEN_TABLE_SIZE=16
)
target_compile_options(loadng_vectors_test PRIVATE
  -std=c11
  -Wall -Wextra -Werror
  -Wno-unused-const-variable
)

include(CTest)
add_test(NAME loadng_vectors COMMAND loadng_vectors_test)
