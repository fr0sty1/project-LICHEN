# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(rpl_short_assignment_test C)

set(VECTOR_JSON ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/short_addr_assignment.json)
set(VECTOR_HDR ${CMAKE_CURRENT_BINARY_DIR}/short_assignment_vectors.h)

add_custom_command(
  OUTPUT ${VECTOR_HDR}
  COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/generate_vectors.py
          ${VECTOR_JSON} ${VECTOR_HDR}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/generate_vectors.py ${VECTOR_JSON}
  COMMENT "Generate short_assignment_vectors.h"
)

add_executable(rpl_short_assignment_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/messages.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/rpl_short_assignment.c
  ${VECTOR_HDR}
)

target_include_directories(rpl_short_assignment_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/include
  ${CMAKE_CURRENT_SOURCE_DIR}/stub
  ${CMAKE_CURRENT_BINARY_DIR}
)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)
lichen_test_target(rpl_short_assignment_test)
target_compile_options(rpl_short_assignment_test PRIVATE
  -Wno-nullability-completeness
  -Wno-implicit-int-conversion
)

include(CTest)
add_test(NAME rpl_short_assignment COMMAND rpl_short_assignment_test)
