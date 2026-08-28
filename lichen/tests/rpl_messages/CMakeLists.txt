# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(rpl_messages_test C)

set(VECTOR_JSON ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/rpl_messages.json)
set(VECTOR_HDR ${CMAKE_CURRENT_BINARY_DIR}/rpl_messages_vectors.h)

add_custom_command(
  OUTPUT ${VECTOR_HDR}
  COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/generate_vectors.py
          ${VECTOR_JSON} ${VECTOR_HDR}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/generate_vectors.py ${VECTOR_JSON}
  COMMENT "Generate rpl_messages_vectors.h"
)

add_executable(rpl_messages_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/messages.c
  ${VECTOR_HDR}
)

target_include_directories(rpl_messages_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/include
  ${CMAKE_CURRENT_SOURCE_DIR}/stub
  ${CMAKE_CURRENT_BINARY_DIR}
)
target_compile_options(rpl_messages_test PRIVATE
  -std=c11
  -Wall -Wextra -Werror
  -Wno-nullability-completeness
)

include(CTest)
add_test(NAME rpl_messages COMMAND rpl_messages_test)
