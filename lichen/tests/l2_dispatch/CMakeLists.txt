# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(l2_dispatch)

set(L2_DISPATCH_VECTOR_HEADER ${CMAKE_CURRENT_BINARY_DIR}/l2_dispatch_vectors.h)
add_custom_command(
  OUTPUT ${L2_DISPATCH_VECTOR_HEADER}
  COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/l2_payload.json
          ${L2_DISPATCH_VECTOR_HEADER}
  DEPENDS
          ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/l2_payload.json
  VERBATIM
)
add_custom_target(l2_dispatch_vector_header DEPENDS ${L2_DISPATCH_VECTOR_HEADER})
add_dependencies(app l2_dispatch_vector_header)

target_sources(app PRIVATE src/main.c)
target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
  ${CMAKE_CURRENT_BINARY_DIR}
)
