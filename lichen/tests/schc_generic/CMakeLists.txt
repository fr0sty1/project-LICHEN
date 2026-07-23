# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(schc_generic)

set(SCHC_FRAGMENT_VECTOR_JSON
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/schc_fragmentation.json
)
set(SCHC_FRAGMENT_VECTOR_HEADER
  ${CMAKE_CURRENT_BINARY_DIR}/schc_fragmentation_vectors.h
)

add_custom_command(
  OUTPUT ${SCHC_FRAGMENT_VECTOR_HEADER}
  COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          ${SCHC_FRAGMENT_VECTOR_JSON}
          ${SCHC_FRAGMENT_VECTOR_HEADER}
  DEPENDS
          ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          ${SCHC_FRAGMENT_VECTOR_JSON}
  VERBATIM
)

add_custom_target(schc_fragment_vector_header DEPENDS ${SCHC_FRAGMENT_VECTOR_HEADER})
add_dependencies(app schc_fragment_vector_header)

target_include_directories(app PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_sources(app PRIVATE src/main.c)
