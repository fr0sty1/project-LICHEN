# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(meshcore_codec)

set(MESHCORE_VECTOR_JSON
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/meshcore_app_compat.json
)
set(MESHCORE_VECTOR_HEADER
  ${CMAKE_CURRENT_BINARY_DIR}/meshcore_codec_vectors.h
)

add_custom_command(
  OUTPUT ${MESHCORE_VECTOR_HEADER}
  COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          ${MESHCORE_VECTOR_JSON}
          ${MESHCORE_VECTOR_HEADER}
  DEPENDS
          ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          ${MESHCORE_VECTOR_JSON}
  VERBATIM
)

add_custom_target(meshcore_codec_vector_header DEPENDS ${MESHCORE_VECTOR_HEADER})
add_dependencies(app meshcore_codec_vector_header)

target_include_directories(app PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_sources(app PRIVATE src/main.c)
