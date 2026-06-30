# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(meshtastic_codec)

set(MESHTASTIC_VECTOR_JSON
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/meshtastic_app_compat.json
)
set(MESHTASTIC_VECTOR_HEADER
  ${CMAKE_CURRENT_BINARY_DIR}/meshtastic_vectors.h
)

add_custom_command(
  OUTPUT ${MESHTASTIC_VECTOR_HEADER}
  COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          ${MESHTASTIC_VECTOR_JSON}
          ${MESHTASTIC_VECTOR_HEADER}
  DEPENDS
          ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          ${MESHTASTIC_VECTOR_JSON}
  VERBATIM
)

add_custom_target(meshtastic_vector_header DEPENDS ${MESHTASTIC_VECTOR_HEADER})
add_dependencies(app meshtastic_vector_header)

target_include_directories(app PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_sources(app PRIVATE src/main.c)
