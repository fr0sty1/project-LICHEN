# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(coap_waypoints)

set(WAYPOINT_VECTOR_INC ${CMAKE_CURRENT_BINARY_DIR}/waypoint_vectors.inc)
execute_process(
  COMMAND ${PYTHON_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/waypoint.json
          ${WAYPOINT_VECTOR_INC}
  COMMAND_ERROR_IS_FATAL ANY
)

target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ../../include
  ../../subsys/lichen/coap/include
  ../../subsys/lichen/oscore/include
)

target_compile_definitions(app PRIVATE
  CONFIG_LICHEN_COAP_WAYPOINTS=1
  CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX=512
)

target_sources(app PRIVATE
  src/main.c
  ../../subsys/lichen/coap/coap_waypoints.c
)

zephyr_linker_sources(DATA_SECTIONS
  ../../subsys/lichen/coap/sections-ram.ld
)
zephyr_iterable_section(
  NAME coap_resource_lichen_coap_server
  GROUP DATA_REGION ${XIP_ALIGN_WITH_INPUT}
  SUBALIGN CONFIG_LINKER_ITERABLE_SUBALIGN
)
