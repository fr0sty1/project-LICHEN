# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)

if(DEFINED ENV{ZEPHYR_BASE})
  find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
  project(asn_sfn)
else()
  project(asn_sfn C)
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(VECTOR_JSON ${CMAKE_CURRENT_LIST_DIR}/../../../test/vectors/asn_sfn_derivation.json)
set(GENERATED_HEADER ${CMAKE_CURRENT_BINARY_DIR}/asn_sfn_vectors.h)
execute_process(
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/gen_vectors.py
          ${VECTOR_JSON} ${GENERATED_HEADER}
  RESULT_VARIABLE GENERATOR_RESULT
  ERROR_VARIABLE GENERATOR_STDERR
)
if(NOT GENERATOR_RESULT EQUAL 0)
  message(FATAL_ERROR "ASN/SFN vector generation failed: ${GENERATOR_STDERR}")
endif()

set(SYNC_SOURCE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/link/sync_hop.c)
set(LINK_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/link/include)
set(L2_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/l2)

if(DEFINED ENV{ZEPHYR_BASE})
  target_sources(app PRIVATE src/main.c ${SYNC_SOURCE})
  target_include_directories(app PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LINK_INCLUDE}
    ${L2_INCLUDE}
  )
  target_compile_definitions(app PRIVATE
    CONFIG_LICHEN_SYNC_HOP=1
    CONFIG_LICHEN_SYNC_HOP_SUPERFRAME_MS=2000
  )
else()
  add_executable(asn_sfn src/main.c ${SYNC_SOURCE})
  target_include_directories(asn_sfn PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LINK_INCLUDE}
    ${L2_INCLUDE}
  )
  target_compile_definitions(asn_sfn PRIVATE
    CONFIG_LICHEN_SYNC_HOP=1
    CONFIG_LICHEN_SYNC_HOP_SUPERFRAME_MS=2000
  )
  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/test_common.cmake)
  lichen_test_target(asn_sfn)
  enable_testing()
  add_test(NAME asn_sfn COMMAND asn_sfn)
endif()
