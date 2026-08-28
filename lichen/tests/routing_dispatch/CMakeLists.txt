# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)

if(DEFINED ENV{ZEPHYR_BASE})
  find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
  project(routing_dispatch)
else()
  project(routing_dispatch C)
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(VECTOR_JSON ${CMAKE_CURRENT_LIST_DIR}/../../../test/vectors/route_selection.json)
set(GENERATED_HEADER ${CMAKE_CURRENT_BINARY_DIR}/route_selection_vectors.h)
execute_process(
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/gen_vectors.py
          ${VECTOR_JSON} ${GENERATED_HEADER}
  RESULT_VARIABLE GENERATOR_RESULT
  ERROR_VARIABLE GENERATOR_STDERR
)
if(NOT GENERATOR_RESULT EQUAL 0)
  message(FATAL_ERROR "route-selection vector generation failed: ${GENERATOR_STDERR}")
endif()

set(ROUTER_SOURCE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/routing/router.c)
set(GRADIENT_SOURCE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/routing/gradient.c)
set(ROUTING_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/routing/include)

if(DEFINED ENV{ZEPHYR_BASE})
  target_sources(app PRIVATE src/main.c)
  target_include_directories(app PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
else()
  add_executable(routing_dispatch src/main.c ${ROUTER_SOURCE} ${GRADIENT_SOURCE})
  target_include_directories(routing_dispatch PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/stub
    ${ROUTING_INCLUDE}
  )
  target_compile_definitions(routing_dispatch PRIVATE
    CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE=1024
    CONFIG_LICHEN_ROUTER_DTN_MAX_MESSAGES=4
    CONFIG_LICHEN_ROUTER_DTN_MAX_MESSAGE_SIZE=256
    CONFIG_LICHEN_ROUTER_FORWARDING_BUFFER=1
    CONFIG_LICHEN_ROUTER_MAX_FORWARDING_SOURCES=4
    CONFIG_LICHEN_ROUTER_MAX_PACKETS_PER_SOURCE=2
  )
  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/test_common.cmake)
  lichen_test_target(routing_dispatch)
  enable_testing()
  add_test(NAME routing_dispatch COMMAND routing_dispatch)
endif()
