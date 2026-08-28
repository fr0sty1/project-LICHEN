# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)

if(DEFINED ENV{ZEPHYR_BASE})
  find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
  project(drift_bound)
else()
  project(drift_bound C)
  find_package(Threads REQUIRED)
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(VECTOR_JSON ${CMAKE_CURRENT_LIST_DIR}/../../../test/vectors/ccp7_holdover.json)
set(GENERATED_HEADER ${CMAKE_CURRENT_BINARY_DIR}/drift_bound_vectors.h)
execute_process(
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/gen_vectors.py
          ${VECTOR_JSON} ${GENERATED_HEADER}
  RESULT_VARIABLE GENERATOR_RESULT
  ERROR_VARIABLE GENERATOR_STDERR
)
if(NOT GENERATOR_RESULT EQUAL 0)
  message(FATAL_ERROR "drift-bound vector generation failed: ${GENERATOR_STDERR}")
endif()

set(DRIFT_SOURCE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/link/drift_bound.c)
set(DRIFT_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/link/include)

if(DEFINED ENV{ZEPHYR_BASE})
  target_sources(app PRIVATE src/main.c ${DRIFT_SOURCE})
  target_include_directories(app PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${DRIFT_INCLUDE})
  target_compile_definitions(app PRIVATE
    CONFIG_LICHEN_CCP_TIME_SYNC=1
    CONFIG_LICHEN_LINK_MAX_NEIGHBORS=16
  )
else()
  add_executable(drift_bound src/main.c ${DRIFT_SOURCE})
  target_include_directories(drift_bound PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${DRIFT_INCLUDE}
  )
  target_compile_definitions(drift_bound PRIVATE
    CONFIG_LICHEN_CCP_TIME_SYNC=1
    CONFIG_LICHEN_LINK_MAX_NEIGHBORS=16
  )
  target_link_libraries(drift_bound PRIVATE Threads::Threads)
  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/test_common.cmake)
  lichen_test_target(drift_bound)
  enable_testing()
  add_test(NAME drift_bound COMMAND drift_bound)
endif()
