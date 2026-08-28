# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)

if(DEFINED ENV{ZEPHYR_BASE})
  find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
  project(regional_duty_cycle)
else()
  project(regional_duty_cycle C)
  find_package(Threads REQUIRED)
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(VECTOR_JSON ${CMAKE_CURRENT_LIST_DIR}/../../../test/vectors/duty_cycle_calculation.json)
set(GENERATED_HEADER ${CMAKE_CURRENT_BINARY_DIR}/duty_cycle_vectors.h)
execute_process(
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/gen_vectors.py
          ${VECTOR_JSON} ${GENERATED_HEADER}
  RESULT_VARIABLE GENERATOR_RESULT
  OUTPUT_VARIABLE GENERATOR_STDOUT
  ERROR_VARIABLE GENERATOR_STDERR
)
if(NOT GENERATOR_RESULT EQUAL 0)
  message(FATAL_ERROR "duty-cycle vector generation failed: ${GENERATOR_STDERR}")
endif()

if(DEFINED ENV{ZEPHYR_BASE})
  target_sources(app PRIVATE src/main.c)
  target_include_directories(app PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
else()
  add_executable(regional_duty_cycle
    src/main.c
    ../../subsys/lichen/hal/hal_duty.c
  )
  target_include_directories(regional_duty_cycle PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ../../subsys/lichen/hal/include
  )
  target_compile_definitions(regional_duty_cycle PRIVATE
    CONFIG_LICHEN_DUTY_CYCLE=1
  )
  target_link_libraries(regional_duty_cycle PRIVATE Threads::Threads)
  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/test_common.cmake)
  lichen_test_target(regional_duty_cycle)
  enable_testing()
  add_test(NAME regional_duty_cycle COMMAND regional_duty_cycle)
endif()
