# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)

if(DEFINED ENV{ZEPHYR_BASE})
  find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
  project(coap_codec)
else()
  project(coap_codec C)
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(VECTOR_JSON ${CMAKE_CURRENT_LIST_DIR}/../../../test/vectors/coap_messages.json)
set(VECTOR_HEADER ${CMAKE_CURRENT_BINARY_DIR}/coap_vectors.h)
execute_process(
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/generate_vectors.py
          ${VECTOR_JSON} ${VECTOR_HEADER}
  RESULT_VARIABLE GENERATOR_RESULT
  ERROR_VARIABLE GENERATOR_ERROR
)
if(NOT GENERATOR_RESULT EQUAL 0)
  message(FATAL_ERROR "CoAP vector generation failed: ${GENERATOR_ERROR}")
endif()

set(CODEC_SOURCE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/coap/coap_codec.c)
set(CODEC_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/coap/include)

if(DEFINED ENV{ZEPHYR_BASE})
  target_sources(app PRIVATE src/main.c)
  target_include_directories(app PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
else()
  add_executable(coap_codec_test src/main.c ${CODEC_SOURCE})
  target_include_directories(coap_codec_test PRIVATE
    ${CODEC_INCLUDE}
    ${CMAKE_CURRENT_BINARY_DIR}
  )
  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/test_common.cmake)
  lichen_test_target(coap_codec_test)
  enable_testing()
  add_test(NAME coap_codec COMMAND coap_codec_test)
endif()
