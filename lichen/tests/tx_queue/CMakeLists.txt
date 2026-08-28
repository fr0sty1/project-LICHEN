# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(tx_queue_test C)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(VECTORS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors)
set(GENERATED_VECTORS_H
    ${CMAKE_CURRENT_BINARY_DIR}/lichen_generated_tx_queue_vectors.h)

add_custom_command(
  OUTPUT ${GENERATED_VECTORS_H}
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          --vectors-dir ${VECTORS_DIR}
          --output ${GENERATED_VECTORS_H}
  DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
    ${VECTORS_DIR}/tx_queue_bounded.json
    ${VECTORS_DIR}/tx_queue_expiry.json
    ${VECTORS_DIR}/tx_queue_priority.json
    ${VECTORS_DIR}/tx_queue_implementation.json
  VERBATIM
)

include_directories(
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

add_executable(tx_queue_test
  main.c
  ${GENERATED_VECTORS_H}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/frame_pool.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/tx_queue.c
)

target_compile_definitions(tx_queue_test PRIVATE CONFIG_TX_QUEUE_TEST_TIME CONFIG_LICHEN_LINK_MAX_NEIGHBORS=16)
target_link_libraries(tx_queue_test pthread)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)
lichen_test_target(tx_queue_test)

enable_testing()
add_test(NAME tx_queue_test COMMAND tx_queue_test)

option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)
if(ENABLE_TSAN)
  target_compile_options(tx_queue_test PRIVATE -fsanitize=thread -fno-omit-frame-pointer -g)
  target_link_options(tx_queue_test PRIVATE -fsanitize=thread)
  target_compile_definitions(tx_queue_test PRIVATE ENABLE_TSAN)
endif()
