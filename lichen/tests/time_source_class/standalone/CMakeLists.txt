# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(time_source_class_test C)

find_package(Threads REQUIRED)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/test_common.cmake)

set(LICHEN_LINK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../subsys/lichen/link)

add_executable(time_source_class_test
  main.c
  ${LICHEN_LINK_DIR}/time_sync.c
)

target_include_directories(time_source_class_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${LICHEN_LINK_DIR}/include
)
target_compile_definitions(time_source_class_test PRIVATE
  CONFIG_LICHEN_CCP_TIME_SYNC=1
  CONFIG_LICHEN_LINK_LOG_LEVEL=0
  CONFIG_LICHEN_LINK_MAX_NEIGHBORS=16
)
target_compile_options(time_source_class_test PRIVATE
  -Wno-nullability-completeness
)

lichen_test_target(time_source_class_test)
target_link_libraries(time_source_class_test PRIVATE Threads::Threads)

include(CTest)
add_test(NAME time_source_class COMMAND time_source_class_test)
