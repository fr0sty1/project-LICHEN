# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(link_epoch_host_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(link_epoch_host_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/epoch_persist.c
)
target_include_directories(link_epoch_host_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/stub
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)
target_compile_definitions(link_epoch_host_test PRIVATE
  __ZEPHYR__=1
  CONFIG_LICHEN_LINK_EPOCH_PERSIST=1
  CONFIG_LICHEN_LINK_EPOCH_TEST_HOOKS=1
  CONFIG_LICHEN_LINK_LOG_LEVEL=0
)

lichen_test_target(link_epoch_host_test)
target_link_libraries(link_epoch_host_test PRIVATE pthread)

include(CTest)
add_test(NAME link_epoch_host COMMAND link_epoch_host_test)
