# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(frame_pool_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(frame_pool_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/frame_pool.c
)
target_include_directories(frame_pool_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

lichen_test_target(frame_pool_test)
target_link_libraries(frame_pool_test PRIVATE pthread)

include(CTest)
add_test(NAME frame_pool COMMAND frame_pool_test)
