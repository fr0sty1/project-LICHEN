# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(csma_constants_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(csma_constants_test main.c)
target_include_directories(csma_constants_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

lichen_test_target(csma_constants_test)
target_link_libraries(csma_constants_test PRIVATE pthread)

include(CTest)
add_test(NAME csma_constants COMMAND csma_constants_test)
