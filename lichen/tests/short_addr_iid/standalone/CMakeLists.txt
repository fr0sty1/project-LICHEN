# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(short_addr_iid_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/test_common.cmake)

set(LICHEN_L2_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../subsys/lichen/l2)

add_executable(short_addr_iid_test
  main.c
  ${LICHEN_L2_DIR}/short_addr.c
)

target_include_directories(short_addr_iid_test PRIVATE
  ${LICHEN_L2_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
)

lichen_test_target(short_addr_iid_test)

include(CTest)
add_test(NAME short_addr_iid COMMAND short_addr_iid_test)
