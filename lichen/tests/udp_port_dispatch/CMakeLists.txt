# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(udp_port_dispatch_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(udp_port_dispatch_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/udp_port_dispatch/udp_port_dispatch.c
)
target_include_directories(udp_port_dispatch_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/udp_port_dispatch/include
)
lichen_test_target(udp_port_dispatch_test)

include(CTest)
add_test(NAME udp_port_dispatch COMMAND udp_port_dispatch_test)
