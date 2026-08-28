# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(dad_messages_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(dad_messages_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/l2/dad.c
)
target_include_directories(dad_messages_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/l2
)
lichen_test_target(dad_messages_test)

include(CTest)
add_test(NAME dad_messages COMMAND dad_messages_test)
