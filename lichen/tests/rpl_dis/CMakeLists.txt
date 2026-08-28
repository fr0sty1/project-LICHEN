# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(rpl_dis_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(rpl_dis_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/rpl_dis.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/messages.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/trickle.c
)

target_include_directories(rpl_dis_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../rpl_messages/stub
)
lichen_test_target(rpl_dis_test)
target_compile_options(rpl_dis_test PRIVATE
  -Wno-nullability-completeness
  -Wno-implicit-int-conversion
)

include(CTest)
add_test(NAME rpl_dis COMMAND rpl_dis_test)
