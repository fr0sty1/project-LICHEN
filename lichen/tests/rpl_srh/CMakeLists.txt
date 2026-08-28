# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(rpl_srh_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(rpl_srh_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/rpl_srh.c
)

target_include_directories(rpl_srh_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/include
)
target_compile_definitions(rpl_srh_test PRIVATE LICHEN_RPL_TEST=1)
target_compile_options(rpl_srh_test PRIVATE -Wno-nullability-completeness)
lichen_test_target(rpl_srh_test)

include(CTest)
add_test(NAME rpl_srh COMMAND rpl_srh_test)
