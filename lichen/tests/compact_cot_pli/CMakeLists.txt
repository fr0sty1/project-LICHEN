# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(compact_cot_pli_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(compact_cot_pli_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/compact_cot/compact_cot_pli.c
)
target_include_directories(compact_cot_pli_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/compact_cot/include
)

lichen_test_target(compact_cot_pli_test)

include(CTest)
add_test(NAME compact_cot_pli COMMAND compact_cot_pli_test)
