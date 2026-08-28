# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(tdma_guard_budget_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(tdma_guard_budget_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/tdma.c
)

target_include_directories(tdma_guard_budget_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)
target_compile_definitions(tdma_guard_budget_test PRIVATE
  CONFIG_LICHEN_TDMA=1
)

lichen_test_target(tdma_guard_budget_test)
target_link_libraries(tdma_guard_budget_test PRIVATE pthread)

include(CTest)
add_test(NAME tdma_guard_budget COMMAND tdma_guard_budget_test)
