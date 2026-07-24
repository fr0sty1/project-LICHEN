# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(loadng_test C)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/routing/include
  ${CMAKE_CURRENT_SOURCE_DIR}/stub
)

add_executable(loadng_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/routing/loadng.c
)

target_compile_options(loadng_test PRIVATE -Wall -Wextra -Werror -Wno-unused-const-variable)
target_compile_definitions(loadng_test PRIVATE CONFIG_LICHEN_LOADNG_ROUTE_CACHE_SIZE=32 CONFIG_LICHEN_LOADNG_SEEN_TABLE_SIZE=16)
