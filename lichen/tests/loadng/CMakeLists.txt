# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(loadng_test C)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/routing/include
)

add_executable(loadng_test
  main.c
)

target_compile_options(loadng_test PRIVATE -Wall -Wextra -Werror)
