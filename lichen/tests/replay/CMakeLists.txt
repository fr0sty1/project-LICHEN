# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(replay_test C)

add_executable(replay_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/replay.c
)
target_include_directories(replay_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)
target_compile_options(replay_test PRIVATE -Wall -Wextra -Werror)

include(CTest)
add_test(NAME replay COMMAND replay_test)
