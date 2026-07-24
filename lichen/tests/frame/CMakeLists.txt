# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(frame_test C)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

add_executable(frame_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/frame.c
)

target_compile_definitions(frame_test PRIVATE
  LICHEN_MAX_FRAME_LEN=254
  LICHEN_MAX_FRAME_BODY_LEN=250
)
target_compile_options(frame_test PRIVATE -Wall -Wextra -Werror)

include(CTest)
add_test(NAME frame COMMAND frame_test)
