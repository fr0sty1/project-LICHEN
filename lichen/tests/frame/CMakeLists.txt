# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(frame_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

add_executable(frame_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/frame.c
)

lichen_test_target(frame_test)

# Canonical wire bounds: 255-byte total frame, 254-byte maximum body
target_compile_definitions(frame_test PRIVATE
  LICHEN_MAX_FRAME_LEN=255
  LICHEN_MAX_FRAME_BODY_LEN=254
)

include(CTest)
add_test(NAME frame COMMAND frame_test)
