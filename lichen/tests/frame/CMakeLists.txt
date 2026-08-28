# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(frame_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(FRAME_VECTOR_HEADER ${CMAKE_CURRENT_BINARY_DIR}/frame_vectors.h)
set(FRAME_VECTOR_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/link_frame.json
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/link_frame_signed_modes.json
)

add_custom_command(
  OUTPUT ${FRAME_VECTOR_HEADER}
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          --output ${FRAME_VECTOR_HEADER} ${FRAME_VECTOR_FILES}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py ${FRAME_VECTOR_FILES}
  VERBATIM
)

add_custom_target(frame_vectors DEPENDS ${FRAME_VECTOR_HEADER})

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
  ${CMAKE_CURRENT_BINARY_DIR}
)

add_executable(frame_test
  main.c
  ${FRAME_VECTOR_HEADER}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/frame.c
)

add_dependencies(frame_test frame_vectors)

lichen_test_target(frame_test)

# Canonical wire bounds: 255-byte total frame, 254-byte maximum body
target_compile_definitions(frame_test PRIVATE
  LICHEN_MAX_FRAME_LEN=255
  LICHEN_MAX_FRAME_BODY_LEN=254
)

include(CTest)
add_test(NAME frame COMMAND frame_test)
