# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# RFC 6550 Section 7.2 lollipop + DIO version/identity policy — standalone host test

cmake_minimum_required(VERSION 3.20)
project(rpl_dodag_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(rpl_dodag_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/dodag.c
)

target_include_directories(rpl_dodag_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/include
)
target_compile_definitions(rpl_dodag_test PRIVATE LICHEN_RPL_TEST=1)
# rpl_dodag.h includes rpl_messages.h, which lacks _Nonnull on two pointers.
# Apple Clang -Wnullability-completeness is fatal under this target's -Werror.
target_compile_options(rpl_dodag_test PRIVATE -Wno-nullability-completeness)

lichen_test_target(rpl_dodag_test)

include(CTest)
add_test(NAME rpl_dodag COMMAND rpl_dodag_test)
