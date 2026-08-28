# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# RFC 6550 Section 7.2 DAO Path Sequence comparison — standalone host test

cmake_minimum_required(VERSION 3.20)
project(rpl_dao_sequence_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

set(RPL_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl)
# Host stubs (zephyr/kernel.h) so real headers parse outside Zephyr.
set(HOST_STUB_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)

add_executable(rpl_dao_sequence_test
  main.c
  ${RPL_SRC_DIR}/rpl_dao_build.c
)

target_include_directories(rpl_dao_sequence_test PRIVATE
  ${RPL_SRC_DIR}/include
  ${HOST_STUB_INCLUDE_DIR}
)
target_compile_definitions(rpl_dao_sequence_test PRIVATE LICHEN_RPL_TEST=1)
# rpl_routing.h includes rpl_messages.h, which lacks _Nonnull on two pointers.
# Apple Clang -Wnullability-completeness is fatal under this target's -Werror.
target_compile_options(rpl_dao_sequence_test PRIVATE -Wno-nullability-completeness)

lichen_test_target(rpl_dao_sequence_test)

# Exhaustive 65536-pair comparator sweeps against independent committed golden
# dumps for DAO replay sequencing and DODAG version comparison.
add_executable(rpl_dao_sequence_sweep
  sweep.c
  ${RPL_SRC_DIR}/rpl_dao_build.c
  ${RPL_SRC_DIR}/dodag.c
  ${RPL_SRC_DIR}/messages.c
  ${RPL_SRC_DIR}/trickle.c
)

target_include_directories(rpl_dao_sequence_sweep PRIVATE
  ${RPL_SRC_DIR}/include
  ${HOST_STUB_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../rpl_dodag/stub
)
target_compile_definitions(rpl_dao_sequence_sweep PRIVATE LICHEN_RPL_TEST=1)

lichen_test_target(rpl_dao_sequence_sweep)
target_compile_options(rpl_dao_sequence_sweep PRIVATE
  -Wno-nullability-completeness
  -Wno-implicit-int-conversion
)

include(CTest)
add_test(NAME rpl_dao_sequence COMMAND rpl_dao_sequence_test)
add_test(NAME rpl_dao_sequence_exhaustive_sweep COMMAND rpl_dao_sequence_sweep
         ${CMAKE_CURRENT_SOURCE_DIR}/golden_lollipop_sweep.txt
         ${CMAKE_CURRENT_SOURCE_DIR}/golden_dodag_version_sweep.txt)
