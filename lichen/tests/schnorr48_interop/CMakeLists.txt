# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(schnorr48_interop_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

add_executable(schnorr48_interop_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/schnorr48.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto/monocypher.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto/monocypher-ed25519.c
)

target_compile_definitions(schnorr48_interop_test PRIVATE
  CONFIG_LICHEN_CRYPTO_MONOCYPHER=1
)

lichen_test_target(schnorr48_interop_test)

include(CTest)
add_test(NAME schnorr48_interop COMMAND schnorr48_interop_test)
