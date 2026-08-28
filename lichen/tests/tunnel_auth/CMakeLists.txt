# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(tunnel_auth_test C)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
execute_process(
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          ${CMAKE_CURRENT_BINARY_DIR}/tunnel_auth_vectors.h
  COMMAND_ERROR_IS_FATAL ANY)
add_executable(tunnel_auth_test
  src/main.c
  ../../subsys/lichen/gateway/tunnel_auth.c
  ../../subsys/lichen/link/schnorr48.c
  ../../subsys/lichen/crypto/monocypher.c
  ../../subsys/lichen/crypto/monocypher-ed25519.c
)
target_include_directories(tunnel_auth_test PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ../../subsys/lichen/gateway/include
  ../../subsys/lichen/link/include
  ../../subsys/lichen/crypto
  ../../include
)
target_compile_definitions(tunnel_auth_test PRIVATE CONFIG_LICHEN_CRYPTO_MONOCYPHER=1)
target_link_libraries(tunnel_auth_test PRIVATE OpenSSL::Crypto)
lichen_test_target(tunnel_auth_test)
include(CTest)
add_test(NAME tunnel_auth COMMAND tunnel_auth_test)
