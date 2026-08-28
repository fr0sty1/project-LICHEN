# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(pubkey_to_iid_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(pubkey_to_iid_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/l2/ipv6_addr.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/identity_addr.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto/monocypher.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto/monocypher-ed25519.c
)

target_include_directories(pubkey_to_iid_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/l2
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)
target_compile_definitions(pubkey_to_iid_test PRIVATE
  CONFIG_LICHEN_CRYPTO_MONOCYPHER=1
  LICHEN_UTIL_H=1
)
target_compile_options(pubkey_to_iid_test PRIVATE
  -ffunction-sections
  -include ${CMAKE_CURRENT_SOURCE_DIR}/compat.h
)
if(APPLE)
  target_link_options(pubkey_to_iid_test PRIVATE -Wl,-dead_strip)
else()
  target_link_options(pubkey_to_iid_test PRIVATE -Wl,--gc-sections)
endif()

lichen_test_target(pubkey_to_iid_test)

include(CTest)
add_test(NAME pubkey_to_iid COMMAND pubkey_to_iid_test)
