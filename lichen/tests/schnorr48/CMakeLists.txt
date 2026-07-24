# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# Schnorr-48 unit tests - standalone build

cmake_minimum_required(VERSION 3.20)
project(schnorr48_test C)

# Include paths
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto
)

# Build test executable
add_executable(schnorr48_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/schnorr48.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/frame.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto/monocypher.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto/monocypher-ed25519.c
)

# Define CONFIG_LICHEN_CRYPTO_MONOCYPHER to enable real implementation
# and provide frame constants (normally from Zephyr Kconfig / autoconf.h)
target_compile_definitions(schnorr48_test PRIVATE
  CONFIG_LICHEN_CRYPTO_MONOCYPHER=1
  LICHEN_MAX_FRAME_LEN=254
  LICHEN_MAX_FRAME_BODY_LEN=250
)

# Enable warnings
target_compile_options(schnorr48_test PRIVATE -Wall -Wextra -Werror)

include(CTest)
add_test(NAME schnorr48 COMMAND schnorr48_test)
