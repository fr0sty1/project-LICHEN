# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(lichen_fuzz C)

# Require Clang for libFuzzer
if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
  message(WARNING "libFuzzer requires Clang; skipping fuzz targets")
  return()
endif()

# Common include paths
set(LINK_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include)
set(LINK_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link)

# Fuzzer compile/link flags
set(FUZZ_FLAGS -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)

# --- fuzz_frame: frame parser fuzzer ---
add_executable(fuzz_frame
  fuzz_frame.c
  ${LINK_SRC_DIR}/frame.c
)

target_include_directories(fuzz_frame PRIVATE ${LINK_INCLUDE_DIR})
target_compile_options(fuzz_frame PRIVATE ${FUZZ_FLAGS} -Wall -Wextra -Werror)
target_link_options(fuzz_frame PRIVATE ${FUZZ_FLAGS})

# --- fuzz_schnorr48: signature verifier fuzzer ---
set(CRYPTO_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto)

add_executable(fuzz_schnorr48
  fuzz_schnorr48.c
  ${LINK_SRC_DIR}/schnorr48.c
  ${CRYPTO_SRC_DIR}/monocypher.c
  ${CRYPTO_SRC_DIR}/monocypher-ed25519.c
)

target_include_directories(fuzz_schnorr48 PRIVATE ${LINK_INCLUDE_DIR} ${CRYPTO_SRC_DIR})
target_compile_definitions(fuzz_schnorr48 PRIVATE CONFIG_LICHEN_CRYPTO_MONOCYPHER=1)
target_compile_options(fuzz_schnorr48 PRIVATE ${FUZZ_FLAGS} -Wall -Wextra -Werror)
target_link_options(fuzz_schnorr48 PRIVATE ${FUZZ_FLAGS})
