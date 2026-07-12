# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(lichen_fuzz C)

# Require Clang for fuzzing (libFuzzer or standalone with sanitizers)
if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
  message(WARNING "Fuzzing requires Clang; skipping fuzz targets")
  return()
endif()

# Common include paths
set(LINK_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include)
set(LINK_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link)

# Common warning flags (disable AppleClang nullability warnings in headers)
set(FUZZ_WARN_FLAGS -Wall -Wextra -Werror -Wno-nullability-completeness)

# Check if libFuzzer runtime is available
include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
check_c_source_compiles("
  #include <stdint.h>
  #include <stddef.h>
  int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return 0; }
" HAVE_LIBFUZZER)
unset(CMAKE_REQUIRED_FLAGS)

if(HAVE_LIBFUZZER)
  # Full libFuzzer build
  set(FUZZ_FLAGS -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
  message(STATUS "libFuzzer available: building with -fsanitize=fuzzer")
else()
  # Standalone build with sanitizers (for AppleClang without libFuzzer runtime)
  set(FUZZ_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer)
  set(FUZZ_STANDALONE_DEF FUZZ_STANDALONE)
  message(STATUS "libFuzzer not available: building standalone fuzzers")
endif()

# --- fuzz_frame: frame parser fuzzer ---
add_executable(fuzz_frame
  fuzz_frame.c
  ${LINK_SRC_DIR}/frame.c
)

target_include_directories(fuzz_frame PRIVATE ${LINK_INCLUDE_DIR})
target_compile_options(fuzz_frame PRIVATE ${FUZZ_FLAGS} ${FUZZ_WARN_FLAGS})
target_link_options(fuzz_frame PRIVATE ${FUZZ_FLAGS})
if(FUZZ_STANDALONE_DEF)
  target_compile_definitions(fuzz_frame PRIVATE ${FUZZ_STANDALONE_DEF})
endif()

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
target_compile_options(fuzz_schnorr48 PRIVATE ${FUZZ_FLAGS} ${FUZZ_WARN_FLAGS})
target_link_options(fuzz_schnorr48 PRIVATE ${FUZZ_FLAGS})

# --- fuzz_schc: SCHC compression/fragmentation fuzzer ---
set(SCHC_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/schc/include)
set(SCHC_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/schc)

add_executable(fuzz_schc
  fuzz_schc.c
  ${SCHC_SRC_DIR}/schc.c
)

target_include_directories(fuzz_schc PRIVATE ${SCHC_INCLUDE_DIR})
target_compile_options(fuzz_schc PRIVATE ${FUZZ_FLAGS} ${FUZZ_WARN_FLAGS})
target_link_options(fuzz_schc PRIVATE ${FUZZ_FLAGS})
if(FUZZ_STANDALONE_DEF)
  target_compile_definitions(fuzz_schc PRIVATE ${FUZZ_STANDALONE_DEF})
endif()
