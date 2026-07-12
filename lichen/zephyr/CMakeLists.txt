# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN Zephyr module CMake extension

# -----------------------------------------------------------------------------
# Compiler hardening flags for LICHEN C code
# -----------------------------------------------------------------------------
zephyr_compile_options(
  # Basic warnings as errors
  -Wall
  -Wextra
  -Werror

  # Format string security
  -Wformat=2
  -Wformat-security

  # Shadow detection
  -Wshadow

  # Integer conversion warnings
  -Wconversion
  # -Wsign-conversion  # TODO: enable once existing warnings are fixed

  # Stack protection
  -fstack-protector-strong

  # Zephyr callbacks often have unused parameters
  -Wno-unused-parameter
)

# -----------------------------------------------------------------------------
# Advanced hardening: Control Flow Integrity (Clang 18+)
# Prevents ROP/JOP attacks by validating indirect call targets
# -----------------------------------------------------------------------------
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  # Extract major version number
  if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL "18.0")
    # SECURITY: CFI requires link-time optimization and hidden visibility
    zephyr_compile_options(
      -fsanitize=cfi
      -fvisibility=hidden
    )
    zephyr_link_libraries(
      -fsanitize=cfi
    )
    message(STATUS "LICHEN: Clang ${CMAKE_C_COMPILER_VERSION} detected - enabling CFI hardening")
  endif()
endif()

add_subdirectory(../drivers drivers)
add_subdirectory(../lib lib)
add_subdirectory(../subsys subsys)
