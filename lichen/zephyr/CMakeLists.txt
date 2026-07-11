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

add_subdirectory(../drivers drivers)
add_subdirectory(../lib lib)
add_subdirectory(../subsys subsys)
