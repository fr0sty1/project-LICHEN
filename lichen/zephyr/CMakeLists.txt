# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN Zephyr module CMake extension

# -----------------------------------------------------------------------------
# Compiler hardening flags for LICHEN C code
#
# Applied per LICHEN library target below, NOT via zephyr_compile_options():
# that would inject them into the entire Zephyr build, and Zephyr core is not
# -Wconversion-clean (e.g. sys/util.h bcd2bin), breaking every board target.
# -----------------------------------------------------------------------------
set(LICHEN_HARDENING_FLAGS
  # Basic warnings as errors
  -Wall
  -Wextra
  -Werror

  # Format string security
  -Wformat=2
  -Wformat-security

  # Shadow detection
  -Wshadow

  # Integer conversion warnings — visible but not (yet) fatal:
  # - In C, -Wconversion implies sign-conversion diagnostics, so the deferred
  #   -Wsign-conversion must be masked explicitly or the TODO below is moot.
  # - Zephyr headers (e.g. sys/util.h bcd2bin) trip -Wconversion in every
  #   including translation unit, so it cannot be -Werror until either
  #   Zephyr headers are clean or per-file suppression lands.
  # TODO: promote to fatal once existing warnings are fixed.
  -Wconversion
  -Wno-sign-conversion
  -Wno-error=conversion

  # Stack protection: intentionally NOT passed as a raw flag here — without
  # CONFIG_STACK_CANARIES Zephyr provides no __stack_chk_guard setup and the
  # link fails ("GNU-style constructors required"). Enable stack protection
  # per-application via CONFIG_STACK_CANARIES (already done in test confs).

  # Zephyr callbacks often have unused parameters
  -Wno-unused-parameter

  # Deliberate #warning markers (e.g. the INSECURE CRC32-MIC notice) must
  # stay warnings, not errors.
  -Wno-error=cpp

  # Zephyr's MODEM_CHAT_*_DEFINE macros expand to "const static", tripping
  # -Wold-style-declaration (via -Wextra) in code we don't control.
  -Wno-old-style-declaration

  # Defensive enum range checks ("value >= FIRST_ENUMERATOR") are
  # deliberately tautological when the enum lowers to an unsigned type;
  # keep the guards, drop the -Wextra tautology complaint.
  -Wno-type-limits
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

# Recursively apply the hardening flags to every library target defined by
# the subdirectories above (LICHEN code only).
function(lichen_apply_hardening dir)
  get_property(subdirs DIRECTORY "${dir}" PROPERTY SUBDIRECTORIES)
  foreach(sd IN LISTS subdirs)
    lichen_apply_hardening("${sd}")
  endforeach()
  get_property(targets DIRECTORY "${dir}" PROPERTY BUILDSYSTEM_TARGETS)
  foreach(t IN LISTS targets)
    get_target_property(type ${t} TYPE)
    if(type STREQUAL "STATIC_LIBRARY" OR type STREQUAL "OBJECT_LIBRARY")
      target_compile_options(${t} PRIVATE ${LICHEN_HARDENING_FLAGS})
    endif()
  endforeach()
endfunction()

lichen_apply_hardening("${CMAKE_CURRENT_BINARY_DIR}/drivers")
lichen_apply_hardening("${CMAKE_CURRENT_BINARY_DIR}/lib")
lichen_apply_hardening("${CMAKE_CURRENT_BINARY_DIR}/subsys")
