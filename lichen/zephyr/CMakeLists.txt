# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN Zephyr module CMake extension

include(CheckCCompilerFlag)

# GCC 12 (Zephyr SDK 0.16.8) implements C23 under its draft spelling,
# -std=c2x.  Newer compilers accept the final -std=c23 spelling.  Probe both
# rather than keying this to a vendor/version pair, and fail configuration if
# neither is available: silently compiling LICHEN as Zephyr's C99 default
# would disable language-level checks used by the module.
check_c_compiler_flag("-std=c23" LICHEN_COMPILER_SUPPORTS_STD_C23)
if(LICHEN_COMPILER_SUPPORTS_STD_C23)
  set(LICHEN_C_DIALECT_FLAG -std=c23)
else()
  check_c_compiler_flag("-std=c2x" LICHEN_COMPILER_SUPPORTS_STD_C2X)
  if(NOT LICHEN_COMPILER_SUPPORTS_STD_C2X)
    message(FATAL_ERROR
      "LICHEN requires a C23 compiler (-std=c23 or -std=c2x)")
  endif()
  set(LICHEN_C_DIALECT_FLAG -std=c2x)
endif()
message(STATUS "LICHEN: using ${LICHEN_C_DIALECT_FLAG}")

# Zephyr v3.7.x — the west.yml pin (lichen/west.yml revision v3.7.0) —
# appends its Kconfig-selected C dialect after module target options, so a
# target-local -std option is silently overridden by the default -std=c99.
# Its deprecated global CSTD hook (read at the end of zephyr/CMakeLists.txt
# in v3.7.0) is evaluated after all modules, making the value set here
# authoritative on that tree.  Zephyr 4.1.0 has no reader for this property
# (its dialect comes from CONFIG_STD_*), so this is inert there.
# The value must use Zephyr's own std spelling: v3.7 feeds it to both
# ${compile_features_${CSTD}} and -std=${CSTD}, and "c23" is neither a known
# compile-features id nor accepted by the SDK's GCC 12 — only "c2x" is.
# C23 semantics are unaffected (c2x is GCC 12's draft spelling of C23); the
# probe above remains as a configure-time guard that the toolchain speaks
# C23 under one of its two spellings.
set_property(GLOBAL PROPERTY CSTD c2x)

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
  -Wformat-truncation=2

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

  # Pointer safety
  -Wnull-dereference
  -Wcast-align

  # Implicit float promotion (catches float→double on soft-float MCUs)
  -Wdouble-promotion

  # Stack usage limit (2KB per function — catches runaway VLAs/alloca).
  # Unconditional across word sizes: first-party code is held to 2048 even
  # on 64-bit host builds (native_sim/native/64).  The only known offender
  # is vendored Monocypher (crypto_argon2, monocypher.c:749 — 2464B on one
  # 64-bit toolchain, 3424B on the AWS gcc11 build), which carries a
  # per-file -Wno-error=stack-usage= exception in
  # subsys/lichen/crypto/CMakeLists.txt that keeps the warning visible.
  -Wstack-usage=2048

  # Strict aliasing violations
  -Wstrict-aliasing=2
  -fstrict-aliasing

  # Array bounds checking (GCC)
  -Warray-bounds=2

  # Uninitialized variables (aggressive)
  -Wmaybe-uninitialized

  # Logical op warnings
  -Wlogical-op

  # Duplicate conditions in if-else chains
  -Wduplicated-cond
  -Wduplicated-branches

  # Switch/enum exhaustiveness
  -Wswitch-enum

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

# Public module headers (for example <lichen/lichen_log.h>) are shared by
# multiple subsystems and drivers, so expose them before creating targets.
zephyr_include_directories(${CMAKE_CURRENT_LIST_DIR}/../include)

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
