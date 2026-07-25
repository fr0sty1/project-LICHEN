# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# Runtime sanitizers for host-side testing.
# NOT for embedded targets — these require OS runtime support.
#
# Usage:
#   include(lichen_sanitizers)
#   lichen_target_sanitizers(my_test_target)
#
# Policy: spec/appendix-c-safety.md

include(CheckCCompilerFlag)

# Sanitizer options
option(LICHEN_ENABLE_ASAN "Enable AddressSanitizer" ON)
option(LICHEN_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" ON)
option(LICHEN_ENABLE_TSAN "Enable ThreadSanitizer (mutually exclusive with ASAN)" OFF)
option(LICHEN_ENABLE_MSAN "Enable MemorySanitizer (Clang only, mutually exclusive with ASAN)" OFF)

# Check if we're on a platform that supports sanitizers
function(lichen_sanitizers_available out_var)
    # Sanitizers require hosted environment (not bare-metal)
    if(CMAKE_SYSTEM_NAME STREQUAL "Generic" OR
       CMAKE_CROSSCOMPILING OR
       DEFINED ZEPHYR_BASE)
        set(${out_var} FALSE PARENT_SCOPE)
        return()
    endif()

    # Check compiler support
    check_c_compiler_flag("-fsanitize=address" _asan_supported)
    set(${out_var} ${_asan_supported} PARENT_SCOPE)
endfunction()

# Apply sanitizers to a target
function(lichen_target_sanitizers target)
    lichen_sanitizers_available(_available)
    if(NOT _available)
        message(STATUS "LICHEN: Sanitizers not available for ${target} (cross-compile or bare-metal)")
        return()
    endif()

    set(_san_flags "")
    set(_san_names "")

    # ASAN and TSAN/MSAN are mutually exclusive
    if(LICHEN_ENABLE_ASAN AND NOT LICHEN_ENABLE_TSAN AND NOT LICHEN_ENABLE_MSAN)
        list(APPEND _san_flags "-fsanitize=address")
        list(APPEND _san_names "ASAN")
    endif()

    if(LICHEN_ENABLE_UBSAN)
        list(APPEND _san_flags "-fsanitize=undefined")
        list(APPEND _san_flags "-fno-sanitize-recover=all")
        list(APPEND _san_names "UBSAN")
    endif()

    if(LICHEN_ENABLE_TSAN AND NOT LICHEN_ENABLE_ASAN)
        list(APPEND _san_flags "-fsanitize=thread")
        list(APPEND _san_names "TSAN")
    endif()

    if(LICHEN_ENABLE_MSAN AND NOT LICHEN_ENABLE_ASAN AND CMAKE_C_COMPILER_ID STREQUAL "Clang")
        list(APPEND _san_flags "-fsanitize=memory")
        list(APPEND _san_flags "-fsanitize-memory-track-origins=2")
        list(APPEND _san_names "MSAN")
    endif()

    if(_san_flags)
        # Frame pointers required for useful stack traces
        list(APPEND _san_flags "-fno-omit-frame-pointer")
        list(APPEND _san_flags "-fno-optimize-sibling-calls")

        target_compile_options(${target} PRIVATE ${_san_flags})
        target_link_options(${target} PRIVATE ${_san_flags})

        list(JOIN _san_names "+" _san_list)
        message(STATUS "LICHEN: Sanitizers enabled for ${target}: ${_san_list}")
    endif()
endfunction()

# Convenience function to apply sanitizers to all test targets in a directory
function(lichen_sanitize_tests dir)
    get_property(targets DIRECTORY "${dir}" PROPERTY BUILDSYSTEM_TARGETS)
    foreach(t IN LISTS targets)
        get_target_property(type ${t} TYPE)
        if(type STREQUAL "EXECUTABLE")
            lichen_target_sanitizers(${t})
        endif()
    endforeach()
endfunction()
