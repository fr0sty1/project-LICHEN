# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
#
# Common CMake config for standalone (non-Zephyr) LICHEN tests.
# Enables sanitizers and hardening flags.
#
# Usage in test CMakeLists.txt:
#   include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)
#   lichen_test_target(my_test_executable)

include(CheckCCompilerFlag)

# Standalone config header directory (provides CONFIG_* defaults)
set(LICHEN_STANDALONE_CONFIG_DIR "${CMAKE_CURRENT_LIST_DIR}" CACHE PATH
    "Directory containing standalone_config.h")

# Sanitizer control (can be overridden via -D on cmake command line)
option(LICHEN_TEST_ASAN "Enable AddressSanitizer" ON)
option(LICHEN_TEST_UBSAN "Enable UndefinedBehaviorSanitizer" ON)

# Apply sanitizers and hardening to a test target
function(lichen_test_target target)
    # Include standalone config header directory for CONFIG_* defaults
    target_include_directories(${target} PRIVATE ${LICHEN_STANDALONE_CONFIG_DIR})

    # Provide CONFIG_* defaults for standalone builds (Zephyr provides these via autoconf.h)
    target_compile_definitions(${target} PRIVATE
        CONFIG_LICHEN_LINK_MAX_NEIGHBORS=16
    )

    # Hardening flags - NO EXCEPTIONS
    target_compile_options(${target} PRIVATE
        -std=c23
        -Wall -Wextra -Werror
        -Wformat=2
        -Wshadow
        -Wconversion
        -Wno-sign-conversion
        -Wnull-dereference
        -Wdouble-promotion
        -fstack-protector-strong
    )

    # Sanitizers (host builds only)
    set(_san_flags "")

    if(LICHEN_TEST_ASAN)
        check_c_compiler_flag("-fsanitize=address" _has_asan)
        if(_has_asan)
            list(APPEND _san_flags "-fsanitize=address")
        endif()
    endif()

    if(LICHEN_TEST_UBSAN)
        check_c_compiler_flag("-fsanitize=undefined" _has_ubsan)
        if(_has_ubsan)
            list(APPEND _san_flags "-fsanitize=undefined")
            list(APPEND _san_flags "-fno-sanitize-recover=all")
        endif()
    endif()

    if(_san_flags)
        list(APPEND _san_flags "-fno-omit-frame-pointer")
        target_compile_options(${target} PRIVATE ${_san_flags})
        target_link_options(${target} PRIVATE ${_san_flags})
        message(STATUS "LICHEN test ${target}: sanitizers enabled")
    endif()
endfunction()
