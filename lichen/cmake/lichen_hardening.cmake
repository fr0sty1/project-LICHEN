# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# Hardware memory safety checks for Linux border router builds.
# Enables ARM MTE (-fsanitize=memtag) or Intel CET (-fcf-protection=full)
# when the hardware and compiler support them.
#
# Policy: spec/appendix-c-safety.md

include(CheckCCompilerFlag)

# Cache results to avoid re-checking on every configure
set(LICHEN_HW_HARDENING_CHECKED FALSE CACHE INTERNAL "")

# Check if ARM Memory Tagging Extension (MTE) is supported.
# MTE requires ARM Cortex-A v8.5+ and Linux kernel 5.10+.
function(lichen_check_arm_mte out_supported)
    if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
        set(${out_supported} FALSE PARENT_SCOPE)
        return()
    endif()

    # Check compiler support
    check_c_compiler_flag("-fsanitize=memtag" LICHEN_COMPILER_SUPPORTS_MEMTAG)
    if(NOT LICHEN_COMPILER_SUPPORTS_MEMTAG)
        set(${out_supported} FALSE PARENT_SCOPE)
        return()
    endif()

    # Check for MTE runtime support via /proc/cpuinfo (Linux only)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND EXISTS "/proc/cpuinfo")
        file(READ "/proc/cpuinfo" _cpuinfo)
        if(_cpuinfo MATCHES "mte")
            set(${out_supported} TRUE PARENT_SCOPE)
            return()
        endif()
    endif()

    # Fall back to checking if we can compile and link a trivial MTE program
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=memtag")
    include(CheckCSourceCompiles)
    check_c_source_compiles("int main(void) { return 0; }" LICHEN_MTE_LINKS)
    if(LICHEN_MTE_LINKS)
        set(${out_supported} TRUE PARENT_SCOPE)
    else()
        set(${out_supported} FALSE PARENT_SCOPE)
    endif()
endfunction()

# Check if Intel Control-flow Enforcement Technology (CET) is supported.
# CET requires Intel 12th gen+ (Alder Lake) or AMD Zen 3+ CPUs.
function(lichen_check_intel_cet out_supported)
    if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64|x86-64)$")
        set(${out_supported} FALSE PARENT_SCOPE)
        return()
    endif()

    # Check compiler support for -fcf-protection=full
    check_c_compiler_flag("-fcf-protection=full" LICHEN_COMPILER_SUPPORTS_CET)
    if(NOT LICHEN_COMPILER_SUPPORTS_CET)
        set(${out_supported} FALSE PARENT_SCOPE)
        return()
    endif()

    # CET requires both compiler and linker support
    set(CMAKE_REQUIRED_FLAGS "-fcf-protection=full")
    include(CheckCSourceCompiles)
    check_c_source_compiles("int main(void) { return 0; }" LICHEN_CET_LINKS)
    if(LICHEN_CET_LINKS)
        set(${out_supported} TRUE PARENT_SCOPE)
    else()
        set(${out_supported} FALSE PARENT_SCOPE)
    endif()
endfunction()

# Apply hardware memory safety hardening to a target.
# For ARM64: enables MTE if supported
# For x86_64: enables CET if supported
# Does nothing on unsupported platforms (Cortex-M, etc.)
function(lichen_target_hardware_hardening target)
    get_target_property(_type ${target} TYPE)
    if(_type STREQUAL "INTERFACE_LIBRARY")
        message(WARNING "lichen_target_hardware_hardening: cannot apply to INTERFACE library ${target}")
        return()
    endif()

    # ARM Memory Tagging Extension
    lichen_check_arm_mte(_mte_supported)
    if(_mte_supported)
        target_compile_options(${target} PRIVATE -fsanitize=memtag)
        target_link_options(${target} PRIVATE -fsanitize=memtag)
        message(STATUS "LICHEN: ARM MTE enabled for ${target}")
        return()
    endif()

    # Intel Control-flow Enforcement Technology
    lichen_check_intel_cet(_cet_supported)
    if(_cet_supported)
        target_compile_options(${target} PRIVATE -fcf-protection=full)
        target_link_options(${target} PRIVATE -fcf-protection=full)
        message(STATUS "LICHEN: Intel CET enabled for ${target}")
        return()
    endif()

    message(STATUS "LICHEN: No hardware memory safety available for ${target} (platform: ${CMAKE_SYSTEM_PROCESSOR})")
endfunction()

# Global option to control hardware hardening
option(LICHEN_ENABLE_HW_HARDENING
    "Enable ARM MTE or Intel CET for Linux border router builds" ON)

# Print summary of detected capabilities
function(lichen_print_hardening_summary)
    message(STATUS "")
    message(STATUS "LICHEN Hardware Hardening Summary")
    message(STATUS "==================================")
    message(STATUS "  Platform: ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}")
    message(STATUS "  Compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")

    lichen_check_arm_mte(_mte)
    lichen_check_intel_cet(_cet)

    if(_mte)
        message(STATUS "  ARM MTE: AVAILABLE")
    else()
        message(STATUS "  ARM MTE: not available")
    endif()

    if(_cet)
        message(STATUS "  Intel CET: AVAILABLE")
    else()
        message(STATUS "  Intel CET: not available")
    endif()

    message(STATUS "")
endfunction()
