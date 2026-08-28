# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)

if(DEFINED ENV{ZEPHYR_BASE})
  find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
  project(meshtastic_adapter_layout)
  target_sources(app PRIVATE src/main.c)
  target_include_directories(app PRIVATE
    ../../subsys/lichen/meshtastic/include
  )
else()
  project(meshtastic_adapter_layout C)
  add_executable(meshtastic_adapter_layout src/main.c)
  target_include_directories(meshtastic_adapter_layout PRIVATE
    stub
    ../../subsys/lichen/meshtastic/include
  )
  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/test_common.cmake)
  lichen_test_target(meshtastic_adapter_layout)
  # The production header incrementally annotates its API; this layout-only
  # consumer must not turn unrelated incomplete-nullability warnings into ABI
  # failures under Apple Clang.
  target_compile_options(meshtastic_adapter_layout PRIVATE
    -Wno-nullability-completeness
  )
  enable_testing()
  add_test(NAME meshtastic_adapter_layout COMMAND meshtastic_adapter_layout)
endif()
