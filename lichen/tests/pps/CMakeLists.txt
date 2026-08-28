# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)

if(DEFINED ENV{ZEPHYR_BASE})
  find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
  project(pps)
else()
  project(pps C)
  find_package(Threads REQUIRED)
endif()

set(PPS_SOURCE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/link/pps.c)
set(LINK_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/link/include)

if(DEFINED ENV{ZEPHYR_BASE})
  target_sources(app PRIVATE src/main.c ${PPS_SOURCE})
  target_include_directories(app PRIVATE ${LINK_INCLUDE})
else()
  add_executable(pps src/main.c ${PPS_SOURCE})
  target_include_directories(pps PRIVATE ${LINK_INCLUDE})
  target_link_libraries(pps PRIVATE Threads::Threads)
  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/test_common.cmake)
  lichen_test_target(pps)
  enable_testing()
  add_test(NAME pps COMMAND pps)
endif()
