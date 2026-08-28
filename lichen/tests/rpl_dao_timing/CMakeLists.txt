# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)

if(DEFINED ENV{ZEPHYR_BASE})
  find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
  project(rpl_dao_timing)
else()
  project(rpl_dao_timing C)
endif()

set(RPL_SOURCE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/rpl/rpl_dao_timing.c)
set(RPL_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/rpl/include)

if(DEFINED ENV{ZEPHYR_BASE})
  target_sources(app PRIVATE main.c ${RPL_SOURCE})
  target_include_directories(app PRIVATE ${RPL_INCLUDE})
else()
  add_executable(rpl_dao_timing main.c ${RPL_SOURCE})
  target_include_directories(rpl_dao_timing PRIVATE ${RPL_INCLUDE})
  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/test_common.cmake)
  lichen_test_target(rpl_dao_timing)
  enable_testing()
  add_test(NAME rpl_dao_timing COMMAND rpl_dao_timing)
endif()
