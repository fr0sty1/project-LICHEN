# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/lichen_build_epoch.cmake)
lichen_configure_time_build_epoch()
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(lichen_puck)

target_sources(app PRIVATE src/main.c src/puck_location.c)
target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/native/include)

zephyr_linker_sources(DATA_SECTIONS sections-ram.ld)
zephyr_iterable_section(
  NAME coap_resource_lichen_coap
  GROUP DATA_REGION ${XIP_ALIGN_WITH_INPUT}
  SUBALIGN CONFIG_LINKER_ITERABLE_SUBALIGN)
# Server section owned exclusively by subsys/lichen/coap/CMakeLists.txt
# under CONFIG_LICHEN_COAP_SERVER_STANDALONE (mutually exclusive with
# modular LICHEN_COAP_CONFIG used by puck/gateway per Kconfig and
# AGENTS.md init graph). Avoids duplication/symbol conflicts from
# worker3 merge.
