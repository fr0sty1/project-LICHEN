# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(coap_location_beacon)

target_include_directories(app PRIVATE
  stub_include
  ../../subsys/lichen/coap/include
  ../../subsys/lichen/hal/include
  ../../subsys/lichen/senml/include
  ../../subsys/lichen/l2
  ../../subsys/lichen/l2/include
  ../../subsys/lichen/oscore/include
  ../../subsys/lichen/link/include
)

target_compile_definitions(app PRIVATE
  CONFIG_LICHEN_COAP_LOCATION_LOG_LEVEL=4
  CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX=256
)

target_sources(app PRIVATE
  src/main.c
  ../../subsys/lichen/coap/coap_location.c
)

zephyr_linker_sources(DATA_SECTIONS
  ../../subsys/lichen/coap/sections-ram.ld
)
zephyr_iterable_section(
  NAME coap_resource_lichen_coap_server
  GROUP DATA_REGION ${XIP_ALIGN_WITH_INPUT}
  SUBALIGN CONFIG_LINKER_ITERABLE_SUBALIGN
)
