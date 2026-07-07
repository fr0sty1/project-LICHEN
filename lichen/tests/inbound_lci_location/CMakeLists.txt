# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(inbound_lci_location)

target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src
)

target_sources(app PRIVATE
  src/main.c
  src/ble_uart_stub.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src/ble_lci_netif.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src/inbound_coap.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src/inbound_events.c
)

zephyr_linker_sources(DATA_SECTIONS
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/sections-ram.ld)
zephyr_iterable_section(
  NAME coap_resource_lichen_coap
  GROUP DATA_REGION ${XIP_ALIGN_WITH_INPUT}
  SUBALIGN CONFIG_LINKER_ITERABLE_SUBALIGN)
