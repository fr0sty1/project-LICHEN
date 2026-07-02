# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(meshtastic_gateway_adapter)

target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src
)

if(TARGET drivers__bluetooth)
  # Twister adds -Werror, but Zephyr 3.7 native_sim's Bluetooth user channel
  # trips GCC 13's fortified read() stringop-overflow analysis. Keep the waiver
  # scoped to Zephyr's Bluetooth driver library so LICHEN test sources still fail
  # on the same diagnostic.
  target_compile_options(drivers__bluetooth PRIVATE -Wno-error=stringop-overflow)
endif()

target_sources(app PRIVATE
  src/fake_ble_meshtastic.c
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src/inbound_coap.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src/inbound_events.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src/message_contract.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src/meshtastic_adapter.c
)

zephyr_linker_sources(DATA_SECTIONS
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/sections-ram.ld)
zephyr_iterable_section(
  NAME coap_resource_lichen_coap
  GROUP DATA_REGION ${XIP_ALIGN_WITH_INPUT}
  SUBALIGN CONFIG_LINKER_ITERABLE_SUBALIGN)
