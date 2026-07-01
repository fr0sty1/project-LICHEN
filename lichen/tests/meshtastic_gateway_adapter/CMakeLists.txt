# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(meshtastic_gateway_adapter)

target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src
)

target_compile_definitions(app PRIVATE
  CONFIG_LORA_LICHEN_GATEWAY_MESSAGE_QUEUE_DEPTH=3
)

target_sources(app PRIVATE
  src/fake_ble_meshtastic.c
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src/inbound_coap.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src/inbound_events.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src/message_contract.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src/meshtastic_adapter.c
)
