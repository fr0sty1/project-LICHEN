# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ble_app_owner)

target_include_directories(app PRIVATE ../../apps/gateway/src)
if(DEFINED BLE_APP_OWNER_TEST_MODE)
  if(BLE_APP_OWNER_TEST_MODE STREQUAL "native")
    target_compile_definitions(app PRIVATE CONFIG_LORA_LICHEN_BLE=1)
  elseif(BLE_APP_OWNER_TEST_MODE STREQUAL "meshtastic")
    target_compile_definitions(app PRIVATE CONFIG_LORA_LICHEN_MESHTASTIC_BLE=1)
  elseif(BLE_APP_OWNER_TEST_MODE STREQUAL "meshcore")
    target_compile_definitions(app PRIVATE CONFIG_LORA_LICHEN_MESHCORE_BLE=1)
  else()
    message(FATAL_ERROR "Unsupported BLE_APP_OWNER_TEST_MODE=${BLE_APP_OWNER_TEST_MODE}")
  endif()
endif()
target_sources(app PRIVATE
  ../../apps/gateway/src/ble_app_owner.c
  ../../apps/gateway/src/ble_uart.c
  src/ble_ingress_stub.c
  src/main.c)
