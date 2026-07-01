# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(meshtastic_ble)

target_compile_definitions(app PRIVATE
  CONFIG_LORA_LICHEN_MESHTASTIC_BLE_QUEUE_DEPTH=4
  CONFIG_LORA_LICHEN_MESHTASTIC_BLE_TO_RADIO_QUEUE_DEPTH=4)
target_include_directories(app PRIVATE ../../apps/gateway/src)
target_sources(app PRIVATE
  ../../apps/gateway/src/ble_meshtastic.c
  src/main.c)
