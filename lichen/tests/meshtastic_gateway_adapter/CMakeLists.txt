# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(meshtastic_gateway_adapter)

target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src
)

target_sources(app PRIVATE
  src/fake_ble_meshtastic.c
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src/meshtastic_adapter.c
)
