# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(coap_status_get)

target_include_directories(app PRIVATE
  ../../include
  ../../subsys/lichen/coap/include
)

target_compile_definitions(app PRIVATE
  CONFIG_LICHEN_COAP_STATUS=1
  CONFIG_LICHEN_COAP_STATUS_LOG_LEVEL=4
)

target_sources(app PRIVATE
  src/main.c
  ../../subsys/lichen/coap/coap_status.c
)
