# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(checkin_resource)

target_include_directories(app PRIVATE
  ../../include
  ../../subsys/lichen/coap/include
  ../../subsys/lichen/oscore/include
)

target_compile_definitions(app PRIVATE
  CONFIG_LICHEN_CHECKIN=1
  CONFIG_LICHEN_CHECKIN_RESOURCE=0
  CONFIG_LICHEN_CHECKIN_MAX_CHECKINS=8
  CONFIG_LICHEN_CHECKIN_MAX_ROLLCALLS=2
  CONFIG_LICHEN_CHECKIN_PAYLOAD_MAX=9600
  CONFIG_LICHEN_CHECKIN_LOG_LEVEL=4
  CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX=320
)

target_sources(app PRIVATE
  src/main.c
  ../../subsys/lichen/coap/checkin.c
  ../../subsys/lichen/coap/checkin_resource.c
)
