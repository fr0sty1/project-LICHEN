# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(coap_keys_lifecycle)

zephyr_compile_options(-Wno-error=duplicated-branches)
set(LICHEN_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
target_compile_definitions(app PRIVATE
  CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES=4
  CONFIG_LICHEN_COAP_KEYS_LOG_LEVEL=0
  CONFIG_LICHEN_COAP_KEYS_TEST_HOOKS=1
)
target_sources(app PRIVATE
  src/main.c
  ${LICHEN_ROOT}/subsys/lichen/coap/coap_keys_store.c
  ${LICHEN_ROOT}/subsys/lichen/coap/coap_keys_settings.c
  ${LICHEN_ROOT}/subsys/lichen/crypto/monocypher.c
)
target_include_directories(app PRIVATE
  ${LICHEN_ROOT}/subsys/lichen/coap/include
  ${LICHEN_ROOT}/subsys/lichen/coap
  ${LICHEN_ROOT}/subsys/lichen/crypto
)
