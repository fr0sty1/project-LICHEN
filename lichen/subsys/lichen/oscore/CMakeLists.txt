# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN OSCORE subsystem

zephyr_library()

zephyr_library_sources(
  oscore_ctx.c
  oscore_cbor.c
  oscore_option.c
  oscore_replay.c
  oscore_nonce.c
  oscore_protect.c
  oscore_persist.c
  hkdf.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_OSCORE_SETTINGS
  oscore_settings.c
)

zephyr_library_sources_ifdef(CONFIG_COAP_SERVER
  coap_oscore.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../crypto)
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../coap/include)
