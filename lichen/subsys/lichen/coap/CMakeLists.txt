# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN CoAP subsystem

zephyr_library()

zephyr_library_sources_ifdef(CONFIG_LICHEN_COAP_CLIENT
  coap_client.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_COAP_SERVER
  coap_server.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_COAP_STATUS
  coap_status.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_COAP_CONFIG
  coap_config.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_COAP_MSG
  coap_msg.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_COAP_KEYS
  coap_keys.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
