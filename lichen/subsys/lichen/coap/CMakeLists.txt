# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN CoAP subsystem

zephyr_library()

zephyr_library_sources_ifdef(CONFIG_LICHEN_COAP_CLIENT
  coap_client.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_COAP_SERVER_STANDALONE
  coap_server.c
)

# Standalone (lichen_coap_server) is mutually exclusive with
# LICHEN_COAP_CONFIG (see Kconfig); modular lichen_coap is preferred
# single owner for gateway/nucleo_wl55jc/r1_neo (worker8 conditionalized
# standalone server; no resource renaming). lichen_coap iterable section
# ensured for gateways; correct service (lichen_coap not _server) provided
# by app CMake. subsys provides sections-ram.ld for standalone.
if(CONFIG_LICHEN_COAP_SERVER_STANDALONE)
  zephyr_linker_sources(DATA_SECTIONS sections-ram.ld)
  zephyr_iterable_section(
    NAME coap_resource_lichen_coap_server
    GROUP DATA_REGION ${XIP_ALIGN_WITH_INPUT}
    SUBALIGN CONFIG_LINKER_ITERABLE_SUBALIGN)
endif()

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

zephyr_library_sources_ifdef(CONFIG_LICHEN_COAP_LOCATION
  coap_location.c
)
zephyr_library_sources_ifdef(CONFIG_LICHEN_COAP_DEADDROP
  coap_dtn.c
)

if(CONFIG_LICHEN_COAP_LOCATION)
  zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../l2)
endif()

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
