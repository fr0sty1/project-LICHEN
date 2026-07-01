# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

zephyr_library()

# Common utilities (always built when LICHEN subsystem is enabled)
zephyr_library_sources(
    lichen_util.c
    crash_info.c
)

if(DEFINED CONFIG_LICHEN_LORA_L2 AND CONFIG_LICHEN_LORA_L2)
    zephyr_library_sources(lora_l2.c)
endif()

if(DEFINED CONFIG_LICHEN_L2 AND CONFIG_LICHEN_L2)
    zephyr_library_sources(lichen_l2.c)
endif()

if(DEFINED CONFIG_LICHEN_IPV6 AND CONFIG_LICHEN_IPV6)
    zephyr_library_sources(ipv6_addr.c)
endif()

zephyr_include_directories(.)

# Include LICHEN subsystem headers when link layer is enabled
zephyr_include_directories_ifdef(CONFIG_LICHEN_LINK
    ${ZEPHYR_BASE}/../lichen/subsys/lichen/link/include
    ${ZEPHYR_BASE}/../lichen/subsys/lichen/schc/include
)
