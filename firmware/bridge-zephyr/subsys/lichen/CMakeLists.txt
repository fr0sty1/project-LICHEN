# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

zephyr_library()

# Common utilities (always built when LICHEN subsystem is enabled)
zephyr_library_sources(
    lichen_util.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_LORA_L2
    lora_l2.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_L2
    lichen_l2.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_IPV6
    ipv6_addr.c
)

zephyr_include_directories(.)

# Include LICHEN subsystem headers when link layer is enabled
zephyr_include_directories_ifdef(CONFIG_LICHEN_LINK
    ${ZEPHYR_BASE}/../lichen/subsys/lichen/link/include
    ${ZEPHYR_BASE}/../lichen/subsys/lichen/schc/include
)
