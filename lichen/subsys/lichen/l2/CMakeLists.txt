# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

zephyr_library()

zephyr_library_sources(
  crash_info.c
  lichen_util.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_IPV6 ipv6_addr.c)
zephyr_library_sources_ifdef(CONFIG_LICHEN_LORA_L2 lora_l2.c)
zephyr_library_sources_ifdef(CONFIG_LICHEN_L2 lichen_l2.c)

# Dev provisioning installs a static IPv6 neighbor entry via the internal
# net_ipv6_nbr_add() (no public static-neighbor API in Zephyr 3.7).
if(CONFIG_LICHEN_L2_DEV_PROVISIONING)
  zephyr_library_include_directories(${ZEPHYR_BASE}/subsys/net/ip)
endif()

zephyr_include_directories(.)
