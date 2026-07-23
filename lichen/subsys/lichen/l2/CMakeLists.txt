# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

zephyr_library()

zephyr_library_sources(
  crash_info.c
  lichen_util.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_IPV6 ipv6_addr.c)
zephyr_library_sources_ifdef(CONFIG_LICHEN_ICMPV6 icmpv6.c)
zephyr_library_sources_ifdef(CONFIG_LICHEN_LORA_L2 lora_l2.c)
zephyr_library_sources_ifdef(CONFIG_LICHEN_L2 lichen_l2.c)

# Dev provisioning installs a static IPv6 neighbor entry via the internal
# net_ipv6_nbr_add() (no public static-neighbor API in Zephyr 3.7).
if(CONFIG_LICHEN_L2_DEV_PROVISIONING)
  zephyr_library_include_directories(${ZEPHYR_BASE}/subsys/net/ip)
endif()

zephyr_include_directories(.)
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../link/include)

# Link subsystem headers required for lichen_identity_ygg_addr_from_ed25519
# (used by lichen_yggdrasil_addr in ipv6_addr.c). Matches pattern used in
# routing/ and senml/ CMakeLists.txt.
