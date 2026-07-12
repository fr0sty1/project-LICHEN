# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

zephyr_library()

zephyr_library_sources(
  announce.c
  gradient.c
  router.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_LOADNG
  loadng.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_DTN
  dtn.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_ROUTING_STANDALONE_SCHNORR
  ${CMAKE_CURRENT_SOURCE_DIR}/../link/schnorr48.c
)

zephyr_include_directories(include)
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../link/include)
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../crypto)
