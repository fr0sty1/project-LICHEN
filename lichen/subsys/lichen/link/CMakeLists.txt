# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN link layer

zephyr_library()

zephyr_library_sources(
  frame.c
  lichen_link_rx.c
  lichen_link_tx.c
  link_ctx.c
  replay.c
  tx_queue.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_LINK_SCHNORR
  schnorr48.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_LINK_EPOCH_PERSIST
  epoch_persist.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Include L2 headers for EUI-64 derivation and shared utilities
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../l2)

# Include SCHC headers for compression/decompression
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../schc/include)

# Include shared crypto headers for Schnorr-48 and AES-CCM MIC computation
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../crypto)
