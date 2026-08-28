# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN link layer

zephyr_library()

zephyr_library_sources(
  csma.c
  frame_pool.c
  frame.c
  hash32.c
  identity_addr.c
  lichen_link_rx.c
  lichen_link_tx.c
  link_ctx.c
  replay.c
  tx_queue.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_LINK_CCP16_LOAD_BALANCING
  rf_health.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_LINK_SCHNORR
  schnorr48.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_LINK_EPOCH_PERSIST
  epoch_persist.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_LINK_REPLAY_PERSIST
  replay_persist.c
  replay_settings.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_TDMA
  tdma.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_CCP_TIME_SYNC
  drift_bound.c
  pps.c
  time_sync.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_SYNC_HOP
  sync_hop.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_SOS_RATELIMIT
  sos_ratelimit.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_LINK_SCHNORR
  sos_origin.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Include L2 headers for EUI-64 derivation and shared utilities
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../l2)

# Include SCHC headers for compression/decompression
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../schc/include)

# Include shared crypto headers for Schnorr-48 signatures (Monocypher).
# AES-CCM is not used by the link layer; encrypted frames (E=1) are rejected.
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../crypto)
