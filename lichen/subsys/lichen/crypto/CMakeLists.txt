# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN crypto subsystem

zephyr_library()

zephyr_library_sources_ifdef(CONFIG_LICHEN_CRYPTO_MONOCYPHER
  monocypher.c
  monocypher-ed25519.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_CRYPTO_AES_CCM
  aes_ccm.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR})
