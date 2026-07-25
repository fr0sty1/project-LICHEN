# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN EDHOC subsystem

zephyr_library()

zephyr_library_sources(
  edhoc_crypto.c
  edhoc_kdf.c
  edhoc_sign.c
  edhoc_initiator.c
  edhoc_responder.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
