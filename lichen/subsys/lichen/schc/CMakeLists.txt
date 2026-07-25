# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN SCHC header compression

zephyr_library()

zephyr_library_sources(
  schc.c
  schc_checksum.c
  schc_compress.c
  schc_decompress.c
  schc_helpers.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
