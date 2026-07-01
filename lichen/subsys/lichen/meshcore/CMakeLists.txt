# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

zephyr_library()

zephyr_library_sources(codec.c)
zephyr_library_sources_ifdef(CONFIG_LICHEN_MESHCORE_ADAPTER adapter.c)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
