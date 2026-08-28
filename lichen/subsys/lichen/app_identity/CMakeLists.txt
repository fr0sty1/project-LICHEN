# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

zephyr_library()
zephyr_library_sources(app_identity.c identity_store.c)
zephyr_library_sources_ifdef(CONFIG_LICHEN_APP_IDENTITY_PERSIST
	identity_settings.c)
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../link/include)
