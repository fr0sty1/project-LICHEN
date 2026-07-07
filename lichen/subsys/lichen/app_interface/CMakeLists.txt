# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

zephyr_library()
zephyr_library_sources(app_interface.c)
if(CONFIG_LICHEN_HAL)
  zephyr_library_sources(hal_bridge.c)
  zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../hal/include)
endif()
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
