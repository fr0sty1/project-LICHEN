# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN SenML subsystem

zephyr_library()

zephyr_library_sources(
  senml.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
# senml.c uses the lichen/errno.h portability shim (under Zephyr it just
# includes <errno.h>); it lives in the link subsystem's include tree.
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../link/include)
