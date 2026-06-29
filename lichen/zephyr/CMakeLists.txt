# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN Zephyr module CMake extension

add_subdirectory(../drivers drivers)
add_subdirectory(../subsys subsys)

# L2 integration from bridge-zephyr (Zephyr network stack integration)
set(LICHEN_BRIDGE_ZEPHYR_SUBSYS_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../../firmware/bridge-zephyr/subsys")
get_filename_component(LICHEN_BRIDGE_ZEPHYR_SUBSYS_DIR
    "${LICHEN_BRIDGE_ZEPHYR_SUBSYS_DIR}" REALPATH)

if(NOT EXISTS "${LICHEN_BRIDGE_ZEPHYR_SUBSYS_DIR}/CMakeLists.txt")
  message(FATAL_ERROR
      "LICHEN bridge-zephyr subsystem not found: "
      "${LICHEN_BRIDGE_ZEPHYR_SUBSYS_DIR}")
endif()

get_filename_component(LICHEN_BRIDGE_ZEPHYR_APP_DIR
    "${LICHEN_BRIDGE_ZEPHYR_SUBSYS_DIR}/.." REALPATH)
set(LICHEN_ADD_BRIDGE_ZEPHYR_SUBSYS TRUE)

if(DEFINED APPLICATION_SOURCE_DIR)
  get_filename_component(LICHEN_APPLICATION_SOURCE_DIR
      "${APPLICATION_SOURCE_DIR}" REALPATH)
  if(LICHEN_APPLICATION_SOURCE_DIR STREQUAL LICHEN_BRIDGE_ZEPHYR_APP_DIR)
    set(LICHEN_ADD_BRIDGE_ZEPHYR_SUBSYS FALSE)
  endif()
endif()

if(LICHEN_ADD_BRIDGE_ZEPHYR_SUBSYS)
  add_subdirectory("${LICHEN_BRIDGE_ZEPHYR_SUBSYS_DIR}" bridge-zephyr-subsys)
endif()
