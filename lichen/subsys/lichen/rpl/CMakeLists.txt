# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN RPL routing

zephyr_library()

zephyr_library_sources(
  trickle.c
  messages.c
  rpl_dis.c
  dodag.c
  rpl_srh.c
  rpl_prefix.c
  rpl_routing_table.c
  rpl_dao_build.c
  rpl_dao_timing.c
  rpl_dao_process.c
  rpl_short_assignment.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
