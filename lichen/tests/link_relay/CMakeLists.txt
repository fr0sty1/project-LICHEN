# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(link_relay)

target_sources(app PRIVATE src/main.c)

if(CONFIG_TEST_RANDOM_GENERATOR)
  zephyr_ld_options(-Wl,--wrap=z_impl_sys_csrand_get)
endif()
