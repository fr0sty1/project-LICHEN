# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(app_identity_rollback)

zephyr_compile_options(-Wno-error=duplicated-branches)

set(LICHEN_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
target_sources(app PRIVATE
  ../app_identity/src/identity_store.c
  src/link_stubs.c
  ${LICHEN_ROOT}/subsys/lichen/app_identity/identity_store.c
  ${LICHEN_ROOT}/subsys/lichen/app_identity/identity_settings.c
  ${LICHEN_ROOT}/subsys/lichen/crypto/monocypher.c
)
target_include_directories(app PRIVATE
  ${LICHEN_ROOT}/subsys/lichen/app_identity/include
  ${LICHEN_ROOT}/subsys/lichen/link/include
  ${LICHEN_ROOT}/subsys/lichen/crypto
)
