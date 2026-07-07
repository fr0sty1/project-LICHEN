# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)

include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/lichen_build_epoch.cmake)

set(LICHEN_BUILD_EPOCH_TEST_CASE "source_date_epoch" CACHE STRING
  "Build epoch test case")
set(_developer_generated_checked 0)

if(LICHEN_BUILD_EPOCH_TEST_CASE STREQUAL "source_date_epoch")
  set(ENV{SOURCE_DATE_EPOCH} "1711111111")
  set(LICHEN_TIME_BUILD_EPOCH_MODE "production" CACHE STRING "" FORCE)
  set(_expected_epoch 1711111111)
  set(_expected_source SOURCE_DATE_EPOCH)
  lichen_configure_time_build_epoch()
elseif(LICHEN_BUILD_EPOCH_TEST_CASE STREQUAL "release")
  unset(ENV{SOURCE_DATE_EPOCH})
  set(LICHEN_TIME_BUILD_EPOCH_MODE "production" CACHE STRING "" FORCE)
  set(LICHEN_RELEASE_EPOCH_UNIX "1712222222" CACHE STRING "" FORCE)
  set(_expected_epoch 1712222222)
  set(_expected_source RELEASE)
  lichen_configure_time_build_epoch()
elseif(LICHEN_BUILD_EPOCH_TEST_CASE STREQUAL "developer_generated")
  unset(ENV{SOURCE_DATE_EPOCH})
  set(LICHEN_TIME_BUILD_EPOCH_MODE "developer-generated" CACHE STRING "" FORCE)
  set(_expected_source DEVELOPER_GENERATED)
  lichen_configure_time_build_epoch()
  set(_expected_epoch ${LICHEN_TIME_BUILD_EPOCH_RESOLVED})
  set(_developer_generated_checked ${LICHEN_TIME_BUILD_EPOCH_GENERATED})
elseif(LICHEN_BUILD_EPOCH_TEST_CASE STREQUAL "developer_fixed")
  unset(ENV{SOURCE_DATE_EPOCH})
  set(LICHEN_TIME_BUILD_EPOCH_MODE "developer-generated" CACHE STRING "" FORCE)
  set(LICHEN_DEVELOPER_BUILD_EPOCH_UNIX "1713333333" CACHE STRING "" FORCE)
  set(_expected_epoch 1713333333)
  set(_expected_source DEVELOPER_FIXED)
  lichen_configure_time_build_epoch()
else()
  message(FATAL_ERROR "Unsupported LICHEN_BUILD_EPOCH_TEST_CASE=${LICHEN_BUILD_EPOCH_TEST_CASE}")
endif()

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(build_epoch)

target_compile_definitions(app PRIVATE
  LICHEN_BUILD_EPOCH_EXPECTED_EPOCH=${_expected_epoch}
  LICHEN_BUILD_EPOCH_DEVELOPER_GENERATED_CHECKED=$<BOOL:${_developer_generated_checked}>
  LICHEN_BUILD_EPOCH_EXPECT_SOURCE_${_expected_source}=1)
target_sources(app PRIVATE src/main.c)
