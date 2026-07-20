cmake_minimum_required(VERSION 3.20.0)
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/lichen_build_epoch.cmake)
lichen_configure_time_build_epoch()
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(lichen_puck)

target_sources(app PRIVATE src/main.c src/puck_location.c)
target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/native/include)
