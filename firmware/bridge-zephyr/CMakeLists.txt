cmake_minimum_required(VERSION 3.20.0)
include(${CMAKE_CURRENT_LIST_DIR}/../../lichen/cmake/lichen_build_epoch.cmake)
lichen_configure_time_build_epoch()
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(lichen_bridge)

target_sources(app PRIVATE
    src/main.c
)

# LICHEN L2/common sources are built by the Zephyr module. Keep bridge-zephyr
# as an application entrypoint so west workspaces do not link duplicate symbols
# from the legacy vendored copy under firmware/bridge-zephyr/subsys/lichen.
target_include_directories(app PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lichen/subsys/lichen/l2
)
