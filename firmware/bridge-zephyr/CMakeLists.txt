cmake_minimum_required(VERSION 3.20.0)
include(${CMAKE_CURRENT_LIST_DIR}/../../lichen/cmake/lichen_build_epoch.cmake)
lichen_configure_time_build_epoch()
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(lichen_bridge)

# Bridge-zephyr subsystem sources (directly in app since zephyr_library
# from app subdirs doesn't auto-link)
target_sources(app PRIVATE
    src/main.c
    subsys/lichen/ipv6_addr.c
    subsys/lichen/lichen_util.c
    subsys/lichen/crash_info.c
)

# Add LoRa hardware access only on boards with a LoRa radio configured.
target_sources_ifdef(CONFIG_LICHEN_LORA_L2 app PRIVATE
    subsys/lichen/lora_l2.c
)

# Add lichen_l2.c only when full networking stack is enabled
target_sources_ifdef(CONFIG_LICHEN_L2 app PRIVATE
    subsys/lichen/lichen_l2.c
)

# Include headers from subsystems
target_include_directories(app PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/subsys/lichen
)
