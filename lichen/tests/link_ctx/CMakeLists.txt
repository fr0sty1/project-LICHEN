# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(link_ctx_test C)

find_package(Threads REQUIRED)

add_executable(link_ctx_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/csma.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/link_ctx.c
)
set_target_properties(link_ctx_test PROPERTIES
  C_STANDARD 11
  C_STANDARD_REQUIRED YES
  C_EXTENSIONS OFF
)
target_include_directories(link_ctx_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)
target_compile_definitions(link_ctx_test PRIVATE
  CONFIG_LICHEN_LINK_MAX_NEIGHBORS=16
)
target_compile_options(link_ctx_test PRIVATE -Wall -Wextra -Werror)
if(APPLE)
  target_compile_definitions(link_ctx_test PRIVATE explicit_bzero=bzero)
  target_compile_options(link_ctx_test PRIVATE -include strings.h)
endif()
target_link_libraries(link_ctx_test PRIVATE Threads::Threads)

include(CTest)
add_test(NAME link_ctx COMMAND link_ctx_test)
