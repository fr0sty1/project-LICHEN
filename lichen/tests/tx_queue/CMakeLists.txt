# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(tx_queue_test C)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

add_executable(tx_queue_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/tx_queue.c
)

target_compile_definitions(tx_queue_test PRIVATE CONFIG_TX_QUEUE_TEST_TIME)
target_compile_options(tx_queue_test PRIVATE -Wall -Wextra -Werror)
target_link_libraries(tx_queue_test pthread)
