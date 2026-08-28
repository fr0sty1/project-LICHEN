# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(schc_mqtt_sn_test C)

include(../cmake/test_common.cmake)

add_executable(schc_mqtt_sn_test
  main.c
  ../../subsys/schc/bitstream.c
  ../../subsys/schc/schc.c
  ../../subsys/lichen/schc/schc.c
  ../../subsys/lichen/schc/schc_checksum.c
  ../../subsys/lichen/schc/schc_compress.c
  ../../subsys/lichen/schc/schc_decompress.c
  ../../subsys/lichen/schc/schc_helpers.c
)
target_include_directories(schc_mqtt_sn_test PRIVATE
  ../../subsys/schc/include
  ../../subsys/lichen/schc/include
)
lichen_test_target(schc_mqtt_sn_test)
# The shared generic bitstream predates the repository's conversion-warning
# gate; keep the focused Rule 7 test strict without taking ownership of it.
target_compile_options(schc_mqtt_sn_test PRIVATE -Wno-error=implicit-int-conversion)

enable_testing()
add_test(NAME schc_mqtt_sn_test COMMAND schc_mqtt_sn_test)
