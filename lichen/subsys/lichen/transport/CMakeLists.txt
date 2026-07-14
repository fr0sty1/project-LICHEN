# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LCI transport bindings (spec/11-lci.md section 17.3)
#   - 17.3.1: SLIP over Serial/USB
#   - 17.3.2: BLE IPSP / SLIP over NUS

zephyr_library_named(lichen_transport)

zephyr_library_sources_ifdef(CONFIG_LICHEN_SLIP_TRANSPORT
  slip_transport.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_BLE_TRANSPORT
  ble_ipsp_transport.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_KISS_TRANSPORT
  kiss_transport.c
)

zephyr_include_directories(include)
