# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# BLE IPSP Transport for LCI (spec/11-lci.md section 17.3.2)

zephyr_library_named(lichen_transport)

zephyr_library_sources_ifdef(CONFIG_LICHEN_BLE_TRANSPORT
  ble_ipsp_transport.c
)

zephyr_include_directories(include)
