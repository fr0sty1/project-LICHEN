# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

zephyr_library()

zephyr_library_sources(
	hal_caps.c
	hal_airtime.c
	hal_device.c
	hal_duty.c
	hal_location.c
	hal_power.c
	hal_reset.c
	hal_time.c
)

zephyr_include_directories(include)
