/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_PUCK_LOCATION_H_
#define LICHEN_PUCK_LOCATION_H_

#include <stdbool.h>

#include <zephyr/drivers/gnss.h>

#include <lichen/hal.h>
#include <lichen/native.h>

int lichen_puck_location_submit_gnss(const struct gnss_data *data);
void lichen_puck_location_gnss_callback_for_test(const struct device *dev,
						 const struct gnss_data *data);
bool lichen_puck_location_snapshot_to_native_gps(
	const struct lichen_hal_location_time_snapshot *snapshot,
	struct ln_gps_info *gps);

#endif /* LICHEN_PUCK_LOCATION_H_ */
