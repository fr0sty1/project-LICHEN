/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "puck_location.h"

#include <errno.h>
#include <stdint.h>

static enum lichen_hal_location_fix_state puck_fix_state_from_gnss(
	enum gnss_fix_status fix_status)
{
	if (fix_status == GNSS_FIX_STATUS_NO_FIX) {
		return LICHEN_HAL_LOCATION_FIX_NO_FIX;
	}

	return LICHEN_HAL_LOCATION_FIX_3D;
}

int lichen_puck_location_submit_gnss(const struct gnss_data *data)
{
	struct lichen_hal_location_sample sample = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE,
		.fix_state = LICHEN_HAL_LOCATION_FIX_NO_FIX,
		.fix_source = LICHEN_HAL_FIX_SOURCE_GNSS,
		.source_name = "gnss0",
	};

	if (data == NULL) {
		return -EINVAL;
	}

	sample.fix_state = puck_fix_state_from_gnss(data->info.fix_status);
	sample.satellites_valid = true;
	sample.satellites = data->info.satellites_cnt > UINT8_MAX ?
			    UINT8_MAX : (uint8_t)data->info.satellites_cnt;

	if (sample.fix_state != LICHEN_HAL_LOCATION_FIX_NO_FIX) {
		sample.latitude_e7_valid = true;
		sample.latitude_e7 = (int32_t)(data->nav_data.latitude / 100);
		sample.longitude_e7_valid = true;
		sample.longitude_e7 = (int32_t)(data->nav_data.longitude / 100);
		sample.altitude_m_valid = true;
		sample.altitude_m = data->nav_data.altitude / 1000;
		sample.altitude_cm_valid = true;
		sample.altitude_cm = data->nav_data.altitude / 10;
	}

	return lichen_hal_location_submit(&sample);
}

void lichen_puck_location_gnss_callback_for_test(const struct device *dev,
						 const struct gnss_data *data)
{
	ARG_UNUSED(dev);

	(void)lichen_puck_location_submit_gnss(data);
}

bool lichen_puck_location_snapshot_to_native_gps(
	const struct lichen_hal_location_time_snapshot *snapshot,
	struct ln_gps_info *gps)
{
	if (snapshot == NULL || gps == NULL) {
		return false;
	}
	if (!snapshot->latitude_e7_valid || !snapshot->longitude_e7_valid) {
		*gps = (struct ln_gps_info){ 0 };
		return false;
	}

	*gps = (struct ln_gps_info){
		.lat_udeg = snapshot->latitude_e7 / 10,
		.lon_udeg = snapshot->longitude_e7 / 10,
		.alt_cm = snapshot->altitude_cm_valid ?
			  snapshot->altitude_cm :
			  (snapshot->altitude_m_valid ?
			   snapshot->altitude_m * 100 : 0),
		.satellites = snapshot->satellites_valid ?
			      snapshot->satellites : 0,
		.valid = true,
	};

	return true;
}
