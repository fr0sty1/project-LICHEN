/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "network_location.h"

#include <errno.h>
#include <string.h>

#include <lichen/app_interface/app_interface.h>

static bool valid_lat_lon(int32_t latitude_e7, int32_t longitude_e7)
{
	return latitude_e7 >= -900000000 && latitude_e7 <= 900000000 &&
	       longitude_e7 >= -1800000000 && longitude_e7 <= 1800000000;
}

int gateway_network_location_submit(
	const struct gateway_network_location_sample *sample)
{
	struct lichen_app_location_time_snapshot location;

	if (sample == NULL ||
	    sample->latitude_e7_valid != sample->longitude_e7_valid ||
	    !sample->latitude_e7_valid ||
	    !valid_lat_lon(sample->latitude_e7, sample->longitude_e7)) {
		return -EINVAL;
	}

	location = (struct lichen_app_location_time_snapshot){
		.source_class_valid = true,
		.source_class = LICHEN_APP_LOCATION_SOURCE_NETWORK,
		.fix_state_valid = true,
		.fix_state = sample->altitude_m_valid ?
			     LICHEN_APP_LOCATION_FIX_3D :
			     LICHEN_APP_LOCATION_FIX_2D,
		.latitude_e7_valid = true,
		.latitude_e7 = sample->latitude_e7,
		.longitude_e7_valid = true,
		.longitude_e7 = sample->longitude_e7,
		.altitude_m_valid = sample->altitude_m_valid,
		.altitude_m = sample->altitude_m,
		.fix_time_unix_valid = sample->fix_time_unix_valid,
		.fix_time_unix = sample->fix_time_unix,
		.satellites_valid = sample->satellites_valid,
		.satellites = sample->satellites,
		.age_seconds_valid = sample->age_seconds_valid,
		.age_seconds = sample->age_seconds,
		.horizontal_accuracy_mm_valid =
			sample->horizontal_accuracy_mm_valid,
		.horizontal_accuracy_mm = sample->horizontal_accuracy_mm,
		.vertical_accuracy_mm_valid = sample->vertical_accuracy_mm_valid,
		.vertical_accuracy_mm = sample->vertical_accuracy_mm,
	};
	if (sample->source_name_valid) {
		strncpy(location.source_name, sample->source_name,
			sizeof(location.source_name) - 1U);
		location.source_name[sizeof(location.source_name) - 1U] = '\0';
	}

	return lichen_app_interface_submit_network_location(&location);
}
