/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "config_apply.h"

#include <errno.h>
#include <string.h>

#include <lichen/app_interface/app_interface.h>

int lichen_gateway_apply_config_update(
	const struct lichen_gateway_config_update *update,
	int8_t *tx_power_dbm,
	struct lichen_gateway_manual_location_config *manual_location,
	bool *has_manual_location)
{
	if (update == NULL || tx_power_dbm == NULL ||
	    manual_location == NULL || has_manual_location == NULL) {
		return -EINVAL;
	}

	if (update->has_manual_location) {
		const struct lichen_gateway_manual_location_config *manual =
			&update->manual_location;
		struct lichen_app_location_time_snapshot location = {
			.source_class_valid = true,
			.source_class = LICHEN_APP_LOCATION_SOURCE_MANUAL_STATIC,
			.fix_state_valid = true,
			.fix_state = LICHEN_APP_LOCATION_FIX_2D,
			.age_seconds_valid = manual->age_seconds_valid,
			.age_seconds = manual->age_seconds,
			.horizontal_accuracy_mm_valid =
				manual->horizontal_accuracy_mm_valid,
			.horizontal_accuracy_mm = manual->horizontal_accuracy_mm,
			.latitude_e7_valid = manual->latitude_e7_valid,
			.latitude_e7 = manual->latitude_e7,
			.longitude_e7_valid = manual->longitude_e7_valid,
			.longitude_e7 = manual->longitude_e7,
		};

		if (manual->source_name[0] != '\0') {
			strncpy(location.source_name, manual->source_name,
				sizeof(location.source_name) - 1U);
			location.source_name[sizeof(location.source_name) - 1U] =
				'\0';
		}
		if (lichen_app_interface_submit_manual_location(&location) < 0) {
			return -EINVAL;
		}
	}

	if (update->has_tx_power_dbm) {
		*tx_power_dbm = update->tx_power_dbm;
	}
	if (update->has_manual_location) {
		*manual_location = update->manual_location;
		*has_manual_location = true;
	}

	return 0;
}
