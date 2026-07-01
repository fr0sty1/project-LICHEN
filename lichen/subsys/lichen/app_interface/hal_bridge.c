/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <lichen/app_interface/hal_bridge.h>

static enum lichen_app_fix_source
app_fix_source_from_hal(enum lichen_hal_fix_source source)
{
	switch (source) {
	case LICHEN_HAL_FIX_SOURCE_GNSS:
		return LICHEN_APP_FIX_SOURCE_GNSS;
	case LICHEN_HAL_FIX_SOURCE_NONE:
	default:
		return LICHEN_APP_FIX_SOURCE_NONE;
	}
}

static enum lichen_app_location_source_class
app_location_source_class_from_hal(
	enum lichen_hal_location_source_class source_class)
{
	switch (source_class) {
	case LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE:
		return LICHEN_APP_LOCATION_SOURCE_ONBOARD_HARDWARE;
	case LICHEN_HAL_LOCATION_SOURCE_EXTERNAL_HARDWARE:
		return LICHEN_APP_LOCATION_SOURCE_EXTERNAL_HARDWARE;
	case LICHEN_HAL_LOCATION_SOURCE_NETWORK:
		return LICHEN_APP_LOCATION_SOURCE_NETWORK;
	case LICHEN_HAL_LOCATION_SOURCE_LOCAL_CLIENT:
		return LICHEN_APP_LOCATION_SOURCE_LOCAL_CLIENT;
	case LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC:
		return LICHEN_APP_LOCATION_SOURCE_MANUAL_STATIC;
	case LICHEN_HAL_LOCATION_SOURCE_NONE:
	default:
		return LICHEN_APP_LOCATION_SOURCE_NONE;
	}
}

static enum lichen_app_location_fix_state
app_location_fix_state_from_hal(enum lichen_hal_location_fix_state fix_state)
{
	switch (fix_state) {
	case LICHEN_HAL_LOCATION_FIX_NO_FIX:
		return LICHEN_APP_LOCATION_FIX_NO_FIX;
	case LICHEN_HAL_LOCATION_FIX_2D:
		return LICHEN_APP_LOCATION_FIX_2D;
	case LICHEN_HAL_LOCATION_FIX_3D:
		return LICHEN_APP_LOCATION_FIX_3D;
	case LICHEN_HAL_LOCATION_FIX_STALE:
		return LICHEN_APP_LOCATION_FIX_STALE;
	case LICHEN_HAL_LOCATION_FIX_ERROR:
		return LICHEN_APP_LOCATION_FIX_ERROR;
	case LICHEN_HAL_LOCATION_FIX_NONE:
	default:
		return LICHEN_APP_LOCATION_FIX_NONE;
	}
}

int lichen_app_location_time_from_hal(
	struct lichen_app_location_time_snapshot *app,
	const struct lichen_hal_location_time_snapshot *hal)
{
	if (app == NULL || hal == NULL) {
		return -EINVAL;
	}

	*app = (struct lichen_app_location_time_snapshot){
		.location_provider_available = hal->location_provider_available,
		.time_provider_available = hal->time_provider_available,
		.latitude_e7_valid = hal->latitude_e7_valid,
		.latitude_e7 = hal->latitude_e7,
		.longitude_e7_valid = hal->longitude_e7_valid,
		.longitude_e7 = hal->longitude_e7,
		.altitude_m_valid = hal->altitude_m_valid,
		.altitude_m = hal->altitude_m,
		.fix_time_unix_valid = hal->fix_time_unix_valid,
		.fix_time_unix = hal->fix_time_unix,
		.satellites_valid = hal->satellites_valid,
		.satellites = hal->satellites,
		.fix_source_valid = hal->fix_source_valid,
		.fix_source = app_fix_source_from_hal(hal->fix_source),
		.source_class_valid = hal->source_class_valid,
		.source_class =
			app_location_source_class_from_hal(hal->source_class),
		.fix_state_valid = hal->fix_state_valid,
		.fix_state = app_location_fix_state_from_hal(hal->fix_state),
		.age_seconds_valid = hal->age_seconds_valid,
		.age_seconds = hal->age_seconds,
		.horizontal_accuracy_mm_valid =
			hal->horizontal_accuracy_mm_valid,
		.horizontal_accuracy_mm = hal->horizontal_accuracy_mm,
		.vertical_accuracy_mm_valid = hal->vertical_accuracy_mm_valid,
		.vertical_accuracy_mm = hal->vertical_accuracy_mm,
	};
	strncpy(app->source_name, hal->source_name,
		sizeof(app->source_name) - 1U);
	app->source_name[sizeof(app->source_name) - 1U] = '\0';
	return 0;
}
