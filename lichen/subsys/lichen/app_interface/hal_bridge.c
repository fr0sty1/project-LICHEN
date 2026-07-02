/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/app_interface/hal_bridge.h>

#define APP_LOCATION_DEFAULT_SOURCE_NAME "local-client"

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

static enum lichen_hal_location_fix_state
hal_location_fix_state_from_app(enum lichen_app_location_fix_state fix_state)
{
	switch (fix_state) {
	case LICHEN_APP_LOCATION_FIX_NO_FIX:
		return LICHEN_HAL_LOCATION_FIX_NO_FIX;
	case LICHEN_APP_LOCATION_FIX_2D:
		return LICHEN_HAL_LOCATION_FIX_2D;
	case LICHEN_APP_LOCATION_FIX_3D:
		return LICHEN_HAL_LOCATION_FIX_3D;
	case LICHEN_APP_LOCATION_FIX_ERROR:
		return LICHEN_HAL_LOCATION_FIX_ERROR;
	case LICHEN_APP_LOCATION_FIX_NONE:
	default:
		return LICHEN_HAL_LOCATION_FIX_NONE;
	}
}

static bool valid_app_location_fix_state(
	enum lichen_app_location_fix_state fix_state)
{
	return fix_state >= LICHEN_APP_LOCATION_FIX_NONE &&
	       fix_state <= LICHEN_APP_LOCATION_FIX_ERROR &&
	       fix_state != LICHEN_APP_LOCATION_FIX_STALE;
}

static bool valid_app_fix_source(enum lichen_app_fix_source fix_source)
{
	return fix_source >= LICHEN_APP_FIX_SOURCE_NONE &&
	       fix_source <= LICHEN_APP_FIX_SOURCE_GNSS;
}

static bool valid_app_location_source_class(
	enum lichen_app_location_source_class source_class)
{
	return source_class >= LICHEN_APP_LOCATION_SOURCE_NONE &&
	       source_class <= LICHEN_APP_LOCATION_SOURCE_MANUAL_STATIC;
}

static int64_t bridge_now_ms(void)
{
#ifdef CONFIG_ZTEST
	return lichen_hal_location_test_now_ms();
#else
	return k_uptime_get();
#endif
}

static int64_t observed_uptime_from_age_seconds(uint32_t age_seconds)
{
	const int64_t now_ms = bridge_now_ms();
	const int64_t max_age_seconds = INT64_MAX / 1000;
	const int64_t bounded_age_seconds =
		(int64_t)MIN((uint64_t)age_seconds, (uint64_t)max_age_seconds);
	const int64_t age_ms = bounded_age_seconds * 1000;

	return now_ms - age_ms;
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

int lichen_app_location_submit_to_hal(
	const struct lichen_app_location_time_snapshot *app)
{
	struct lichen_hal_location_sample sample;
	const char *source_name;

	if (app == NULL) {
		return -EINVAL;
	}
	if (app->fix_state_valid &&
	    !valid_app_location_fix_state(app->fix_state)) {
		return -EINVAL;
	}
	if (app->fix_source_valid && !valid_app_fix_source(app->fix_source)) {
		return -EINVAL;
	}
	if (app->source_class_valid &&
	    (!valid_app_location_source_class(app->source_class) ||
	     app->source_class != LICHEN_APP_LOCATION_SOURCE_LOCAL_CLIENT)) {
		return -EINVAL;
	}
	if (app->fix_state_valid &&
	    app->fix_state == LICHEN_APP_LOCATION_FIX_STALE) {
		return -EINVAL;
	}
	if (app->fix_source_valid &&
	    app->fix_source != LICHEN_APP_FIX_SOURCE_NONE) {
		return -EINVAL;
	}

	source_name = app->source_name[0] != '\0' ?
		      app->source_name : APP_LOCATION_DEFAULT_SOURCE_NAME;
	sample = (struct lichen_hal_location_sample){
		.source_class = LICHEN_HAL_LOCATION_SOURCE_LOCAL_CLIENT,
		.fix_state = app->fix_state_valid ?
			     hal_location_fix_state_from_app(app->fix_state) :
			     LICHEN_HAL_LOCATION_FIX_NONE,
		.fix_source = LICHEN_HAL_FIX_SOURCE_NONE,
		.source_name = source_name,
		.horizontal_accuracy_mm_valid =
			app->horizontal_accuracy_mm_valid,
		.horizontal_accuracy_mm = app->horizontal_accuracy_mm,
		.vertical_accuracy_mm_valid = app->vertical_accuracy_mm_valid,
		.vertical_accuracy_mm = app->vertical_accuracy_mm,
		.latitude_e7_valid = app->latitude_e7_valid,
		.latitude_e7 = app->latitude_e7,
		.longitude_e7_valid = app->longitude_e7_valid,
		.longitude_e7 = app->longitude_e7,
		.altitude_m_valid = app->altitude_m_valid,
		.altitude_m = app->altitude_m,
		.fix_time_unix_valid = app->fix_time_unix_valid,
		.fix_time_unix = app->fix_time_unix,
		.satellites_valid = app->satellites_valid,
		.satellites = app->satellites,
	};

	if (app->age_seconds_valid) {
		sample.observed_uptime_ms_valid = true;
		sample.observed_uptime_ms =
			observed_uptime_from_age_seconds(app->age_seconds);
	}

	return lichen_hal_location_submit(&sample);
}
