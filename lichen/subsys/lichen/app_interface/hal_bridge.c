/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/app_interface/hal_bridge.h>

#define APP_LOCATION_DEFAULT_SOURCE_NAME "local-client"
#define APP_LOCATION_NETWORK_SOURCE_NAME "network"
#define APP_LOCATION_MANUAL_SOURCE_NAME "manual"

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

static enum lichen_app_time_source_class
app_time_source_class_from_hal(enum lichen_hal_time_source_class source_class)
{
	switch (source_class) {
	case LICHEN_HAL_TIME_SOURCE_MONOTONIC_INTERNAL:
		return LICHEN_APP_TIME_SOURCE_MONOTONIC_INTERNAL;
	case LICHEN_HAL_TIME_SOURCE_INTERNAL_RTC:
		return LICHEN_APP_TIME_SOURCE_INTERNAL_RTC;
	case LICHEN_HAL_TIME_SOURCE_GNSS:
		return LICHEN_APP_TIME_SOURCE_GNSS;
	case LICHEN_HAL_TIME_SOURCE_NETWORK:
		return LICHEN_APP_TIME_SOURCE_NETWORK;
	case LICHEN_HAL_TIME_SOURCE_LOCAL_CLIENT:
		return LICHEN_APP_TIME_SOURCE_LOCAL_CLIENT;
	case LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC:
		return LICHEN_APP_TIME_SOURCE_MANUAL_STATIC;
	case LICHEN_HAL_TIME_SOURCE_NONE:
	default:
		return LICHEN_APP_TIME_SOURCE_NONE;
	}
}

static enum lichen_app_time_rejection_reason
app_time_rejection_from_hal(enum lichen_hal_time_rejection_reason reason)
{
	switch (reason) {
	case LICHEN_HAL_TIME_REJECT_INVALID_SOURCE:
		return LICHEN_APP_TIME_REJECT_INVALID_SOURCE;
	case LICHEN_HAL_TIME_REJECT_MISSING_TIMESTAMP:
		return LICHEN_APP_TIME_REJECT_MISSING_TIMESTAMP;
	case LICHEN_HAL_TIME_REJECT_BELOW_EPOCH_FLOOR:
		return LICHEN_APP_TIME_REJECT_BELOW_EPOCH_FLOOR;
	case LICHEN_HAL_TIME_REJECT_STALE:
		return LICHEN_APP_TIME_REJECT_STALE;
	case LICHEN_HAL_TIME_REJECT_LOWER_TRUST:
		return LICHEN_APP_TIME_REJECT_LOWER_TRUST;
	case LICHEN_HAL_TIME_REJECT_PROVISION_UNAUTHENTICATED:
		return LICHEN_APP_TIME_REJECT_PROVISION_UNAUTHENTICATED;
	case LICHEN_HAL_TIME_REJECT_PROVISION_INVALID:
		return LICHEN_APP_TIME_REJECT_PROVISION_INVALID;
	case LICHEN_HAL_TIME_REJECT_PROVISION_FUTURE:
		return LICHEN_APP_TIME_REJECT_PROVISION_FUTURE;
	case LICHEN_HAL_TIME_REJECT_NONE:
	default:
		return LICHEN_APP_TIME_REJECT_NONE;
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
	case LICHEN_APP_LOCATION_FIX_STALE:
		__ASSERT(false, "STALE not valid from app side");
		return LICHEN_HAL_LOCATION_FIX_NONE;
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

static bool valid_app_time_source_class(
	enum lichen_app_time_source_class source_class)
{
	return source_class >= LICHEN_APP_TIME_SOURCE_NONE &&
	       source_class <= LICHEN_APP_TIME_SOURCE_MANUAL_STATIC;
}

static const char *default_source_name(
	enum lichen_hal_location_source_class source_class)
{
	enum lichen_app_location_source_class app_class =
		app_location_source_class_from_hal(source_class);
	switch (app_class) {
	case LICHEN_APP_LOCATION_SOURCE_NETWORK:
		return APP_LOCATION_NETWORK_SOURCE_NAME;
	case LICHEN_APP_LOCATION_SOURCE_MANUAL_STATIC:
		return APP_LOCATION_MANUAL_SOURCE_NAME;
	default:
		return APP_LOCATION_DEFAULT_SOURCE_NAME;
	}
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

	/*
	 * May be negative when the sample is older than this node's uptime
	 * (e.g. a mesh announce received right after boot). The HAL accepts
	 * negative observed times and its age math handles them; clamping to
	 * zero here would silently shrink the reported age to the uptime.
	 */
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
	const char *name_end = memchr(hal->source_name, '\0',
				      sizeof(app->source_name));
	if (name_end == NULL) {
		return -EINVAL;
	}
	size_t name_len = (size_t)(name_end - hal->source_name);
	memcpy(app->source_name, hal->source_name, name_len);
	app->source_name[name_len] = '\0';
	return 0;
}

int lichen_app_time_from_hal(struct lichen_app_time_snapshot *app,
			     const struct lichen_hal_time_snapshot *hal)
{
	if (app == NULL || hal == NULL) {
		return -EINVAL;
	}

	*app = (struct lichen_app_time_snapshot){
		.provider_available = hal->provider_available,
		.wall_clock_valid = hal->wall_clock_valid,
		.source_class_valid = hal->source_class_valid,
		.source_class = app_time_source_class_from_hal(hal->source_class),
		.unix_time_valid = hal->unix_time_valid,
		.unix_time = hal->unix_time,
		.age_seconds_valid = hal->age_seconds_valid,
		.age_seconds = hal->age_seconds,
		.accuracy_ms_valid = hal->accuracy_ms_valid,
		.accuracy_ms = hal->accuracy_ms,
		.quality_valid = hal->quality_valid,
		.quality = hal->quality,
		.passed_epoch_floor = hal->passed_epoch_floor,
		.last_rejection = app_time_rejection_from_hal(hal->last_rejection),
		.rejection_source_class_valid =
			hal->rejection_source_class_valid,
		.rejection_source_class =
			app_time_source_class_from_hal(hal->rejection_source_class),
		.rejection_passed_epoch_floor =
			hal->rejection_passed_epoch_floor,
		.effective_epoch_floor = hal->effective_epoch_floor,
		.build_epoch = hal->build_epoch,
		.provision_epoch_valid = hal->provision_epoch_valid,
		.provision_epoch = hal->provision_epoch,
	};
	const char *name_end = memchr(hal->source_name, '\0',
				      sizeof(app->source_name));
	if (name_end == NULL) {
		return -EINVAL;
	}
	size_t name_len = (size_t)(name_end - hal->source_name);
	memcpy(app->source_name, hal->source_name, name_len);
	app->source_name[name_len] = '\0';
	name_end = memchr(hal->rejection_source_name, '\0',
			  sizeof(app->rejection_source_name));
	if (name_end == NULL) {
		return -EINVAL;
	}
	name_len = (size_t)(name_end - hal->rejection_source_name);
	memcpy(app->rejection_source_name, hal->rejection_source_name, name_len);
	app->rejection_source_name[name_len] = '\0';
	return 0;
}

static int submit_to_hal_as(
	const struct lichen_app_location_time_snapshot *app,
	enum lichen_hal_location_source_class source_class)
{
	struct lichen_hal_location_sample sample;
	const char *source_name;
	enum lichen_app_location_source_class expected_source_class;

	if (app == NULL) {
		return -EINVAL;
	}
	expected_source_class = app_location_source_class_from_hal(source_class);
	if (app->fix_state_valid &&
	    !valid_app_location_fix_state(app->fix_state)) {
		return -EINVAL;
	}
	if (app->fix_source_valid && !valid_app_fix_source(app->fix_source)) {
		return -EINVAL;
	}
	if (app->source_class_valid &&
	    (!valid_app_location_source_class(app->source_class) ||
	     app->source_class != expected_source_class)) {
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
	/* Validate geographic coordinate bounds when present */
	if (app->latitude_e7_valid &&
	    (app->latitude_e7 < -900000000 || app->latitude_e7 > 900000000)) {
		return -EINVAL;
	}
	if (app->longitude_e7_valid &&
	    (app->longitude_e7 < -1800000000 || app->longitude_e7 > 1800000000)) {
		return -EINVAL;
	}

	source_name = app->source_name[0] != '\0' ?
		      app->source_name : default_source_name(source_class);
	sample = (struct lichen_hal_location_sample){
		.source_class = source_class,
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

int lichen_app_location_submit_to_hal(
	const struct lichen_app_location_time_snapshot *app)
{
	return submit_to_hal_as(app, LICHEN_HAL_LOCATION_SOURCE_LOCAL_CLIENT);
}

int lichen_app_network_location_submit_to_hal(
	const struct lichen_app_location_time_snapshot *app)
{
	return submit_to_hal_as(app, LICHEN_HAL_LOCATION_SOURCE_NETWORK);
}

int lichen_app_network_location_clear_from_hal(void)
{
	return lichen_hal_location_clear_source(LICHEN_HAL_LOCATION_SOURCE_NETWORK);
}

int lichen_app_manual_location_submit_to_hal(
	const struct lichen_app_location_time_snapshot *app)
{
	return submit_to_hal_as(app, LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC);
}

static const char *default_time_source_name(
	enum lichen_hal_time_source_class source_class)
{
	switch (source_class) {
	case LICHEN_HAL_TIME_SOURCE_NETWORK:
		return APP_LOCATION_NETWORK_SOURCE_NAME;
	case LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC:
		return APP_LOCATION_MANUAL_SOURCE_NAME;
	case LICHEN_HAL_TIME_SOURCE_LOCAL_CLIENT:
	default:
		return APP_LOCATION_DEFAULT_SOURCE_NAME;
	}
}

static int submit_time_to_hal_as(
	const struct lichen_app_time_snapshot *app,
	enum lichen_hal_time_source_class source_class)
{
	struct lichen_hal_time_sample sample;
	const char *source_name;
	enum lichen_app_time_source_class expected_source_class;

	if (app == NULL) {
		return -EINVAL;
	}
	expected_source_class = app_time_source_class_from_hal(source_class);
	if (app->source_class_valid &&
	    (!valid_app_time_source_class(app->source_class) ||
	     app->source_class != expected_source_class)) {
		return -EINVAL;
	}

	source_name = app->source_name[0] != '\0' ?
		      app->source_name : default_time_source_name(source_class);
	sample = (struct lichen_hal_time_sample){
		.source_class = source_class,
		.source_name = source_name,
		.unix_time_valid = app->unix_time_valid,
		.unix_time = app->unix_time,
		.accuracy_ms_valid = app->accuracy_ms_valid,
		.accuracy_ms = app->accuracy_ms,
		.quality_valid = app->quality_valid,
		.quality = app->quality,
	};
	if (app->age_seconds_valid) {
		sample.observed_uptime_ms_valid = true;
		sample.observed_uptime_ms =
			observed_uptime_from_age_seconds(app->age_seconds);
	}

	return lichen_hal_time_submit(&sample);
}

int lichen_app_time_submit_to_hal(const struct lichen_app_time_snapshot *app)
{
	return submit_time_to_hal_as(app, LICHEN_HAL_TIME_SOURCE_LOCAL_CLIENT);
}

int lichen_app_network_time_submit_to_hal(const struct lichen_app_time_snapshot *app)
{
	return submit_time_to_hal_as(app, LICHEN_HAL_TIME_SOURCE_NETWORK);
}

int lichen_app_manual_time_submit_to_hal(const struct lichen_app_time_snapshot *app)
{
	return submit_time_to_hal_as(app, LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC);
}
