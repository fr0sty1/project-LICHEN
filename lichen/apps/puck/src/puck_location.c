/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "puck_location.h"

#include <errno.h>
#include <stdint.h>
#include <time.h>

#include <zephyr/sys/timeutil.h>

static enum lichen_hal_location_fix_state puck_fix_state_from_gnss(
	enum gnss_fix_status fix_status)
{
	if (fix_status == GNSS_FIX_STATUS_NO_FIX) {
		return LICHEN_HAL_LOCATION_FIX_NO_FIX;
	}

	return LICHEN_HAL_LOCATION_FIX_3D;
}

static bool puck_year_is_leap(uint16_t year)
{
	return (year % 4U) == 0U &&
	       ((year % 100U) != 0U || (year % 400U) == 0U);
}

static uint8_t puck_days_in_month(uint16_t year, uint8_t month)
{
	switch (month) {
	case 1U:
	case 3U:
	case 5U:
	case 7U:
	case 8U:
	case 10U:
	case 12U:
		return 31U;
	case 4U:
	case 6U:
	case 9U:
	case 11U:
		return 30U;
	case 2U:
		return puck_year_is_leap(year) ? 29U : 28U;
	default:
		return 0U;
	}
}

static bool puck_gnss_utc_to_unix(const struct gnss_time *utc,
				  uint64_t *unix_time)
{
	struct tm tm = { 0 };
	int64_t epoch;
	uint16_t year;
	uint8_t days;

	if (utc == NULL || unix_time == NULL ||
	    utc->month < 1U || utc->month > 12U ||
	    utc->hour > 23U || utc->minute > 59U ||
	    utc->millisecond > 59999U) {
		return false;
	}

	year = 2000U + utc->century_year;
	days = puck_days_in_month(year, utc->month);
	if (utc->month_day < 1U || utc->month_day > days) {
		return false;
	}

	tm.tm_year = (int)year - 1900;
	tm.tm_mon = (int)utc->month - 1;
	tm.tm_mday = utc->month_day;
	tm.tm_hour = utc->hour;
	tm.tm_min = utc->minute;
	tm.tm_sec = utc->millisecond / 1000U;

	epoch = timeutil_timegm64(&tm);
	if (epoch <= 0) {
		return false;
	}

	*unix_time = (uint64_t)epoch;
	return true;
}

static void puck_submit_gnss_time(const struct gnss_data *data)
{
	uint64_t unix_time;
	struct lichen_hal_time_sample sample = {
		.source_class = LICHEN_HAL_TIME_SOURCE_GNSS,
		.source_name = "gnss0",
		.unix_time_valid = true,
	};

	if (data->info.fix_status == GNSS_FIX_STATUS_NO_FIX) {
		return;
	}

	if (!puck_gnss_utc_to_unix(&data->utc, &unix_time)) {
		return;
	}

	sample.unix_time = unix_time;
	if (data->info.fix_quality != GNSS_FIX_QUALITY_INVALID) {
		sample.quality_valid = true;
		sample.quality = data->info.fix_quality;
	}

	(void)lichen_hal_time_submit(&sample);
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

	puck_submit_gnss_time(data);

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
