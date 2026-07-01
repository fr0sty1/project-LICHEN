/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <stdint.h>

#include <zephyr/ztest.h>

#include "puck_location.h"

static struct gnss_data gnss_fix(enum gnss_fix_status status)
{
	return (struct gnss_data){
		.nav_data = {
			.latitude = 47620613000LL,
			.longitude = -122349300000LL,
			.altitude = 42499,
		},
		.info = {
			.fix_status = status,
			.satellites_cnt = 9,
		},
	};
}

ZTEST(puck_location, test_rejects_null_gnss_data)
{
	zassert_equal(lichen_puck_location_submit_gnss(NULL), -EINVAL);
}

ZTEST(puck_location, test_no_fix_submits_provider_metadata_without_position)
{
	struct gnss_data data = gnss_fix(GNSS_FIX_STATUS_NO_FIX);
	struct lichen_hal_location_time_snapshot snapshot;
	struct ln_gps_info gps = {
		.valid = true,
		.lat_udeg = 1,
	};

	lichen_hal_location_clear();
	lichen_hal_location_test_set_uptime_ms(1000);
	zassert_ok(lichen_puck_location_submit_gnss(&data));
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));

	zassert_true(snapshot.location_provider_available);
	zassert_true(snapshot.source_class_valid);
	zassert_equal(snapshot.source_class,
		      LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE);
	zassert_str_equal(snapshot.source_name, "gnss0");
	zassert_true(snapshot.fix_state_valid);
	zassert_equal(snapshot.fix_state, LICHEN_HAL_LOCATION_FIX_NO_FIX);
	zassert_false(snapshot.fix_source_valid);
	zassert_true(snapshot.satellites_valid);
	zassert_equal(snapshot.satellites, 9U);
	zassert_false(snapshot.latitude_e7_valid);
	zassert_false(snapshot.longitude_e7_valid);
	zassert_false(lichen_puck_location_snapshot_to_native_gps(&snapshot,
								 &gps));
	zassert_false(gps.valid);
}

ZTEST(puck_location, test_fresh_gnss_fix_updates_provider_and_native_gps)
{
	struct gnss_data data = gnss_fix(GNSS_FIX_STATUS_GNSS_FIX);
	struct lichen_hal_location_time_snapshot snapshot;
	struct ln_gps_info gps;

	lichen_hal_location_clear();
	lichen_hal_location_test_set_uptime_ms(2000);
	lichen_puck_location_gnss_callback_for_test(NULL, &data);
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));

	zassert_true(snapshot.location_provider_available);
	zassert_equal(snapshot.source_class,
		      LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE);
	zassert_str_equal(snapshot.source_name, "gnss0");
	zassert_equal(snapshot.fix_state, LICHEN_HAL_LOCATION_FIX_3D);
	zassert_true(snapshot.latitude_e7_valid);
	zassert_equal(snapshot.latitude_e7, 476206130);
	zassert_true(snapshot.longitude_e7_valid);
	zassert_equal(snapshot.longitude_e7, -1223493000);
	zassert_true(snapshot.altitude_m_valid);
	zassert_equal(snapshot.altitude_m, 42);
	zassert_true(snapshot.altitude_cm_valid);
	zassert_equal(snapshot.altitude_cm, 4249);
	zassert_true(snapshot.satellites_valid);
	zassert_equal(snapshot.satellites, 9U);
	zassert_true(snapshot.fix_source_valid);
	zassert_equal(snapshot.fix_source, LICHEN_HAL_FIX_SOURCE_GNSS);

	zassert_true(lichen_puck_location_snapshot_to_native_gps(&snapshot,
								&gps));
	zassert_true(gps.valid);
	zassert_equal(gps.lat_udeg, 47620613);
	zassert_equal(gps.lon_udeg, -122349300);
	zassert_equal(gps.alt_cm, 4249);
	zassert_equal(gps.satellites, 9U);
}

ZTEST(puck_location, test_stale_gnss_snapshot_omits_native_gps)
{
	struct gnss_data data = gnss_fix(GNSS_FIX_STATUS_DGNSS_FIX);
	struct lichen_hal_location_time_snapshot snapshot;
	struct ln_gps_info gps;

	lichen_hal_location_clear();
	lichen_hal_location_test_set_uptime_ms(0);
	zassert_ok(lichen_puck_location_submit_gnss(&data));
	lichen_hal_location_test_set_uptime_ms(
		((int64_t)CONFIG_LICHEN_LOCATION_FRESHNESS_MAX_AGE_S + 1) *
		1000);
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));

	zassert_true(snapshot.location_provider_available);
	zassert_equal(snapshot.fix_state, LICHEN_HAL_LOCATION_FIX_STALE);
	zassert_true(snapshot.age_seconds_valid);
	zassert_false(snapshot.latitude_e7_valid);
	zassert_false(snapshot.longitude_e7_valid);
	zassert_false(snapshot.altitude_m_valid);
	zassert_false(snapshot.altitude_cm_valid);
	zassert_false(snapshot.satellites_valid);
	zassert_false(lichen_puck_location_snapshot_to_native_gps(&snapshot,
								 &gps));
}

static void after_each(void *fixture)
{
	ARG_UNUSED(fixture);

	lichen_hal_location_clear();
	lichen_hal_location_test_use_real_uptime();
}

ZTEST_SUITE(puck_location, NULL, NULL, after_each, NULL, NULL);
