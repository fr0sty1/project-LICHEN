/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <zcbor_common.h>
#include <zcbor_decode.h>

#include "status_cbor.h"

struct status_view {
	bool location_provider;
	bool time_provider;
	bool has_location_provider;
	bool has_time_provider;
	bool has_loc_source_class;
	bool has_loc_source;
	bool has_loc_fix_state;
	bool has_loc_age_s;
	bool has_hacc_mm;
	bool has_vacc_mm;
	bool has_lat_i;
	bool has_lon_i;
	bool has_alt_m;
	bool has_time_unix;
	bool has_satellites;
	char loc_source_class[24];
	char loc_source[24];
	char loc_fix_state[12];
	uint32_t loc_age_s;
	uint32_t hacc_mm;
	uint32_t vacc_mm;
	int32_t lat_i;
	int32_t lon_i;
	int32_t alt_m;
	uint32_t time_unix;
	uint32_t satellites;
};

static bool key_matches(const struct zcbor_string *key, const char *expected)
{
	size_t expected_len = strlen(expected);

	return key->len == expected_len &&
	       memcmp(key->value, expected, expected_len) == 0;
}

static bool copy_tstr(zcbor_state_t *zsd, char *out, size_t out_len)
{
	struct zcbor_string value;

	if (!zcbor_tstr_decode(zsd, &value) || value.len >= out_len) {
		return false;
	}
	memcpy(out, value.value, value.len);
	out[value.len] = '\0';
	return true;
}

static int decode_status(const uint8_t *buf, size_t len, struct status_view *out)
{
	ZCBOR_STATE_D(zsd, 1, buf, len, 1, 0);

	memset(out, 0, sizeof(*out));
	if (!zcbor_map_start_decode(zsd)) {
		return -EINVAL;
	}
	while (!zcbor_array_at_end(zsd)) {
		struct zcbor_string key;
		zcbor_state_t key_state = *zsd;
		bool decoded = true;

		if (!zcbor_tstr_decode(zsd, &key)) {
			(void)zcbor_list_map_end_force_decode(zsd);
			return -EINVAL;
		}
		if (key_matches(&key, "location_provider")) {
			out->has_location_provider = zcbor_bool_decode(
				zsd, &out->location_provider);
			decoded = out->has_location_provider;
		} else if (key_matches(&key, "time_provider")) {
			out->has_time_provider = zcbor_bool_decode(
				zsd, &out->time_provider);
			decoded = out->has_time_provider;
		} else if (key_matches(&key, "loc_source_class")) {
			out->has_loc_source_class = copy_tstr(
				zsd, out->loc_source_class,
				sizeof(out->loc_source_class));
			decoded = out->has_loc_source_class;
		} else if (key_matches(&key, "loc_source")) {
			out->has_loc_source = copy_tstr(
				zsd, out->loc_source, sizeof(out->loc_source));
			decoded = out->has_loc_source;
		} else if (key_matches(&key, "loc_fix_state")) {
			out->has_loc_fix_state = copy_tstr(
				zsd, out->loc_fix_state,
				sizeof(out->loc_fix_state));
			decoded = out->has_loc_fix_state;
		} else if (key_matches(&key, "loc_age_s")) {
			out->has_loc_age_s = zcbor_uint32_decode(
				zsd, &out->loc_age_s);
			decoded = out->has_loc_age_s;
		} else if (key_matches(&key, "hacc_mm")) {
			out->has_hacc_mm = zcbor_uint32_decode(zsd, &out->hacc_mm);
			decoded = out->has_hacc_mm;
		} else if (key_matches(&key, "vacc_mm")) {
			out->has_vacc_mm = zcbor_uint32_decode(zsd, &out->vacc_mm);
			decoded = out->has_vacc_mm;
		} else if (key_matches(&key, "lat_i")) {
			out->has_lat_i = zcbor_int32_decode(zsd, &out->lat_i);
			decoded = out->has_lat_i;
		} else if (key_matches(&key, "lon_i")) {
			out->has_lon_i = zcbor_int32_decode(zsd, &out->lon_i);
			decoded = out->has_lon_i;
		} else if (key_matches(&key, "alt_m")) {
			out->has_alt_m = zcbor_int32_decode(zsd, &out->alt_m);
			decoded = out->has_alt_m;
		} else if (key_matches(&key, "time_unix")) {
			out->has_time_unix = zcbor_uint32_decode(zsd,
								 &out->time_unix);
			decoded = out->has_time_unix;
		} else if (key_matches(&key, "satellites")) {
			out->has_satellites = zcbor_uint32_decode(
				zsd, &out->satellites);
			decoded = out->has_satellites;
		} else {
			*zsd = key_state;
			if (!zcbor_any_skip(zsd, NULL) ||
			    !zcbor_any_skip(zsd, NULL)) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
		}
		if (!decoded) {
			return -EINVAL;
		}
	}
	if (!zcbor_map_end_decode(zsd) || !zcbor_payload_at_end(zsd)) {
		(void)zcbor_list_map_end_force_decode(zsd);
		return -EINVAL;
	}
	return 0;
}

static size_t encode_status(uint8_t *buf, size_t buf_len,
			    const struct lichen_hal_location_time_snapshot *location)
{
	const struct lichen_hal_power_snapshot power = { 0 };

	return lichen_gateway_encode_status_cbor(buf, buf_len, 256, "root",
						 true, 1234U, &power, location);
}

static size_t encode_status_with_power(
	uint8_t *buf, size_t buf_len,
	const struct lichen_hal_power_snapshot *power,
	const struct lichen_hal_location_time_snapshot *location)
{
	return lichen_gateway_encode_status_cbor(buf, buf_len, UINT16_MAX,
						 "border-router01", true,
						 UINT32_MAX, power, location);
}

ZTEST(gateway_status, test_absent_location_metadata_is_omitted)
{
	const struct lichen_hal_location_time_snapshot location = { 0 };
	uint8_t buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];
	struct status_view view;
	size_t len = encode_status(buf, sizeof(buf), &location);

	zassert_true(len > 0U);
	zassert_ok(decode_status(buf, len, &view));
	zassert_true(view.has_location_provider);
	zassert_false(view.location_provider);
	zassert_true(view.has_time_provider);
	zassert_false(view.time_provider);
	zassert_false(view.has_loc_source_class);
	zassert_false(view.has_loc_source);
	zassert_false(view.has_loc_fix_state);
	zassert_false(view.has_loc_age_s);
	zassert_false(view.has_lat_i);
	zassert_false(view.has_lon_i);
}

ZTEST(gateway_status, test_fresh_location_metadata_is_encoded)
{
	const struct lichen_hal_location_time_snapshot location = {
		.location_provider_available = true,
		.time_provider_available = true,
		.source_class_valid = true,
		.source_class = LICHEN_HAL_LOCATION_SOURCE_NETWORK,
		.source_name = "mesh",
		.fix_state_valid = true,
		.fix_state = LICHEN_HAL_LOCATION_FIX_3D,
		.age_seconds_valid = true,
		.age_seconds = 7U,
		.horizontal_accuracy_mm_valid = true,
		.horizontal_accuracy_mm = 2500U,
		.vertical_accuracy_mm_valid = true,
		.vertical_accuracy_mm = 7500U,
		.latitude_e7_valid = true,
		.latitude_e7 = 476206130,
		.longitude_e7_valid = true,
		.longitude_e7 = -1223493000,
		.altitude_m_valid = true,
		.altitude_m = 42,
		.fix_time_unix_valid = true,
		.fix_time_unix = 1710000000U,
		.satellites_valid = true,
		.satellites = 9U,
	};
	uint8_t buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];
	struct status_view view;
	size_t len = encode_status(buf, sizeof(buf), &location);

	zassert_true(len > 0U);
	zassert_ok(decode_status(buf, len, &view));
	zassert_true(view.location_provider);
	zassert_true(view.time_provider);
	zassert_true(view.has_loc_source_class);
	zassert_str_equal(view.loc_source_class, "network");
	zassert_true(view.has_loc_source);
	zassert_str_equal(view.loc_source, "mesh");
	zassert_true(view.has_loc_fix_state);
	zassert_str_equal(view.loc_fix_state, "3d");
	zassert_true(view.has_loc_age_s);
	zassert_equal(view.loc_age_s, 7U);
	zassert_true(view.has_hacc_mm);
	zassert_equal(view.hacc_mm, 2500U);
	zassert_true(view.has_vacc_mm);
	zassert_equal(view.vacc_mm, 7500U);
	zassert_true(view.has_lat_i);
	zassert_equal(view.lat_i, 476206130);
	zassert_true(view.has_lon_i);
	zassert_equal(view.lon_i, -1223493000);
	zassert_true(view.has_alt_m);
	zassert_equal(view.alt_m, 42);
	zassert_true(view.has_time_unix);
	zassert_equal(view.time_unix, 1710000000U);
	zassert_true(view.has_satellites);
	zassert_equal(view.satellites, 9U);
}

ZTEST(gateway_status, test_manual_static_location_metadata_is_encoded)
{
	const struct lichen_hal_location_time_snapshot location = {
		.location_provider_available = true,
		.source_class_valid = true,
		.source_class = LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC,
		.source_name = "config-static",
		.fix_state_valid = true,
		.fix_state = LICHEN_HAL_LOCATION_FIX_2D,
		.age_seconds_valid = true,
		.age_seconds = 0U,
		.latitude_e7_valid = true,
		.latitude_e7 = 476206130,
		.longitude_e7_valid = true,
		.longitude_e7 = -1223493000,
	};
	uint8_t buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];
	struct status_view view;
	size_t len = encode_status(buf, sizeof(buf), &location);

	zassert_true(len > 0U);
	zassert_ok(decode_status(buf, len, &view));
	zassert_true(view.location_provider);
	zassert_true(view.has_loc_source_class);
	zassert_str_equal(view.loc_source_class, "manual_static");
	zassert_true(view.has_loc_source);
	zassert_str_equal(view.loc_source, "config-static");
	zassert_true(view.has_loc_fix_state);
	zassert_str_equal(view.loc_fix_state, "2d");
	zassert_true(view.has_lat_i);
	zassert_equal(view.lat_i, 476206130);
	zassert_true(view.has_lon_i);
	zassert_equal(view.lon_i, -1223493000);
}

ZTEST(gateway_status, test_full_status_fits_advertised_buffer)
{
	const struct lichen_hal_power_snapshot power = {
		.battery_provider_available = true,
		.pmic_provider_available = true,
		.battery_percent_valid = true,
		.battery_percent = 100U,
		.battery_voltage_mv_valid = true,
		.battery_voltage_mv = UINT16_MAX,
		.charging_valid = true,
		.charging = true,
		.external_power_valid = true,
		.external_power = true,
	};
	const struct lichen_hal_location_time_snapshot location = {
		.location_provider_available = true,
		.time_provider_available = true,
		.source_class_valid = true,
		.source_class = LICHEN_HAL_LOCATION_SOURCE_EXTERNAL_HARDWARE,
		.source_name = "abcdefghijklmnopqrstuvw",
		.fix_state_valid = true,
		.fix_state = LICHEN_HAL_LOCATION_FIX_3D,
		.age_seconds_valid = true,
		.age_seconds = UINT32_MAX,
		.horizontal_accuracy_mm_valid = true,
		.horizontal_accuracy_mm = UINT32_MAX,
		.vertical_accuracy_mm_valid = true,
		.vertical_accuracy_mm = UINT32_MAX,
		.latitude_e7_valid = true,
		.latitude_e7 = INT32_MIN,
		.longitude_e7_valid = true,
		.longitude_e7 = INT32_MAX,
		.altitude_m_valid = true,
		.altitude_m = INT32_MIN,
		.fix_time_unix_valid = true,
		.fix_time_unix = UINT32_MAX,
		.satellites_valid = true,
		.satellites = UINT8_MAX,
	};
	uint8_t buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];
	struct status_view view;
	size_t len = encode_status_with_power(buf, sizeof(buf), &power, &location);

	zassert_true(len > 0U);
	zassert_true(len <= sizeof(buf));
	zassert_ok(decode_status(buf, len, &view));
	zassert_true(view.location_provider);
	zassert_true(view.time_provider);
	zassert_true(view.has_loc_source_class);
	zassert_str_equal(view.loc_source_class, "external_hardware");
	zassert_true(view.has_loc_source);
	zassert_str_equal(view.loc_source, "abcdefghijklmnopqrstuvw");
	zassert_true(view.has_lat_i);
	zassert_equal(view.lat_i, INT32_MIN);
	zassert_true(view.has_lon_i);
	zassert_equal(view.lon_i, INT32_MAX);
	zassert_true(view.has_alt_m);
	zassert_equal(view.alt_m, INT32_MIN);
}

ZTEST(gateway_status, test_stale_location_metadata_suppresses_position)
{
	const struct lichen_hal_location_sample sample = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC,
		.fix_state = LICHEN_HAL_LOCATION_FIX_3D,
		.fix_source = LICHEN_HAL_FIX_SOURCE_NONE,
		.source_name = "manual",
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 0,
		.horizontal_accuracy_mm_valid = true,
		.horizontal_accuracy_mm = 1200U,
		.vertical_accuracy_mm_valid = true,
		.vertical_accuracy_mm = 3400U,
		.latitude_e7_valid = true,
		.latitude_e7 = 476206130,
		.longitude_e7_valid = true,
		.longitude_e7 = -1223493000,
		.altitude_m_valid = true,
		.altitude_m = 42,
		.fix_time_unix_valid = true,
		.fix_time_unix = 1710000000U,
		.satellites_valid = true,
		.satellites = 9U,
	};
	struct lichen_hal_location_time_snapshot location;
	uint8_t buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];
	struct status_view view;
	size_t len;

	lichen_hal_location_time_test_set_snapshot(NULL);
	lichen_hal_location_clear();
	lichen_hal_location_test_set_uptime_ms(
		(int64_t)(CONFIG_LICHEN_LOCATION_FRESHNESS_MAX_AGE_S + 1) *
		1000);
	zassert_ok(lichen_hal_location_submit(&sample));
	zassert_ok(lichen_hal_location_time_snapshot_get(&location));
	len = encode_status(buf, sizeof(buf), &location);

	zassert_true(len > 0U);
	zassert_ok(decode_status(buf, len, &view));
	zassert_true(view.location_provider);
	zassert_false(view.time_provider);
	zassert_true(view.has_loc_source_class);
	zassert_str_equal(view.loc_source_class, "manual_static");
	zassert_true(view.has_loc_source);
	zassert_str_equal(view.loc_source, "manual");
	zassert_true(view.has_loc_fix_state);
	zassert_str_equal(view.loc_fix_state, "stale");
	zassert_true(view.has_loc_age_s);
	zassert_equal(view.loc_age_s, 301U);
	zassert_false(view.has_hacc_mm);
	zassert_false(view.has_vacc_mm);
	zassert_false(view.has_lat_i);
	zassert_false(view.has_lon_i);
	zassert_false(view.has_alt_m);
	zassert_false(view.has_time_unix);
	zassert_false(view.has_satellites);
}

ZTEST_SUITE(gateway_status, NULL, NULL, NULL, NULL, NULL);
