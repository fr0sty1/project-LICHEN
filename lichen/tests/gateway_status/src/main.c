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
	bool battery_provider;
	bool pmic_provider;
	bool location_provider;
	bool time_provider;
	bool wall_clock_valid;
	bool charging;
	bool external_power;
	bool time_passed_epoch_floor;
	bool time_provision_epoch_valid;
	bool time_reject_passed_epoch_floor;
	bool has_battery_provider;
	bool has_pmic_provider;
	bool has_location_provider;
	bool has_time_provider;
	bool has_wall_clock_valid;
	bool has_battery;
	bool has_voltage_mv;
	bool has_charging;
	bool has_external_power;
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
	bool has_time_source_class;
	bool has_time_source;
	bool has_wall_time_unix;
	bool has_time_age_s;
	bool has_time_accuracy_ms;
	bool has_time_quality;
	bool has_time_passed_epoch_floor;
	bool has_time_build_epoch;
	bool has_time_effective_epoch_floor;
	bool has_time_provision_epoch_valid;
	bool has_time_provision_epoch;
	bool has_time_reject;
	bool has_time_reject_source_class;
	bool has_time_reject_source;
	bool has_time_reject_passed_epoch_floor;
	char loc_source_class[24];
	char loc_source[24];
	char loc_fix_state[12];
	char time_source_class[24];
	char time_source[24];
	char time_reject[32];
	char time_reject_source_class[24];
	char time_reject_source[24];
	uint32_t battery;
	uint32_t voltage_mv;
	uint32_t loc_age_s;
	uint32_t hacc_mm;
	uint32_t vacc_mm;
	int32_t lat_i;
	int32_t lon_i;
	int32_t alt_m;
	uint32_t time_unix;
	uint32_t satellites;
	uint32_t wall_time_unix;
	uint32_t time_age_s;
	uint32_t time_accuracy_ms;
	uint32_t time_quality;
	uint32_t time_build_epoch;
	uint32_t time_effective_epoch_floor;
	uint32_t time_provision_epoch;
};

static size_t cbor_map_count(const uint8_t *buf, size_t len)
{
	if (buf == NULL || len == 0U) {
		return 0U;
	}
	if (buf[0] == 0xb8U && len >= 2U) {
		return buf[1];
	}
	if ((buf[0] & 0xe0U) == 0xa0U) {
		return buf[0] & 0x1fU;
	}
	return 0U;
}

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
		if (key_matches(&key, "battery_provider")) {
			out->has_battery_provider = zcbor_bool_decode(
				zsd, &out->battery_provider);
			decoded = out->has_battery_provider;
		} else if (key_matches(&key, "pmic_provider")) {
			out->has_pmic_provider = zcbor_bool_decode(
				zsd, &out->pmic_provider);
			decoded = out->has_pmic_provider;
		} else if (key_matches(&key, "location_provider")) {
			out->has_location_provider = zcbor_bool_decode(
				zsd, &out->location_provider);
			decoded = out->has_location_provider;
		} else if (key_matches(&key, "time_provider")) {
			out->has_time_provider = zcbor_bool_decode(
				zsd, &out->time_provider);
			decoded = out->has_time_provider;
		} else if (key_matches(&key, "wall_clock_valid")) {
			out->has_wall_clock_valid = zcbor_bool_decode(
				zsd, &out->wall_clock_valid);
			decoded = out->has_wall_clock_valid;
		} else if (key_matches(&key, "battery")) {
			out->has_battery = zcbor_uint32_decode(zsd, &out->battery);
			decoded = out->has_battery;
		} else if (key_matches(&key, "voltage_mv")) {
			out->has_voltage_mv = zcbor_uint32_decode(
				zsd, &out->voltage_mv);
			decoded = out->has_voltage_mv;
		} else if (key_matches(&key, "charging")) {
			out->has_charging = zcbor_bool_decode(zsd,
							     &out->charging);
			decoded = out->has_charging;
		} else if (key_matches(&key, "external_power")) {
			out->has_external_power = zcbor_bool_decode(
				zsd, &out->external_power);
			decoded = out->has_external_power;
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
		} else if (key_matches(&key, "time_source_class")) {
			out->has_time_source_class = copy_tstr(
				zsd, out->time_source_class,
				sizeof(out->time_source_class));
			decoded = out->has_time_source_class;
		} else if (key_matches(&key, "time_source")) {
			out->has_time_source = copy_tstr(
				zsd, out->time_source, sizeof(out->time_source));
			decoded = out->has_time_source;
		} else if (key_matches(&key, "wall_time_unix")) {
			out->has_wall_time_unix = zcbor_uint32_decode(
				zsd, &out->wall_time_unix);
			decoded = out->has_wall_time_unix;
		} else if (key_matches(&key, "time_age_s")) {
			out->has_time_age_s = zcbor_uint32_decode(
				zsd, &out->time_age_s);
			decoded = out->has_time_age_s;
		} else if (key_matches(&key, "time_accuracy_ms")) {
			out->has_time_accuracy_ms = zcbor_uint32_decode(
				zsd, &out->time_accuracy_ms);
			decoded = out->has_time_accuracy_ms;
		} else if (key_matches(&key, "time_quality")) {
			out->has_time_quality = zcbor_uint32_decode(
				zsd, &out->time_quality);
			decoded = out->has_time_quality;
		} else if (key_matches(&key, "time_passed_epoch_floor")) {
			out->has_time_passed_epoch_floor = zcbor_bool_decode(
				zsd, &out->time_passed_epoch_floor);
			decoded = out->has_time_passed_epoch_floor;
		} else if (key_matches(&key, "time_build_epoch")) {
			out->has_time_build_epoch = zcbor_uint32_decode(
				zsd, &out->time_build_epoch);
			decoded = out->has_time_build_epoch;
		} else if (key_matches(&key, "time_effective_epoch_floor")) {
			out->has_time_effective_epoch_floor =
				zcbor_uint32_decode(
					zsd, &out->time_effective_epoch_floor);
			decoded = out->has_time_effective_epoch_floor;
		} else if (key_matches(&key, "time_provision_epoch_valid")) {
			out->has_time_provision_epoch_valid =
				zcbor_bool_decode(
					zsd, &out->time_provision_epoch_valid);
			decoded = out->has_time_provision_epoch_valid;
		} else if (key_matches(&key, "time_provision_epoch")) {
			out->has_time_provision_epoch = zcbor_uint32_decode(
				zsd, &out->time_provision_epoch);
			decoded = out->has_time_provision_epoch;
		} else if (key_matches(&key, "time_reject")) {
			out->has_time_reject = copy_tstr(
				zsd, out->time_reject, sizeof(out->time_reject));
			decoded = out->has_time_reject;
		} else if (key_matches(&key, "time_reject_source_class")) {
			out->has_time_reject_source_class = copy_tstr(
				zsd, out->time_reject_source_class,
				sizeof(out->time_reject_source_class));
			decoded = out->has_time_reject_source_class;
		} else if (key_matches(&key, "time_reject_source")) {
			out->has_time_reject_source = copy_tstr(
				zsd, out->time_reject_source,
				sizeof(out->time_reject_source));
			decoded = out->has_time_reject_source;
		} else if (key_matches(&key, "time_reject_passed_epoch_floor")) {
			out->has_time_reject_passed_epoch_floor =
				zcbor_bool_decode(
					zsd, &out->time_reject_passed_epoch_floor);
			decoded = out->has_time_reject_passed_epoch_floor;
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
	const struct lichen_hal_time_snapshot time = { 0 };

	return lichen_gateway_encode_status_cbor(buf, buf_len, 256, "root",
						 true, 1234U, &power, location,
							 &time);
}

static size_t encode_status_with_time(
	uint8_t *buf, size_t buf_len,
	const struct lichen_hal_location_time_snapshot *location,
	const struct lichen_hal_time_snapshot *time)
{
	const struct lichen_hal_power_snapshot power = { 0 };

	return lichen_gateway_encode_status_cbor(buf, buf_len, 256, "root",
						 true, 1234U, &power, location,
						 time);
}

static size_t encode_status_with_power(
	uint8_t *buf, size_t buf_len,
	const struct lichen_hal_power_snapshot *power,
	const struct lichen_hal_location_time_snapshot *location)
{
	const struct lichen_hal_time_snapshot time = {
		.provider_available = true,
		.wall_clock_valid = true,
		.source_class_valid = true,
		.source_class = LICHEN_HAL_TIME_SOURCE_NETWORK,
		.source_name = "abcdefghijklmnopqrstuvw",
		.unix_time_valid = true,
		.unix_time = 1710000100U,
		.age_seconds_valid = true,
		.age_seconds = 3U,
		.accuracy_ms_valid = true,
		.accuracy_ms = 250U,
		.quality_valid = true,
		.quality = 200U,
		.passed_epoch_floor = true,
		.last_rejection = LICHEN_HAL_TIME_REJECT_PROVISION_UNAUTHENTICATED,
		.effective_epoch_floor = 1710000000U,
		.build_epoch = 1700000000U,
		.provision_epoch_valid = true,
		.provision_epoch = 1710000000U,
	};

	return lichen_gateway_encode_status_cbor(buf, buf_len, UINT16_MAX,
						 "border-router01", true,
						 UINT32_MAX, power, location,
						 &time);
}

static size_t encode_status_power_only(
	uint8_t *buf, size_t buf_len,
	const struct lichen_hal_power_snapshot *power)
{
	const struct lichen_hal_location_time_snapshot location = { 0 };
	const struct lichen_hal_time_snapshot time = { 0 };

	return lichen_gateway_encode_status_cbor(buf, buf_len, 256, "root",
						 true, 1234U, power, &location,
						 &time);
}

ZTEST(gateway_status, test_absent_location_metadata_is_omitted)
{
	const struct lichen_hal_location_time_snapshot location = { 0 };
	uint8_t buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];
	struct status_view view;
	size_t len = encode_status(buf, sizeof(buf), &location);

	zassert_true(len > 0U);
	zassert_equal(cbor_map_count(buf, len), 13U);
	zassert_ok(decode_status(buf, len, &view));
	zassert_true(view.has_battery_provider);
	zassert_false(view.battery_provider);
	zassert_true(view.has_pmic_provider);
	zassert_false(view.pmic_provider);
	zassert_false(view.has_battery);
	zassert_false(view.has_voltage_mv);
	zassert_false(view.has_charging);
	zassert_false(view.has_external_power);
	zassert_true(view.has_location_provider);
	zassert_false(view.location_provider);
	zassert_true(view.has_time_provider);
	zassert_false(view.time_provider);
	zassert_true(view.has_wall_clock_valid);
	zassert_false(view.wall_clock_valid);
	zassert_true(view.has_time_passed_epoch_floor);
	zassert_false(view.time_passed_epoch_floor);
	zassert_true(view.has_time_build_epoch);
	zassert_equal(view.time_build_epoch, 0U);
	zassert_true(view.has_time_effective_epoch_floor);
	zassert_equal(view.time_effective_epoch_floor, 0U);
	zassert_true(view.has_time_provision_epoch_valid);
	zassert_false(view.time_provision_epoch_valid);
	zassert_false(view.has_time_provision_epoch);
	zassert_false(view.has_time_reject);
	zassert_false(view.has_loc_source_class);
	zassert_false(view.has_loc_source);
	zassert_false(view.has_loc_fix_state);
	zassert_false(view.has_loc_age_s);
	zassert_false(view.has_lat_i);
	zassert_false(view.has_lon_i);
}

ZTEST(gateway_status, test_uptime_only_time_provider_keeps_legacy_time_false)
{
	const struct lichen_hal_location_time_snapshot location = { 0 };
	const struct lichen_hal_time_snapshot time = {
		.provider_available = true,
		.wall_clock_valid = false,
		.unix_time_valid = false,
	};
	uint8_t buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];
	struct status_view view;
	size_t len = encode_status_with_time(buf, sizeof(buf), &location, &time);

	zassert_true(len > 0U);
	zassert_ok(decode_status(buf, len, &view));
	zassert_true(view.has_time_provider);
	zassert_false(view.time_provider);
	zassert_true(view.has_wall_clock_valid);
	zassert_false(view.wall_clock_valid);
	zassert_false(view.has_wall_time_unix);
	zassert_false(view.has_time_reject);
}

ZTEST(gateway_status, test_gnss_below_epoch_rejection_is_diagnostic)
{
	const uint32_t build_epoch = CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX;
	const uint32_t provision_epoch = build_epoch + 100U;
	const struct lichen_hal_time_sample sample = {
		.source_class = LICHEN_HAL_TIME_SOURCE_GNSS,
		.source_name = "gnss0",
		.unix_time_valid = true,
		.unix_time = build_epoch + 50U,
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 1000,
		.accuracy_ms_valid = true,
		.accuracy_ms = 1500U,
		.quality_valid = true,
		.quality = 75U,
	};
	const struct lichen_hal_location_sample location_sample = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE,
		.fix_state = LICHEN_HAL_LOCATION_FIX_NO_FIX,
		.fix_source = LICHEN_HAL_FIX_SOURCE_GNSS,
		.source_name = "gnss0",
		.observed_uptime_ms_valid = true,
		.observed_uptime_ms = 1000,
	};
	struct lichen_hal_location_time_snapshot location;
	struct lichen_hal_time_snapshot time;
	uint8_t buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];
	struct status_view view;
	size_t len;

	lichen_hal_time_clear();
	lichen_hal_time_provision_epoch_clear();
	lichen_hal_location_test_set_uptime_ms(1000);
	zassert_ok(lichen_hal_location_submit(&location_sample));
	zassert_ok(lichen_hal_time_provision_epoch_set(provision_epoch, true));
	zassert_equal(lichen_hal_time_submit(&sample), -ERANGE);
	zassert_ok(lichen_hal_location_time_snapshot_get(&location));
	zassert_ok(lichen_hal_time_snapshot_get(&time));
	len = encode_status_with_time(buf, sizeof(buf), &location, &time);

	zassert_true(len > 0U);
	zassert_ok(decode_status(buf, len, &view));
	zassert_true(view.location_provider);
	zassert_true(view.has_time_provider);
	zassert_false(view.time_provider);
	zassert_true(view.has_loc_source_class);
	zassert_str_equal(view.loc_source_class, "onboard_hardware");
	zassert_true(view.has_loc_source);
	zassert_str_equal(view.loc_source, "gnss0");
	zassert_true(view.has_loc_fix_state);
	zassert_str_equal(view.loc_fix_state, "no_fix");
	zassert_true(view.has_time_source_class);
	zassert_str_equal(view.time_source_class, "gnss");
	zassert_true(view.has_time_source);
	zassert_str_equal(view.time_source, "gnss0");
	zassert_true(view.has_wall_clock_valid);
	zassert_false(view.wall_clock_valid);
	zassert_false(view.has_wall_time_unix);
	zassert_true(view.has_time_passed_epoch_floor);
	zassert_false(view.time_passed_epoch_floor);
	zassert_true(view.has_time_build_epoch);
	zassert_equal(view.time_build_epoch, build_epoch);
	zassert_true(view.has_time_effective_epoch_floor);
	zassert_equal(view.time_effective_epoch_floor, provision_epoch);
	zassert_true(view.has_time_provision_epoch_valid);
	zassert_true(view.time_provision_epoch_valid);
	zassert_true(view.has_time_provision_epoch);
	zassert_equal(view.time_provision_epoch, provision_epoch);
	zassert_true(view.has_time_accuracy_ms);
	zassert_equal(view.time_accuracy_ms, 1500U);
	zassert_true(view.has_time_quality);
	zassert_equal(view.time_quality, 75U);
	zassert_true(view.has_time_reject);
	zassert_str_equal(view.time_reject, "below_epoch_floor");
	zassert_true(view.has_time_reject_source_class);
	zassert_str_equal(view.time_reject_source_class, "gnss");
	zassert_true(view.has_time_reject_source);
	zassert_str_equal(view.time_reject_source, "gnss0");
	zassert_true(view.has_time_reject_passed_epoch_floor);
	zassert_false(view.time_reject_passed_epoch_floor);
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
	zassert_true(view.has_time_provider);
	zassert_true(view.time_provider);
	zassert_true(view.has_wall_clock_valid);
	zassert_false(view.wall_clock_valid);
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
	zassert_equal(cbor_map_count(buf, len), 36U);
	zassert_ok(decode_status(buf, len, &view));
	zassert_true(view.has_battery_provider);
	zassert_true(view.battery_provider);
	zassert_true(view.has_pmic_provider);
	zassert_true(view.pmic_provider);
	zassert_true(view.has_battery);
	zassert_equal(view.battery, 100U);
	zassert_true(view.has_voltage_mv);
	zassert_equal(view.voltage_mv, UINT16_MAX);
	zassert_true(view.has_charging);
	zassert_true(view.charging);
	zassert_true(view.has_external_power);
	zassert_true(view.external_power);
	zassert_true(view.location_provider);
	zassert_true(view.time_provider);
	zassert_true(view.has_wall_clock_valid);
	zassert_true(view.wall_clock_valid);
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
	zassert_true(view.has_time_source_class);
	zassert_str_equal(view.time_source_class, "network");
	zassert_true(view.has_time_source);
	zassert_str_equal(view.time_source, "abcdefghijklmnopqrstuvw");
	zassert_true(view.has_wall_time_unix);
	zassert_equal(view.wall_time_unix, 1710000100U);
	zassert_true(view.has_time_age_s);
	zassert_equal(view.time_age_s, 3U);
	zassert_true(view.has_time_accuracy_ms);
	zassert_equal(view.time_accuracy_ms, 250U);
	zassert_true(view.has_time_quality);
	zassert_equal(view.time_quality, 200U);
	zassert_true(view.has_time_passed_epoch_floor);
	zassert_true(view.time_passed_epoch_floor);
	zassert_true(view.has_time_build_epoch);
	zassert_equal(view.time_build_epoch, 1700000000U);
	zassert_true(view.has_time_effective_epoch_floor);
	zassert_equal(view.time_effective_epoch_floor, 1710000000U);
	zassert_true(view.has_time_provision_epoch_valid);
	zassert_true(view.time_provision_epoch_valid);
	zassert_true(view.has_time_provision_epoch);
	zassert_equal(view.time_provision_epoch, 1710000000U);
	zassert_true(view.has_time_reject);
	zassert_str_equal(view.time_reject, "provision_unauthenticated");
	zassert_false(view.has_time_reject_source_class);
	zassert_false(view.has_time_reject_source);
	zassert_false(view.has_time_reject_passed_epoch_floor);
}

ZTEST(gateway_status, test_power_fields_are_encoded)
{
	const struct lichen_hal_power_snapshot power = {
		.battery_provider_available = true,
		.pmic_provider_available = true,
		.battery_percent_valid = true,
		.battery_percent = 87U,
		.battery_voltage_mv_valid = true,
		.battery_voltage_mv = 4199U,
		.charging_valid = true,
		.charging = true,
		.external_power_valid = true,
		.external_power = true,
	};
	uint8_t buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];
	struct status_view view;
	size_t len = encode_status_power_only(buf, sizeof(buf), &power);

	zassert_true(len > 0U);
	zassert_equal(cbor_map_count(buf, len), 17U);
	zassert_ok(decode_status(buf, len, &view));
	zassert_true(view.has_battery_provider);
	zassert_true(view.battery_provider);
	zassert_true(view.has_pmic_provider);
	zassert_true(view.pmic_provider);
	zassert_true(view.has_battery);
	zassert_equal(view.battery, 87U);
	zassert_true(view.has_voltage_mv);
	zassert_equal(view.voltage_mv, 4199U);
	zassert_true(view.has_charging);
	zassert_true(view.charging);
	zassert_true(view.has_external_power);
	zassert_true(view.external_power);
	zassert_false(view.has_loc_source_class);
	zassert_false(view.has_wall_time_unix);
}

ZTEST(gateway_status, test_power_fields_are_valid_only)
{
	const struct lichen_hal_power_snapshot power = {
		.battery_provider_available = true,
		.pmic_provider_available = true,
		.battery_percent_valid = false,
		.battery_percent = 88U,
		.battery_voltage_mv_valid = true,
		.battery_voltage_mv = 3700U,
		.charging_valid = false,
		.charging = true,
		.external_power_valid = true,
		.external_power = false,
	};
	uint8_t buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];
	struct status_view view;
	size_t len = encode_status_power_only(buf, sizeof(buf), &power);

	zassert_true(len > 0U);
	zassert_equal(cbor_map_count(buf, len), 15U);
	zassert_ok(decode_status(buf, len, &view));
	zassert_true(view.has_battery_provider);
	zassert_true(view.battery_provider);
	zassert_true(view.has_pmic_provider);
	zassert_true(view.pmic_provider);
	zassert_false(view.has_battery);
	zassert_true(view.has_voltage_mv);
	zassert_equal(view.voltage_mv, 3700U);
	zassert_false(view.has_charging);
	zassert_true(view.has_external_power);
	zassert_false(view.external_power);
}

ZTEST(gateway_status, test_status_encoder_rejects_smaller_than_fixed_bound)
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
	const struct lichen_hal_location_time_snapshot location = { 0 };
	const struct lichen_hal_time_snapshot time = { 0 };
	uint8_t buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];

	zassert_equal(lichen_gateway_encode_status_cbor(
			      buf, sizeof(buf) - 1U, UINT16_MAX,
			      "border-router01", true, UINT32_MAX, &power,
			      &location, &time),
		      0U);
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
	zassert_true(view.has_wall_clock_valid);
	zassert_false(view.wall_clock_valid);
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

static void gateway_status_after(void *fixture)
{
	ARG_UNUSED(fixture);

	lichen_hal_location_clear();
	lichen_hal_time_clear();
	lichen_hal_time_provision_epoch_clear();
	lichen_hal_location_test_use_real_uptime();
}

ZTEST_SUITE(gateway_status, NULL, NULL, NULL, gateway_status_after, NULL);
