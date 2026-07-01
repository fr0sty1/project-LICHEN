/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "status_cbor.h"

#include <string.h>

static void cbor_put_map_header(uint8_t *buf, size_t *off, uint8_t count)
{
	if (count < 24U) {
		buf[(*off)++] = 0xa0U | count;
	} else {
		buf[(*off)++] = 0xb8;
		buf[(*off)++] = count;
	}
}

static void cbor_put_tstr(uint8_t *buf, size_t *off, const char *value)
{
	size_t len = strlen(value);

	if (len < 24U) {
		buf[(*off)++] = 0x60U | (uint8_t)len;
	} else if (len <= UINT8_MAX) {
		buf[(*off)++] = 0x78;
		buf[(*off)++] = (uint8_t)len;
	} else {
		buf[(*off)++] = 0x79;
		buf[(*off)++] = (uint8_t)(len >> 8);
		buf[(*off)++] = (uint8_t)(len & 0xffU);
	}
	memcpy(&buf[*off], value, len);
	*off += len;
}

static void cbor_put_key(uint8_t *buf, size_t *off, const char *key)
{
	cbor_put_tstr(buf, off, key);
}

static void cbor_put_bool(uint8_t *buf, size_t *off, bool value)
{
	buf[(*off)++] = value ? 0xf5 : 0xf4;
}

static void cbor_put_uint(uint8_t *buf, size_t *off, uint32_t value)
{
	if (value < 24U) {
		buf[(*off)++] = (uint8_t)value;
	} else if (value <= UINT8_MAX) {
		buf[(*off)++] = 0x18;
		buf[(*off)++] = (uint8_t)value;
	} else if (value <= UINT16_MAX) {
		buf[(*off)++] = 0x19;
		buf[(*off)++] = (uint8_t)(value >> 8);
		buf[(*off)++] = (uint8_t)(value & 0xffU);
	} else {
		buf[(*off)++] = 0x1a;
		buf[(*off)++] = (uint8_t)(value >> 24);
		buf[(*off)++] = (uint8_t)(value >> 16);
		buf[(*off)++] = (uint8_t)(value >> 8);
		buf[(*off)++] = (uint8_t)(value & 0xffU);
	}
}

static void cbor_put_int(uint8_t *buf, size_t *off, int32_t value)
{
	uint32_t encoded;

	if (value >= 0) {
		cbor_put_uint(buf, off, (uint32_t)value);
		return;
	}

	encoded = (uint32_t)(-1LL - (int64_t)value);
	if (encoded < 24U) {
		buf[(*off)++] = 0x20U | (uint8_t)encoded;
	} else if (encoded <= 0xffU) {
		buf[(*off)++] = 0x38;
		buf[(*off)++] = (uint8_t)encoded;
	} else if (encoded <= 0xffffU) {
		buf[(*off)++] = 0x39;
		buf[(*off)++] = (uint8_t)(encoded >> 8);
		buf[(*off)++] = (uint8_t)(encoded & 0xffU);
	} else {
		buf[(*off)++] = 0x3a;
		buf[(*off)++] = (uint8_t)(encoded >> 24);
		buf[(*off)++] = (uint8_t)(encoded >> 16);
		buf[(*off)++] = (uint8_t)(encoded >> 8);
		buf[(*off)++] = (uint8_t)(encoded & 0xffU);
	}
}

static const char *location_source_class_name(
	enum lichen_hal_location_source_class source_class)
{
	switch (source_class) {
	case LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE:
		return "onboard_hardware";
	case LICHEN_HAL_LOCATION_SOURCE_EXTERNAL_HARDWARE:
		return "external_hardware";
	case LICHEN_HAL_LOCATION_SOURCE_NETWORK:
		return "network";
	case LICHEN_HAL_LOCATION_SOURCE_LOCAL_CLIENT:
		return "local_client";
	case LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC:
		return "manual_static";
	case LICHEN_HAL_LOCATION_SOURCE_NONE:
	default:
		return "none";
	}
}

static const char *location_fix_state_name(
	enum lichen_hal_location_fix_state fix_state)
{
	switch (fix_state) {
	case LICHEN_HAL_LOCATION_FIX_NO_FIX:
		return "no_fix";
	case LICHEN_HAL_LOCATION_FIX_2D:
		return "2d";
	case LICHEN_HAL_LOCATION_FIX_3D:
		return "3d";
	case LICHEN_HAL_LOCATION_FIX_STALE:
		return "stale";
	case LICHEN_HAL_LOCATION_FIX_ERROR:
		return "error";
	case LICHEN_HAL_LOCATION_FIX_NONE:
	default:
		return "none";
	}
}

size_t lichen_gateway_encode_status_cbor(
	uint8_t *buf, size_t buf_size, uint16_t rank, const char *role,
	bool rpl_capable, uint32_t uptime_ms,
	const struct lichen_hal_power_snapshot *power,
	const struct lichen_hal_location_time_snapshot *location_time)
{
	size_t role_len = role ? strlen(role) : 0;
	uint8_t map_count = 8U;
	size_t off = 0;

	if (buf == NULL || power == NULL || location_time == NULL ||
	    role == NULL || role_len > LICHEN_GATEWAY_STATUS_CBOR_MAX_ROLE_LEN ||
	    buf_size < LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE) {
		return 0;
	}

	map_count += power->battery_percent_valid ? 1U : 0U;
	map_count += power->battery_voltage_mv_valid ? 1U : 0U;
	map_count += power->charging_valid ? 1U : 0U;
	map_count += power->external_power_valid ? 1U : 0U;
	map_count += location_time->source_class_valid ? 1U : 0U;
	map_count += location_time->source_name[0] != '\0' ? 1U : 0U;
	map_count += location_time->fix_state_valid ? 1U : 0U;
	map_count += location_time->age_seconds_valid ? 1U : 0U;
	map_count += location_time->horizontal_accuracy_mm_valid ? 1U : 0U;
	map_count += location_time->vertical_accuracy_mm_valid ? 1U : 0U;
	map_count += location_time->latitude_e7_valid ? 1U : 0U;
	map_count += location_time->longitude_e7_valid ? 1U : 0U;
	map_count += location_time->altitude_m_valid ? 1U : 0U;
	map_count += location_time->fix_time_unix_valid ? 1U : 0U;
	map_count += location_time->satellites_valid ? 1U : 0U;

	cbor_put_map_header(buf, &off, map_count);

	cbor_put_key(buf, &off, "rank");
	cbor_put_uint(buf, &off, rank);
	cbor_put_key(buf, &off, "role");
	cbor_put_tstr(buf, &off, role);
	cbor_put_key(buf, &off, "rpl");
	cbor_put_bool(buf, &off, rpl_capable);
	cbor_put_key(buf, &off, "uptime");
	cbor_put_uint(buf, &off, uptime_ms);

	cbor_put_key(buf, &off, "battery_provider");
	cbor_put_bool(buf, &off, power->battery_provider_available);
	cbor_put_key(buf, &off, "pmic_provider");
	cbor_put_bool(buf, &off, power->pmic_provider_available);
	cbor_put_key(buf, &off, "location_provider");
	cbor_put_bool(buf, &off, location_time->location_provider_available);
	cbor_put_key(buf, &off, "time_provider");
	cbor_put_bool(buf, &off, location_time->time_provider_available);

	if (power->battery_percent_valid) {
		cbor_put_key(buf, &off, "battery");
		cbor_put_uint(buf, &off, power->battery_percent);
	}
	if (power->battery_voltage_mv_valid) {
		cbor_put_key(buf, &off, "voltage_mv");
		cbor_put_uint(buf, &off, power->battery_voltage_mv);
	}
	if (power->charging_valid) {
		cbor_put_key(buf, &off, "charging");
		cbor_put_bool(buf, &off, power->charging);
	}
	if (power->external_power_valid) {
		cbor_put_key(buf, &off, "external_power");
		cbor_put_bool(buf, &off, power->external_power);
	}
	if (location_time->source_class_valid) {
		cbor_put_key(buf, &off, "loc_source_class");
		cbor_put_tstr(buf, &off,
			      location_source_class_name(location_time->source_class));
	}
	if (location_time->source_name[0] != '\0') {
		cbor_put_key(buf, &off, "loc_source");
		cbor_put_tstr(buf, &off, location_time->source_name);
	}
	if (location_time->fix_state_valid) {
		cbor_put_key(buf, &off, "loc_fix_state");
		cbor_put_tstr(buf, &off,
			      location_fix_state_name(location_time->fix_state));
	}
	if (location_time->age_seconds_valid) {
		cbor_put_key(buf, &off, "loc_age_s");
		cbor_put_uint(buf, &off, location_time->age_seconds);
	}
	if (location_time->horizontal_accuracy_mm_valid) {
		cbor_put_key(buf, &off, "hacc_mm");
		cbor_put_uint(buf, &off, location_time->horizontal_accuracy_mm);
	}
	if (location_time->vertical_accuracy_mm_valid) {
		cbor_put_key(buf, &off, "vacc_mm");
		cbor_put_uint(buf, &off, location_time->vertical_accuracy_mm);
	}
	if (location_time->latitude_e7_valid) {
		cbor_put_key(buf, &off, "lat_i");
		cbor_put_int(buf, &off, location_time->latitude_e7);
	}
	if (location_time->longitude_e7_valid) {
		cbor_put_key(buf, &off, "lon_i");
		cbor_put_int(buf, &off, location_time->longitude_e7);
	}
	if (location_time->altitude_m_valid) {
		cbor_put_key(buf, &off, "alt_m");
		cbor_put_int(buf, &off, location_time->altitude_m);
	}
	if (location_time->fix_time_unix_valid) {
		cbor_put_key(buf, &off, "time_unix");
		cbor_put_uint(buf, &off, location_time->fix_time_unix);
	}
	if (location_time->satellites_valid) {
		cbor_put_key(buf, &off, "satellites");
		cbor_put_uint(buf, &off, location_time->satellites);
	}

	return off;
}
