/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "config_cbor.h"

#include <errno.h>
#include <string.h>

#include <zcbor_decode.h>

#define CONFIG_KEY_TX_POWER_DBM "tx_power_dbm"
#define CONFIG_KEY_TX_POWER_DBM_LEN (sizeof(CONFIG_KEY_TX_POWER_DBM) - 1u)
#define CONFIG_KEY_MANUAL_LOCATION "manual_location"
#define CONFIG_KEY_MANUAL_LOCATION_LEN (sizeof(CONFIG_KEY_MANUAL_LOCATION) - 1u)
#define MANUAL_LOCATION_KEY_LAT_I "lat_i"
#define MANUAL_LOCATION_KEY_LAT_I_LEN (sizeof(MANUAL_LOCATION_KEY_LAT_I) - 1u)
#define MANUAL_LOCATION_KEY_LON_I "lon_i"
#define MANUAL_LOCATION_KEY_LON_I_LEN (sizeof(MANUAL_LOCATION_KEY_LON_I) - 1u)
#define MANUAL_LOCATION_KEY_HACC_MM "hacc_mm"
#define MANUAL_LOCATION_KEY_HACC_MM_LEN (sizeof(MANUAL_LOCATION_KEY_HACC_MM) - 1u)
#define MANUAL_LOCATION_KEY_SOURCE_NAME "source_name"
#define MANUAL_LOCATION_KEY_SOURCE_NAME_LEN (sizeof(MANUAL_LOCATION_KEY_SOURCE_NAME) - 1u)
#define MANUAL_LOCATION_KEY_AGE_S "age_s"
#define MANUAL_LOCATION_KEY_AGE_S_LEN (sizeof(MANUAL_LOCATION_KEY_AGE_S) - 1u)

static bool valid_manual_location_config(
	const struct lichen_gateway_manual_location_config *manual_location);

size_t lichen_gateway_encode_config_cbor(uint8_t *buf, size_t buf_size,
					 int8_t tx_power_dbm)
{
	if (buf == NULL || buf_size < 16) {
		return 0;
	}

	buf[0] = 0xa1;
	buf[1] = 0x6c;
	(void)memcpy(&buf[2], CONFIG_KEY_TX_POWER_DBM, CONFIG_KEY_TX_POWER_DBM_LEN);
	if (tx_power_dbm >= 0 && tx_power_dbm <= 23) {
		buf[14] = (uint8_t)tx_power_dbm;
		return 15;
	} else if (tx_power_dbm >= 24) {
		buf[14] = 0x18;
		buf[15] = (uint8_t)tx_power_dbm;
		return 16;
	} else if (tx_power_dbm >= -24) {
		buf[14] = (uint8_t)(0x20u + (uint8_t)(-tx_power_dbm - 1));
		return 15;
	} else {
		buf[14] = 0x38;
		buf[15] = (uint8_t)(-tx_power_dbm - 1);
		return 16;
	}
}

static bool put_type_len(uint8_t *buf, size_t cap, size_t *off,
			 uint8_t major, size_t len)
{
	if (len > 23U || *off >= cap) {
		return false;
	}
	buf[(*off)++] = (uint8_t)(major | (uint8_t)len);
	return true;
}

static bool put_tstr(uint8_t *buf, size_t cap, size_t *off,
		     const char *value, size_t len)
{
	if (!put_type_len(buf, cap, off, 0x60, len) || cap - *off < len) {
		return false;
	}
	memcpy(&buf[*off], value, len);
	*off += len;
	return true;
}

static bool put_uint(uint8_t *buf, size_t cap, size_t *off, uint32_t value)
{
	if (*off >= cap) {
		return false;
	}
	if (value <= 23U) {
		buf[(*off)++] = (uint8_t)value;
		return true;
	}
	if (value <= UINT8_MAX && cap - *off >= 2U) {
		buf[(*off)++] = 0x18;
		buf[(*off)++] = (uint8_t)value;
		return true;
	}
	if (value <= UINT16_MAX && cap - *off >= 3U) {
		buf[(*off)++] = 0x19;
		buf[(*off)++] = (uint8_t)(value >> 8);
		buf[(*off)++] = (uint8_t)value;
		return true;
	}
	if (cap - *off < 5U) {
		return false;
	}
	buf[(*off)++] = 0x1a;
	buf[(*off)++] = (uint8_t)(value >> 24);
	buf[(*off)++] = (uint8_t)(value >> 16);
	buf[(*off)++] = (uint8_t)(value >> 8);
	buf[(*off)++] = (uint8_t)value;
	return true;
}

static bool put_int(uint8_t *buf, size_t cap, size_t *off, int32_t value)
{
	if (value >= 0) {
		return put_uint(buf, cap, off, (uint32_t)value);
	}
	if (*off >= cap) {
		return false;
	}
	uint32_t encoded = (uint32_t)(-1LL - (int64_t)value);

	if (encoded <= 23U) {
		buf[(*off)++] = (uint8_t)(0x20U + encoded);
		return true;
	}
	if (encoded <= UINT8_MAX && cap - *off >= 2U) {
		buf[(*off)++] = 0x38;
		buf[(*off)++] = (uint8_t)encoded;
		return true;
	}
	if (encoded <= UINT16_MAX && cap - *off >= 3U) {
		buf[(*off)++] = 0x39;
		buf[(*off)++] = (uint8_t)(encoded >> 8);
		buf[(*off)++] = (uint8_t)encoded;
		return true;
	}
	if (cap - *off < 5U) {
		return false;
	}
	buf[(*off)++] = 0x3a;
	buf[(*off)++] = (uint8_t)(encoded >> 24);
	buf[(*off)++] = (uint8_t)(encoded >> 16);
	buf[(*off)++] = (uint8_t)(encoded >> 8);
	buf[(*off)++] = (uint8_t)encoded;
	return true;
}

size_t lichen_gateway_encode_config_update_cbor(
	uint8_t *buf, size_t buf_size,
	int8_t tx_power_dbm,
	const struct lichen_gateway_manual_location_config *manual_location)
{
	size_t off = 0U;
	size_t manual_count = 2U;
	size_t name_len;

	if (buf == NULL || buf_size == 0U) {
		return 0U;
	}
	if (!put_type_len(buf, buf_size, &off, 0xa0,
			  manual_location == NULL ? 1U : 2U) ||
	    !put_tstr(buf, buf_size, &off, CONFIG_KEY_TX_POWER_DBM,
		      CONFIG_KEY_TX_POWER_DBM_LEN) ||
	    !put_int(buf, buf_size, &off, tx_power_dbm)) {
		return 0U;
	}
	if (manual_location == NULL) {
		return off;
	}
	if (!valid_manual_location_config(manual_location)) {
		return 0U;
	}

	manual_count += manual_location->horizontal_accuracy_mm_valid ? 1U : 0U;
	manual_count += manual_location->age_seconds_valid ? 1U : 0U;
	name_len = strlen(manual_location->source_name);
	manual_count += name_len > 0U ? 1U : 0U;

	if (!put_tstr(buf, buf_size, &off, CONFIG_KEY_MANUAL_LOCATION,
		      CONFIG_KEY_MANUAL_LOCATION_LEN) ||
	    !put_type_len(buf, buf_size, &off, 0xa0, manual_count) ||
	    !put_tstr(buf, buf_size, &off, MANUAL_LOCATION_KEY_LAT_I,
		      MANUAL_LOCATION_KEY_LAT_I_LEN) ||
	    !put_int(buf, buf_size, &off, manual_location->latitude_e7) ||
	    !put_tstr(buf, buf_size, &off, MANUAL_LOCATION_KEY_LON_I,
		      MANUAL_LOCATION_KEY_LON_I_LEN) ||
	    !put_int(buf, buf_size, &off, manual_location->longitude_e7)) {
		return 0U;
	}
	if (manual_location->horizontal_accuracy_mm_valid &&
	    (!put_tstr(buf, buf_size, &off, MANUAL_LOCATION_KEY_HACC_MM,
		       MANUAL_LOCATION_KEY_HACC_MM_LEN) ||
	     !put_uint(buf, buf_size, &off,
		       manual_location->horizontal_accuracy_mm))) {
		return 0U;
	}
	if (manual_location->age_seconds_valid &&
	    (!put_tstr(buf, buf_size, &off, MANUAL_LOCATION_KEY_AGE_S,
		       MANUAL_LOCATION_KEY_AGE_S_LEN) ||
	     !put_uint(buf, buf_size, &off, manual_location->age_seconds))) {
		return 0U;
	}
	if (name_len > 0U &&
	    (!put_tstr(buf, buf_size, &off, MANUAL_LOCATION_KEY_SOURCE_NAME,
		       MANUAL_LOCATION_KEY_SOURCE_NAME_LEN) ||
	     !put_tstr(buf, buf_size, &off, manual_location->source_name,
		       name_len))) {
		return 0U;
	}

	return off;
}

static bool key_is_tx_power_dbm(const struct zcbor_string *key)
{
	return key->len == CONFIG_KEY_TX_POWER_DBM_LEN &&
	       memcmp(key->value, CONFIG_KEY_TX_POWER_DBM,
		      CONFIG_KEY_TX_POWER_DBM_LEN) == 0;
}

static bool key_matches(const struct zcbor_string *key, const char *expected,
			size_t expected_len)
{
	return key->len == expected_len &&
	       memcmp(key->value, expected, expected_len) == 0;
}

static bool valid_lat_lon(int32_t latitude_e7, int32_t longitude_e7)
{
	return latitude_e7 >= -900000000 && latitude_e7 <= 900000000 &&
	       longitude_e7 >= -1800000000 && longitude_e7 <= 1800000000;
}

static bool valid_source_name_bytes(const uint8_t *value, size_t len)
{
	for (size_t i = 0U; i < len; i++) {
		if (value[i] < 0x20U || value[i] > 0x7eU) {
			return false;
		}
	}

	return true;
}

static bool valid_manual_location_config(
	const struct lichen_gateway_manual_location_config *manual_location)
{
	size_t name_len;

	if (manual_location == NULL ||
	    !manual_location->latitude_e7_valid ||
	    !manual_location->longitude_e7_valid ||
	    !valid_lat_lon(manual_location->latitude_e7,
			   manual_location->longitude_e7)) {
		return false;
	}

	name_len = strnlen(manual_location->source_name,
			   sizeof(manual_location->source_name));
	if (name_len == sizeof(manual_location->source_name)) {
		return false;
	}

	return valid_source_name_bytes(
		(const uint8_t *)manual_location->source_name, name_len);
}

static int decode_manual_location(
	zcbor_state_t *zsd,
	struct lichen_gateway_manual_location_config *location)
{
	struct lichen_gateway_manual_location_config decoded = { 0 };
	int32_t value = 0;
	uint32_t uvalue = 0;
	struct zcbor_string tstr;
	bool source_name_seen = false;

	if (!zcbor_map_start_decode(zsd)) {
		return -EINVAL;
	}

	while (!zcbor_array_at_end(zsd)) {
		struct zcbor_string key;
		zcbor_state_t key_state = *zsd;

		if (!zcbor_tstr_decode(zsd, &key)) {
			(void)zcbor_list_map_end_force_decode(zsd);
			return -EINVAL;
		}

		if (key_matches(&key, MANUAL_LOCATION_KEY_LAT_I,
				MANUAL_LOCATION_KEY_LAT_I_LEN)) {
			if (decoded.latitude_e7_valid) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			if (!zcbor_int32_decode(zsd, &value)) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			decoded.latitude_e7 = value;
			decoded.latitude_e7_valid = true;
		} else if (key_matches(&key, MANUAL_LOCATION_KEY_LON_I,
				       MANUAL_LOCATION_KEY_LON_I_LEN)) {
			if (decoded.longitude_e7_valid) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			if (!zcbor_int32_decode(zsd, &value)) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			decoded.longitude_e7 = value;
			decoded.longitude_e7_valid = true;
		} else if (key_matches(&key, MANUAL_LOCATION_KEY_HACC_MM,
				       MANUAL_LOCATION_KEY_HACC_MM_LEN)) {
			if (decoded.horizontal_accuracy_mm_valid) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			if (!zcbor_uint32_decode(zsd, &uvalue)) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			decoded.horizontal_accuracy_mm = uvalue;
			decoded.horizontal_accuracy_mm_valid = true;
		} else if (key_matches(&key, MANUAL_LOCATION_KEY_AGE_S,
				       MANUAL_LOCATION_KEY_AGE_S_LEN)) {
			if (decoded.age_seconds_valid) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			if (!zcbor_uint32_decode(zsd, &uvalue)) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			decoded.age_seconds = uvalue;
			decoded.age_seconds_valid = true;
		} else if (key_matches(&key, MANUAL_LOCATION_KEY_SOURCE_NAME,
				       MANUAL_LOCATION_KEY_SOURCE_NAME_LEN)) {
			if (source_name_seen) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			if (!zcbor_tstr_decode(zsd, &tstr)) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			if (tstr.len >= sizeof(location->source_name)) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -ENAMETOOLONG;
			}
			if (!valid_source_name_bytes(tstr.value, tstr.len)) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			memcpy(decoded.source_name, tstr.value, tstr.len);
			decoded.source_name[tstr.len] = '\0';
			source_name_seen = true;
		} else {
			(void)zcbor_pop_error(zsd);
			*zsd = key_state;
			if (!zcbor_any_skip(zsd, NULL) ||
			    !zcbor_any_skip(zsd, NULL)) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
		}
	}

	if (!zcbor_map_end_decode(zsd) ||
	    !decoded.latitude_e7_valid ||
	    !valid_manual_location_config(&decoded)) {
		(void)zcbor_list_map_end_force_decode(zsd);
		return -EINVAL;
	}

	*location = decoded;
	return 0;
}

static bool key_is_manual_location(const struct zcbor_string *key)
{
	return key_matches(key, CONFIG_KEY_MANUAL_LOCATION,
			   CONFIG_KEY_MANUAL_LOCATION_LEN);
}

int lichen_gateway_decode_config_cbor(
	const uint8_t *buf, size_t len,
	struct lichen_gateway_config_update *update)
{
	bool found_tx_power = false;
	bool found_manual_location = false;
	int32_t decoded_tx_power = 0;

	if (buf == NULL || len == 0 || update == NULL) {
		return -EINVAL;
	}
	*update = (struct lichen_gateway_config_update){ 0 };

	ZCBOR_STATE_D(zsd, 2, buf, len, 1, 0);

	if (!zcbor_map_start_decode(zsd)) {
		return -EINVAL;
	}

	while (!zcbor_array_at_end(zsd)) {
		struct zcbor_string key;
		zcbor_state_t key_state = *zsd;

		if (!zcbor_tstr_decode(zsd, &key)) {
			(void)zcbor_list_map_end_force_decode(zsd);
			return -EINVAL;
		}

		if (key_is_tx_power_dbm(&key)) {
			if (found_tx_power) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			if (!zcbor_int32_decode(zsd, &decoded_tx_power) ||
			    decoded_tx_power < LICHEN_GATEWAY_TX_POWER_MIN_DBM ||
			    decoded_tx_power > LICHEN_GATEWAY_TX_POWER_MAX_DBM) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			found_tx_power = true;
			continue;
		}

		if (key_is_manual_location(&key)) {
			if (found_manual_location) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			if (decode_manual_location(zsd,
						   &update->manual_location) < 0) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			found_manual_location = true;
			continue;
		}

		(void)zcbor_pop_error(zsd);
		*zsd = key_state;

		if (!zcbor_any_skip(zsd, NULL) || !zcbor_any_skip(zsd, NULL)) {
			(void)zcbor_list_map_end_force_decode(zsd);
			return -EINVAL;
		}
	}

	if (!zcbor_map_end_decode(zsd) ||
	    !zcbor_payload_at_end(zsd) ||
	    (!found_tx_power && !found_manual_location)) {
		(void)zcbor_list_map_end_force_decode(zsd);
		return -EINVAL;
	}

	if (found_tx_power) {
		update->tx_power_dbm = (int8_t)decoded_tx_power;
		update->has_tx_power_dbm = true;
	}
	update->has_manual_location = found_manual_location;
	return 0;
}
