/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file senml.c
 * @brief SenML CBOR encoder
 *
 * Encodes sensor data as SenML (RFC 8428) in CBOR format.
 * Uses Zephyr's zcbor library for CBOR encoding.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <math.h>

#include <lichen/senml.h>
#include <lichen/errno.h>
#include <zcbor_encode.h>

#ifndef ENOTSUP
#define ENOTSUP 95
#endif

/* CBOR SenML label indices (RFC 8428 Section 6) */
enum senml_label {
	SENML_LABEL_BS = -6,  /* Base Sum */
	SENML_LABEL_BV = -5,  /* Base Value */
	SENML_LABEL_BU = -4,  /* Base Unit */
	SENML_LABEL_BT = -3,  /* Base Time */
	SENML_LABEL_BN = -2,  /* Base Name */
	SENML_LABEL_N  =  0,  /* Name */
	SENML_LABEL_U  =  1,  /* Unit */
	SENML_LABEL_V  =  2,  /* Value */
	SENML_LABEL_VS =  3,  /* String Value */
	SENML_LABEL_VB =  4,  /* Boolean Value */
	SENML_LABEL_S  =  5,  /* Sum */
	SENML_LABEL_T  =  6,  /* Time */
	SENML_LABEL_UT =  7,  /* Update Time */
	SENML_LABEL_VD =  8,  /* Data Value */
};

static bool string_too_long(const char *str, size_t max_len)
{
	return str != NULL && strnlen(str, max_len + 1) > max_len;
}

static int validate_name(const char *name)
{
	return string_too_long(name, SENML_MAX_NAME_LEN) ? -EMSGSIZE : 0;
}

static int validate_unit(const char *unit)
{
	return string_too_long(unit, SENML_MAX_UNIT_LEN) ? -EMSGSIZE : 0;
}

static int validate_string(const char *str)
{
	return string_too_long(str, SENML_MAX_STRING_LEN) ? -EMSGSIZE : 0;
}

int senml_pack_init(struct senml_pack *pack,
		    const char *base_name,
		    uint64_t base_time)
{
	if (pack == NULL) {
		return -EINVAL;
	}

	memset(pack, 0, sizeof(*pack));

	if (validate_name(base_name) < 0) {
		return -EMSGSIZE;
	}

	pack->base_name = base_name;
	if (base_time > 0) {
		pack->base_time = base_time;
		pack->has_base_time = true;
	}

	return 0;
}

int senml_add_float(struct senml_pack *pack,
		    const char *name,
		    const char *unit,
		    float value)
{
	if (pack == NULL || name == NULL) {
		return -EINVAL;
	}

	if (validate_name(name) < 0 || validate_unit(unit) < 0) {
		return -EMSGSIZE;
	}

	if (pack->record_count >= SENML_MAX_RECORDS) {
		return -ENOMEM;
	}

	struct senml_record *rec = &pack->records[pack->record_count++];
	rec->name = name;
	rec->unit = unit;
	rec->type = SENML_VALUE_FLOAT;
	rec->value.f = value;
	rec->time_offset = 0;
	rec->has_time = false;

	return 0;
}

int senml_add_float_t(struct senml_pack *pack,
		      const char *name,
		      const char *unit,
		      float value,
		      int32_t time_offset)
{
	if (pack == NULL || name == NULL) {
		return -EINVAL;
	}

	if (validate_name(name) < 0 || validate_unit(unit) < 0) {
		return -EMSGSIZE;
	}

	if (pack->record_count >= SENML_MAX_RECORDS) {
		return -ENOMEM;
	}

	struct senml_record *rec = &pack->records[pack->record_count++];
	rec->name = name;
	rec->unit = unit;
	rec->type = SENML_VALUE_FLOAT;
	rec->value.f = value;
	rec->time_offset = time_offset;
	rec->has_time = true;

	return 0;
}

int senml_add_bool(struct senml_pack *pack,
		   const char *name,
		   bool value)
{
	if (pack == NULL || name == NULL) {
		return -EINVAL;
	}

	if (validate_name(name) < 0) {
		return -EMSGSIZE;
	}

	if (pack->record_count >= SENML_MAX_RECORDS) {
		return -ENOMEM;
	}

	struct senml_record *rec = &pack->records[pack->record_count++];
	rec->name = name;
	rec->unit = NULL;
	rec->type = SENML_VALUE_BOOL;
	rec->value.b = value;
	rec->time_offset = 0;
	rec->has_time = false;

	return 0;
}

int senml_add_string(struct senml_pack *pack,
		    const char *name,
		    const char *value)
{
	if (pack == NULL || name == NULL) {
		return -EINVAL;
	}

	if (validate_name(name) < 0 || (value != NULL && validate_string(value) < 0)) {
		return -EMSGSIZE;
	}

	if (pack->record_count >= SENML_MAX_RECORDS) {
		return -ENOMEM;
	}

	struct senml_record *rec = &pack->records[pack->record_count++];
	rec->name = name;
	rec->unit = NULL;
	rec->type = SENML_VALUE_STRING;
	rec->value.s = value;
	rec->time_offset = 0;
	rec->has_time = false;

	return 0;
}

 /*
  * Encode a single SenML record as a CBOR map.
  * Returns: 0 on success, -ENOTSUP for unsupported types, -ENOMEM on CBOR error
  */
static int encode_record(zcbor_state_t *state,
			 const struct senml_record *rec,
			 const struct senml_pack *pack,
			 bool is_first)

{
	/* Count map entries */
	size_t entries = 1; /* value always present */
	if (is_first && pack->base_name != NULL) entries++;
	if (is_first && pack->has_base_time) entries++;
	if (rec->name != NULL) entries++;
	if (rec->unit != NULL) entries++;
	if (rec->has_time) entries++;

	if ((is_first && validate_name(pack->base_name) < 0) ||
	    validate_name(rec->name) < 0 ||
	    validate_unit(rec->unit) < 0 ||
	    (rec->type == SENML_VALUE_STRING && rec->value.s != NULL &&
	     validate_string(rec->value.s) < 0)) {
		return -EMSGSIZE;
	}

	if (!zcbor_map_start_encode(state, entries)) {
		return -ENOMEM;
	}

	/* Base name (first record only) */
	if (is_first && pack->base_name != NULL) {
		if (!zcbor_int32_put(state, SENML_LABEL_BN) ||
		    !zcbor_tstr_put_term(state, pack->base_name, 256)) {
			return -ENOMEM;
		}
	}

	/* Base time (first record only) */
	if (is_first && pack->has_base_time) {
		if (!zcbor_int32_put(state, SENML_LABEL_BT) ||
		    !zcbor_uint64_put(state, pack->base_time)) {
			return -ENOMEM;
		}
	}

	/* Name */
	if (rec->name != NULL) {
		if (!zcbor_int32_put(state, SENML_LABEL_N) ||
		    !zcbor_tstr_put_term(state, rec->name, 256)) {
			return -ENOMEM;
		}
	}

	/* Unit */
	if (rec->unit != NULL) {
		if (!zcbor_int32_put(state, SENML_LABEL_U) ||
		    !zcbor_tstr_put_term(state, rec->unit, 256)) {
			return -ENOMEM;
		}
	}

	/* Value */
	switch (rec->type) {
	case SENML_VALUE_FLOAT:
		if (!zcbor_int32_put(state, SENML_LABEL_V) ||
		    !zcbor_float32_put(state, rec->value.f)) {
			return -ENOMEM;
		}
		break;

	case SENML_VALUE_BOOL:
		if (!zcbor_int32_put(state, SENML_LABEL_VB) ||
		    !zcbor_bool_put(state, rec->value.b)) {
			return -ENOMEM;
		}
		break;

	case SENML_VALUE_STRING:
		if (rec->value.s == NULL ||
		    !zcbor_int32_put(state, SENML_LABEL_VS) ||
		    !zcbor_tstr_put_term(state, rec->value.s, 256)) {
			return -ENOMEM;
		}
		break;

	case SENML_VALUE_DATA:
		return -ENOTSUP;
	default:
		return -EINVAL;
	}

	/* Time offset */
	if (rec->has_time) {
		if (!zcbor_int32_put(state, SENML_LABEL_T) ||
		    !zcbor_int32_put(state, rec->time_offset)) {
			return -ENOMEM;
		}
	}

	if (!zcbor_map_end_encode(state, entries)) {
		return -ENOMEM;
	}

	return 0;
}

/**
 * @brief Encode a SenML pack to CBOR
 *
 * @return Encoded length on success, or negative errno:
 *         -EINVAL: No records in pack
 *         -ENOMEM: Output buffer too small
 *         -EMSGSIZE: Encoded length exceeds INT_MAX
 */
int senml_encode_cbor(const struct senml_pack *pack,
		      uint8_t *buf, size_t buflen)
{
	if (pack == NULL || buf == NULL) {
		return -EINVAL;
	}

	if (pack->record_count == 0) {
		return -EINVAL;
	}

	ZCBOR_STATE_E(state, 1, buf, buflen, 1);

	/* SenML is an array of records */
	if (!zcbor_list_start_encode(state, pack->record_count)) {
		return -ENOMEM;
	}

	/* Encode each record */
	for (size_t i = 0; i < pack->record_count; i++) {
		int ret = encode_record(state, &pack->records[i], pack, (i == 0));
		if (ret < 0) {
			return ret;
		}
	}

	if (!zcbor_list_end_encode(state, pack->record_count)) {
		return -ENOMEM;
	}

	/* Calculate encoded length */
	size_t encoded_len = state->payload - buf;
	if (encoded_len > (size_t)INT_MAX) {
		return -EMSGSIZE;
	}

	return (int)encoded_len;
}

int senml_encode_location(const char *base_name, uint64_t base_time,
			  float lat, float lon, float alt,
			  uint8_t *buf, size_t buflen)
{
	struct senml_pack pack;
	int ret;

	/* Validate lat/lon are finite (not NaN or Inf) */
	if (isnan(lat) || isnan(lon) || isinf(lat) || isinf(lon)) {
		return -EINVAL;
	}

	/* Validate WGS84 coordinate ranges */
	if (lat < -90.0f || lat > 90.0f || lon < -180.0f || lon > 180.0f) {
		return -ERANGE;
	}

	ret = senml_pack_init(&pack, base_name, base_time);
	if (ret < 0) {
		return ret;
	}

	ret = senml_add_float(&pack, SENML_LOCATION_LAT, SENML_LOCATION_LAT, lat);
	if (ret < 0) {
		return ret;
	}

	ret = senml_add_float(&pack, SENML_LOCATION_LON, SENML_LOCATION_LON, lon);
	if (ret < 0) {
		return ret;
	}

	if (!isnan(alt)) {
		ret = senml_add_float(&pack, SENML_LOCATION_ALT, SENML_LOCATION_UNIT_M, alt);
		if (ret < 0) {
			return ret;
		}
	}

	return senml_encode_cbor(&pack, buf, buflen);
}

int senml_encode_battery(const char *base_name, uint64_t base_time,
			 uint8_t percent, uint16_t mv, bool charging,
			 uint8_t *buf, size_t buflen)
{
	struct senml_pack pack;
	int ret;

	ret = senml_pack_init(&pack, base_name, base_time);
	if (ret < 0) {
		return ret;
	}

	/* Use "%" for battery percentage (not %RH which is relative humidity) */
	ret = senml_add_float(&pack, "pct", "%", (float)percent);
	if (ret < 0) {
		return ret;
	}

	ret = senml_add_float(&pack, "mv", "mV", (float)mv);
	if (ret < 0) {
		return ret;
	}

	ret = senml_add_bool(&pack, "charging", charging);
	if (ret < 0) {
		return ret;
	}

	return senml_encode_cbor(&pack, buf, buflen);
}

int senml_encode_temperature(const char *base_name, uint64_t base_time,
			     float temp_c,
			     uint8_t *buf, size_t buflen)
{
	struct senml_pack pack;
	int ret;

	ret = senml_pack_init(&pack, base_name, base_time);
	if (ret < 0) {
		return ret;
	}

	ret = senml_add_float(&pack, "temp", "Cel", temp_c);
	if (ret < 0) {
		return ret;
	}

	return senml_encode_cbor(&pack, buf, buflen);
}

int senml_encode_deaddrop(const char *base_name, uint64_t base_time,
			  uint16_t pending,
			  uint8_t *buf, size_t buflen)
{
	struct senml_pack pack;
	int ret;

	ret = senml_pack_init(&pack, base_name, base_time);
	if (ret < 0) {
		return ret;
	}

	ret = senml_add_float(&pack, "pending", NULL, (float)pending);
	if (ret < 0) {
		return ret;
	}

	return senml_encode_cbor(&pack, buf, buflen);
}
