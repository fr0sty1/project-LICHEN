/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file senml.c
 * @brief Allocation-free SenML CBOR codec
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
	pack->base_time = base_time;
	pack->has_base_time = base_time != 0U;

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

	if (isnan(value) || isinf(value)) {
		return -EINVAL;
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

	if (isnan(value) || isinf(value)) {
		return -EINVAL;
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

int senml_add_data(struct senml_pack *pack, const char *name,
		   const uint8_t *data, size_t data_len)
{
	if (pack == NULL || name == NULL || (data == NULL && data_len != 0U)) {
		return -EINVAL;
	}
	if (validate_name(name) < 0 || data_len > SENML_MAX_DATA_LEN) {
		return -EMSGSIZE;
	}
	if (pack->record_count >= SENML_MAX_RECORDS) {
		return -ENOMEM;
	}

	struct senml_record *rec = &pack->records[pack->record_count++];
	rec->name = name;
	rec->unit = NULL;
	rec->type = SENML_VALUE_DATA;
	rec->value.data.data = data;
	rec->value.data.len = data_len;
	rec->time_offset = 0;
	rec->has_time = false;

	return 0;
}

/* Encode a single SenML record as a CBOR map. */
static int encode_record(zcbor_state_t *state,
			 const struct senml_record *rec,
			 const struct senml_pack *pack,
			 bool is_first)

{
	/* Count map entries (order matches encoding: BT, BN, N, U, V/VB/VS, T) */
	size_t entries = 1; /* value always present */
	if (is_first && pack->has_base_time) entries++;
	if (is_first && pack->base_name != NULL) entries++;
	if (rec->name != NULL) entries++;
	if (rec->unit != NULL) entries++;
	if (rec->has_time) entries++;

	if (rec->type == SENML_VALUE_FLOAT && !isfinite(rec->value.f)) {
		return -EINVAL;
	}
	if ((is_first && validate_name(pack->base_name) < 0) ||
	    validate_name(rec->name) < 0 ||
	    validate_unit(rec->unit) < 0 ||
	    (rec->type == SENML_VALUE_STRING && rec->value.s != NULL &&
	     validate_string(rec->value.s) < 0) ||
	    (rec->type == SENML_VALUE_DATA &&
	     (rec->value.data.len > SENML_MAX_DATA_LEN ||
	      (rec->value.data.data == NULL && rec->value.data.len != 0U)))) {
		return -EMSGSIZE;
	}

	if (!zcbor_map_start_encode(state, entries)) {
		return -ENOMEM;
	}

	/* Base time (first record only) — encoded before base name per canonical CBOR ordering (RFC 8428 §6) */
	if (is_first && pack->has_base_time) {
		if (!zcbor_int32_put(state, SENML_LABEL_BT) ||
		    !zcbor_uint64_put(state, pack->base_time)) {
			return -ENOMEM;
		}
	}

	/* Base name (first record only) */
	if (is_first && pack->base_name != NULL) {
		if (!zcbor_int32_put(state, SENML_LABEL_BN) ||
		    !zcbor_tstr_put_term(state, pack->base_name, 256)) {
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

	case SENML_VALUE_STRING: {
		const char *str = rec->value.s != NULL ? rec->value.s : "";
		if (!zcbor_int32_put(state, SENML_LABEL_VS) ||
		    !zcbor_tstr_put_term(state, str, 256)) {
			return -ENOMEM;
		}
		}
		break;

	case SENML_VALUE_DATA:
		if (!zcbor_int32_put(state, SENML_LABEL_VD) ||
		    !zcbor_bstr_encode_ptr(state,
				      rec->value.data.len == 0U ? "" :
				      (const char *)rec->value.data.data,
				      rec->value.data.len)) {
			return -ENOMEM;
		}
		break;
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

	if (pack->record_count == 0 || pack->record_count > SENML_MAX_RECORDS) {
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

struct cbor_cursor {
	const uint8_t *buf;
	size_t len;
	size_t pos;
};

static int cbor_read_argument(struct cbor_cursor *cursor, uint8_t ai,
			      uint64_t *value)
{
	size_t width;

	if (ai < 24U) {
		*value = ai;
		return 0;
	}
	switch (ai) {
	case 24U:
		width = 1U;
		break;
	case 25U:
		width = 2U;
		break;
	case 26U:
		width = 4U;
		break;
	case 27U:
		width = 8U;
		break;
	default:
		/* Indefinite-length items and reserved additional values are not
		 * accepted by this bounded codec. */
		return -EINVAL;
	}
	if (width > cursor->len - cursor->pos) {
		return -EINVAL;
	}

	*value = 0U;
	for (size_t i = 0; i < width; i++) {
		*value = (*value << UINT64_C(8)) |
			 (uint64_t)cursor->buf[cursor->pos++];
	}
	return 0;
}

static int cbor_read_head(struct cbor_cursor *cursor, uint8_t *major,
			  uint8_t *ai, uint64_t *value)
{
	uint8_t initial;

	if (cursor->pos >= cursor->len) {
		return -EINVAL;
	}
	initial = cursor->buf[cursor->pos++];
	*major = (uint8_t)((uint32_t)initial >> 5U);
	*ai = initial & 0x1fU;
	return cbor_read_argument(cursor, *ai, value);
}

static int cbor_read_int(struct cbor_cursor *cursor, int64_t *value)
{
	uint8_t major;
	uint8_t ai;
	uint64_t argument;
	int ret = cbor_read_head(cursor, &major, &ai, &argument);

	(void)ai;
	if (ret < 0 || major > 1U || argument > (uint64_t)INT64_MAX) {
		return -EINVAL;
	}
	if (major == 0U) {
		*value = (int64_t)argument;
	} else {
		*value = -1 - (int64_t)argument;
	}
	return 0;
}

static double cbor_half_to_double(uint16_t bits)
{
	uint16_t exponent = (uint16_t)(((uint32_t)bits >> 10U) &
				       UINT32_C(0x1f));
	uint16_t fraction = bits & 0x03ffU;
	double value;

	if (exponent == 0U) {
		value = ldexp((double)fraction, -24);
	} else if (exponent == 0x1fU) {
		value = fraction == 0U ? (double)INFINITY : (double)NAN;
	} else {
		value = ldexp((double)(fraction + 1024U), (int)exponent - 25);
	}
	return (bits & 0x8000U) != 0U ? -value : value;
}

static int cbor_read_number(struct cbor_cursor *cursor, double *value)
{
	uint8_t major;
	uint8_t ai;
	uint64_t argument;
	int ret = cbor_read_head(cursor, &major, &ai, &argument);

	if (ret < 0) {
		return ret;
	}
	if (major == 0U) {
		*value = (double)argument;
	} else if (major == 1U) {
		*value = -(double)argument - 1.0;
	} else if (major == 7U && ai == 25U) {
		*value = cbor_half_to_double((uint16_t)argument);
	} else if (major == 7U && ai == 26U) {
		union {
			uint32_t bits;
			float number;
		} decoded = { .bits = (uint32_t)argument };

		*value = (double)decoded.number;
	} else if (major == 7U && ai == 27U) {
		union {
			uint64_t bits;
			double number;
		} decoded = { .bits = argument };

		*value = decoded.number;
	} else {
		return -EINVAL;
	}
	return isfinite(*value) ? 0 : -EINVAL;
}

static bool valid_utf8(const uint8_t *data, size_t len)
{
	size_t i = 0U;

	while (i < len) {
		uint8_t lead = data[i++];
		size_t continuation;
		uint32_t codepoint;

		if (lead < 0x80U) {
			continue;
		}
		if (lead >= 0xc2U && lead <= 0xdfU) {
			continuation = 1U;
			codepoint = lead & 0x1fU;
		} else if (lead >= 0xe0U && lead <= 0xefU) {
			continuation = 2U;
			codepoint = lead & 0x0fU;
		} else if (lead >= 0xf0U && lead <= 0xf4U) {
			continuation = 3U;
			codepoint = lead & 0x07U;
		} else {
			return false;
		}
		if (continuation > len - i) {
			return false;
		}
		for (size_t j = 0; j < continuation; j++) {
			uint8_t byte = data[i++];

			if ((byte & 0xc0U) != 0x80U) {
				return false;
			}
			codepoint = (codepoint << 6U) |
				    ((uint32_t)byte & UINT32_C(0x3f));
		}
		if ((continuation == 2U && codepoint < 0x800U) ||
		    (continuation == 3U && codepoint < 0x10000U) ||
		    (codepoint >= 0xd800U && codepoint <= 0xdfffU) ||
		    codepoint > 0x10ffffU) {
			return false;
		}
	}
	return true;
}

static int cbor_read_span(struct cbor_cursor *cursor, uint8_t expected_major,
			  struct senml_span *span)
{
	uint8_t major;
	uint8_t ai;
	uint64_t argument;
	int ret = cbor_read_head(cursor, &major, &ai, &argument);

	(void)ai;
	if (ret < 0 || major != expected_major ||
	    argument > (uint64_t)SIZE_MAX ||
	    (size_t)argument > cursor->len - cursor->pos) {
		return -EINVAL;
	}
	span->data = &cursor->buf[cursor->pos];
	span->len = (size_t)argument;
	cursor->pos += span->len;
	if (expected_major == 3U && !valid_utf8(span->data, span->len)) {
		return -EINVAL;
	}
	return 0;
}

static int cbor_skip(struct cbor_cursor *cursor, unsigned int depth)
{
	uint8_t major;
	uint8_t ai;
	uint64_t argument;
	int ret;

	if (depth > 8U) {
		return -EINVAL;
	}
	ret = cbor_read_head(cursor, &major, &ai, &argument);
	if (ret < 0) {
		return ret;
	}
	switch (major) {
	case 0U:
	case 1U:
	case 7U:
		return 0;
	case 2U:
		if (argument > (uint64_t)SIZE_MAX ||
		    (size_t)argument > cursor->len - cursor->pos) {
			return -EINVAL;
		}
		cursor->pos += (size_t)argument;
		return 0;
	case 3U:
		if (argument > (uint64_t)SIZE_MAX ||
		    (size_t)argument > cursor->len - cursor->pos ||
		    !valid_utf8(&cursor->buf[cursor->pos], (size_t)argument)) {
			return -EINVAL;
		}
		cursor->pos += (size_t)argument;
		return 0;
	case 4U:
		if (argument > cursor->len - cursor->pos) {
			return -EINVAL;
		}
		for (uint64_t i = 0U; i < argument; i++) {
			ret = cbor_skip(cursor, depth + 1U);
			if (ret < 0) {
				return ret;
			}
		}
		return 0;
	case 5U:
		if (argument > (cursor->len - cursor->pos) / 2U) {
			return -EINVAL;
		}
		for (uint64_t i = 0U; i < argument; i++) {
			ret = cbor_skip(cursor, depth + 1U);
			if (ret < 0) {
				return ret;
			}
			ret = cbor_skip(cursor, depth + 1U);
			if (ret < 0) {
				return ret;
			}
		}
		return 0;
	case 6U:
		return cbor_skip(cursor, depth + 1U);
	default:
		(void)ai;
		return -EINVAL;
	}
}

static int cbor_read_bool(struct cbor_cursor *cursor, bool *value)
{
	uint8_t major;
	uint8_t ai;
	uint64_t argument;
	int ret = cbor_read_head(cursor, &major, &ai, &argument);

	(void)argument;
	if (ret < 0 || major != 7U || (ai != 20U && ai != 21U)) {
		return -EINVAL;
	}
	*value = ai == 21U;
	return 0;
}

static int decode_record(struct cbor_cursor *cursor,
			 struct senml_decoded_record *record)
{
	uint8_t major;
	uint8_t ai;
	uint64_t entries;
	uint16_t seen = 0U;
	unsigned int value_count = 0U;
	int ret = cbor_read_head(cursor, &major, &ai, &entries);

	(void)ai;
	if (ret < 0 || major != 5U || entries > (cursor->len - cursor->pos) / 2U) {
		return -EINVAL;
	}
	memset(record, 0, sizeof(*record));

	for (uint64_t i = 0U; i < entries; i++) {
		size_t key_start = cursor->pos;
		int64_t key;

		if (key_start >= cursor->len) {
			return -EINVAL;
		}
		major = (uint8_t)((uint32_t)cursor->buf[key_start] >> 5U);
		if (major == 3U) {
			struct senml_span extension;

			ret = cbor_read_span(cursor, 3U, &extension);
			if (ret < 0 ||
			    (extension.len != 0U &&
			     extension.data[extension.len - 1U] == (uint8_t)'_')) {
				return -EINVAL;
			}
			ret = cbor_skip(cursor, 1U);
			if (ret < 0) {
				return ret;
			}
			continue;
		}
		ret = cbor_read_int(cursor, &key);
		if (ret < 0) {
			return ret;
		}
		if (key < SENML_LABEL_BS || key > SENML_LABEL_VD) {
			ret = cbor_skip(cursor, 1U);
			if (ret < 0) {
				return ret;
			}
			continue;
		}

		uint16_t bit = (uint16_t)(1U << (unsigned int)(key - SENML_LABEL_BS));
		if ((seen & bit) != 0U) {
			return -EINVAL;
		}
		seen |= bit;

		switch (key) {
		case SENML_LABEL_BS:
			ret = cbor_read_number(cursor, &record->base_sum);
			record->has_base_sum = ret == 0;
			break;
		case SENML_LABEL_BV:
			ret = cbor_read_number(cursor, &record->base_value);
			record->has_base_value = ret == 0;
			break;
		case SENML_LABEL_BU:
			ret = cbor_read_span(cursor, 3U, &record->base_unit);
			if (ret == 0 && record->base_unit.len > SENML_MAX_UNIT_LEN) {
				ret = -EMSGSIZE;
			}
			record->has_base_unit = ret == 0;
			break;
		case SENML_LABEL_BT:
			ret = cbor_read_number(cursor, &record->base_time);
			record->has_base_time = ret == 0;
			break;
		case SENML_LABEL_BN:
			ret = cbor_read_span(cursor, 3U, &record->base_name);
			if (ret == 0 && record->base_name.len > SENML_MAX_NAME_LEN) {
				ret = -EMSGSIZE;
			}
			record->has_base_name = ret == 0;
			break;
		case -1: {
			int64_t version;

			ret = cbor_read_int(cursor, &version);
			if (ret == 0 && (version < 1 || version > 10)) {
				ret = -EINVAL;
			}
			if (ret == 0) {
				record->base_version = (uint8_t)version;
				record->has_base_version = true;
			}
			break;
		}
		case SENML_LABEL_N:
			ret = cbor_read_span(cursor, 3U, &record->name);
			if (ret == 0 && record->name.len > SENML_MAX_NAME_LEN) {
				ret = -EMSGSIZE;
			}
			record->has_name = ret == 0;
			break;
		case SENML_LABEL_U:
			ret = cbor_read_span(cursor, 3U, &record->unit);
			if (ret == 0 && record->unit.len > SENML_MAX_UNIT_LEN) {
				ret = -EMSGSIZE;
			}
			record->has_unit = ret == 0;
			break;
		case SENML_LABEL_V:
			ret = cbor_read_number(cursor, &record->value);
			if (ret == 0) {
				record->value_type = SENML_VALUE_FLOAT;
				record->has_value = true;
				value_count++;
			}
			break;
		case SENML_LABEL_VS:
			ret = cbor_read_span(cursor, 3U, &record->string_value);
			if (ret == 0 && record->string_value.len > SENML_MAX_STRING_LEN) {
				ret = -EMSGSIZE;
			}
			if (ret == 0) {
				record->value_type = SENML_VALUE_STRING;
				record->has_value = true;
				value_count++;
			}
			break;
		case SENML_LABEL_VB:
			ret = cbor_read_bool(cursor, &record->bool_value);
			if (ret == 0) {
				record->value_type = SENML_VALUE_BOOL;
				record->has_value = true;
				value_count++;
			}
			break;
		case SENML_LABEL_S:
			ret = cbor_read_number(cursor, &record->sum);
			record->has_sum = ret == 0;
			break;
		case SENML_LABEL_T:
			ret = cbor_read_number(cursor, &record->time);
			record->has_time = ret == 0;
			break;
		case SENML_LABEL_UT:
			ret = cbor_read_number(cursor, &record->update_time);
			record->has_update_time = ret == 0;
			break;
		case SENML_LABEL_VD:
			ret = cbor_read_span(cursor, 2U, &record->data_value);
			if (ret == 0 && record->data_value.len > SENML_MAX_DATA_LEN) {
				ret = -EMSGSIZE;
			}
			if (ret == 0) {
				record->value_type = SENML_VALUE_DATA;
				record->has_value = true;
				value_count++;
			}
			break;
		default:
			return -EINVAL;
		}
		if (ret < 0 || value_count > 1U) {
			return ret < 0 ? ret : -EINVAL;
		}
	}
	return 0;
}

int senml_decode_cbor(const uint8_t *buf, size_t buflen,
		      struct senml_decoded_pack *pack)
{
	struct cbor_cursor cursor = { .buf = buf, .len = buflen, .pos = 0U };
	uint8_t major;
	uint8_t ai;
	uint64_t record_count;
	int ret;

	if (pack == NULL) {
		return -EINVAL;
	}
	memset(pack, 0, sizeof(*pack));
	if (buf == NULL || buflen == 0U) {
		return -EINVAL;
	}
	ret = cbor_read_head(&cursor, &major, &ai, &record_count);
	(void)ai;
	if (ret < 0 || major != 4U || record_count == 0U) {
		return -EINVAL;
	}
	if (record_count > SENML_MAX_RECORDS) {
		return -ENOMEM;
	}
	for (size_t i = 0; i < (size_t)record_count; i++) {
		ret = decode_record(&cursor, &pack->records[i]);
		if (ret < 0) {
			memset(pack, 0, sizeof(*pack));
			return ret;
		}
	}
	if (cursor.pos != cursor.len) {
		memset(pack, 0, sizeof(*pack));
		return -EINVAL;
	}
	pack->record_count = (size_t)record_count;
	return 0;
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

int senml_encode_location_full(const char *base_name, uint64_t base_time,
			       float lat, float lon, float alt,
			       float speed, float heading,
			       float hacc, float vacc,
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

	if (!isnan(speed)) {
		ret = senml_add_float(&pack, SENML_LOCATION_SPEED, SENML_LOCATION_UNIT_MS, speed);
		if (ret < 0) {
			return ret;
		}
	}

	if (!isnan(heading)) {
		ret = senml_add_float(&pack, SENML_LOCATION_HEADING, SENML_LOCATION_UNIT_DEG, heading);
		if (ret < 0) {
			return ret;
		}
	}

	if (!isnan(hacc)) {
		ret = senml_add_float(&pack, SENML_LOCATION_HACC, SENML_LOCATION_UNIT_M, hacc);
		if (ret < 0) {
			return ret;
		}
	}

	if (!isnan(vacc)) {
		ret = senml_add_float(&pack, SENML_LOCATION_VACC, SENML_LOCATION_UNIT_M, vacc);
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
	ret = senml_add_float(&pack, SENML_BATTERY_PCT, SENML_BATTERY_UNIT_PCT, (float)percent);
	if (ret < 0) {
		return ret;
	}

	ret = senml_add_float(&pack, SENML_BATTERY_MV, SENML_BATTERY_UNIT_MV, (float)mv);
	if (ret < 0) {
		return ret;
	}

	ret = senml_add_bool(&pack, SENML_BATTERY_CHARGING, charging);
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

	ret = senml_add_float(&pack, SENML_TELEMETRY_TEMP, SENML_TELEMETRY_UNIT_CEL, temp_c);
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

	ret = senml_add_float(&pack, SENML_DEADDROP_PENDING, NULL, (float)pending);
	if (ret < 0) {
		return ret;
	}

	return senml_encode_cbor(&pack, buf, buflen);
}
