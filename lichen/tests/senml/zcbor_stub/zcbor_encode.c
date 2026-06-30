/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file zcbor_encode.c
 * @brief Minimal zcbor stub for standalone SenML tests
 */

#include "zcbor_encode.h"
#include <string.h>

/* Check if n bytes fit and advance payload */
static bool emit(zcbor_state_t *state, const uint8_t *data, size_t n)
{
	if (state->payload + n > state->payload_end) {
		return false;
	}
	memcpy(state->payload, data, n);
	state->payload += n;
	return true;
}

static bool emit_byte(zcbor_state_t *state, uint8_t b)
{
	return emit(state, &b, 1);
}

/* Encode the CBOR integer payload for major type 0 or 1. */
static bool encode_uint(zcbor_state_t *state, uint8_t major, uint64_t uval)
{
	if (uval <= 23) {
		return emit_byte(state, major | (uint8_t)uval);
	} else if (uval <= 0xff) {
		uint8_t buf[2] = { major | 24, (uint8_t)uval };
		return emit(state, buf, 2);
	} else if (uval <= 0xffff) {
		uint8_t buf[3] = { major | 25, (uint8_t)(uval >> 8), (uint8_t)uval };
		return emit(state, buf, 3);
	} else if (uval <= 0xffffffff) {
		uint8_t buf[5] = {
			major | 26,
			(uint8_t)(uval >> 24), (uint8_t)(uval >> 16),
			(uint8_t)(uval >> 8), (uint8_t)uval
		};
		return emit(state, buf, 5);
	} else {
		uint8_t buf[9] = {
			major | 27,
			(uint8_t)(uval >> 56), (uint8_t)(uval >> 48),
			(uint8_t)(uval >> 40), (uint8_t)(uval >> 32),
			(uint8_t)(uval >> 24), (uint8_t)(uval >> 16),
			(uint8_t)(uval >> 8), (uint8_t)uval
		};
		return emit(state, buf, 9);
	}
}

/* Encode CBOR unsigned integer (major type 0) or negative (major type 1) */
static bool encode_int(zcbor_state_t *state, int64_t value)
{
	if (value >= 0) {
		return encode_uint(state, 0x00, (uint64_t)value);
	}

	return encode_uint(state, 0x20, (uint64_t)(-(value + 1)));
}

bool zcbor_list_start_encode(zcbor_state_t *state, size_t max_num)
{
	/* CBOR array: major type 4 */
	if (max_num <= 23) {
		return emit_byte(state, 0x80 | (uint8_t)max_num);
	} else if (max_num <= 0xff) {
		uint8_t buf[2] = { 0x98, (uint8_t)max_num };
		return emit(state, buf, 2);
	}
	return false; /* Larger arrays not needed for SenML tests */
}

bool zcbor_list_end_encode(zcbor_state_t *state, size_t max_num)
{
	(void)state;
	(void)max_num;
	return true; /* Definite-length lists don't need end marker */
}

bool zcbor_map_start_encode(zcbor_state_t *state, size_t max_num)
{
	/* CBOR map: major type 5 */
	if (max_num <= 23) {
		return emit_byte(state, 0xa0 | (uint8_t)max_num);
	} else if (max_num <= 0xff) {
		uint8_t buf[2] = { 0xb8, (uint8_t)max_num };
		return emit(state, buf, 2);
	}
	return false;
}

bool zcbor_map_end_encode(zcbor_state_t *state, size_t max_num)
{
	(void)state;
	(void)max_num;
	return true;
}

bool zcbor_int32_put(zcbor_state_t *state, int32_t value)
{
	return encode_int(state, value);
}

bool zcbor_uint64_put(zcbor_state_t *state, uint64_t value)
{
	return encode_uint(state, 0x00, value);
}

bool zcbor_tstr_put_term(zcbor_state_t *state, const char *str, size_t maxlen)
{
	(void)maxlen;
	size_t len = strlen(str);

	/* CBOR text string: major type 3 */
	if (len <= 23) {
		if (!emit_byte(state, 0x60 | (uint8_t)len)) return false;
	} else if (len <= 0xff) {
		uint8_t buf[2] = { 0x78, (uint8_t)len };
		if (!emit(state, buf, 2)) return false;
	} else {
		return false; /* Longer strings not needed */
	}
	return emit(state, (const uint8_t *)str, len);
}

bool zcbor_float32_put(zcbor_state_t *state, float value)
{
	/* CBOR float32: major type 7, additional info 26 (0xfa) */
	union { float f; uint32_t u; } conv;
	conv.f = value;
	uint8_t buf[5] = {
		0xfa,
		(uint8_t)(conv.u >> 24), (uint8_t)(conv.u >> 16),
		(uint8_t)(conv.u >> 8), (uint8_t)conv.u
	};
	return emit(state, buf, 5);
}

bool zcbor_bool_put(zcbor_state_t *state, bool value)
{
	/* CBOR simple values: false=0xf4, true=0xf5 */
	return emit_byte(state, value ? 0xf5 : 0xf4);
}
