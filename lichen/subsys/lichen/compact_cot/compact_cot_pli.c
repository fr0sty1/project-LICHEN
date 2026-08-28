/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/compact_cot_pli.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>

static bool subtype_is_pli(uint8_t subtype)
{
	return subtype >= LICHEN_COMPACT_COT_PLI_FRIENDLY &&
	       subtype <= LICHEN_COMPACT_COT_PLI_UNKNOWN;
}

static int validate_pli(const struct lichen_compact_cot_pli *pli)
{
	if (!subtype_is_pli(pli->subtype) ||
	    pli->latitude_microdegrees < LICHEN_COMPACT_COT_LAT_MIN ||
	    pli->latitude_microdegrees > LICHEN_COMPACT_COT_LAT_MAX ||
	    pli->longitude_microdegrees < LICHEN_COMPACT_COT_LON_MIN ||
	    pli->longitude_microdegrees > LICHEN_COMPACT_COT_LON_MAX ||
	    pli->course_centidegrees > LICHEN_COMPACT_COT_COURSE_MAX) {
		return -EINVAL;
	}

	return 0;
}

static void write_u16_be(uint8_t output[2], uint16_t value)
{
	output[0] = (uint8_t)(value >> 8);
	output[1] = (uint8_t)value;
}

static void write_u32_be(uint8_t output[4], uint32_t value)
{
	output[0] = (uint8_t)(value >> 24);
	output[1] = (uint8_t)(value >> 16);
	output[2] = (uint8_t)(value >> 8);
	output[3] = (uint8_t)value;
}

static uint16_t read_u16_be(const uint8_t input[2])
{
	return (uint16_t)(((uint16_t)input[0] << 8) | (uint16_t)input[1]);
}

static uint32_t read_u32_be(const uint8_t input[4])
{
	return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
	       ((uint32_t)input[2] << 8) | (uint32_t)input[3];
}

static int16_t decode_i16(uint16_t value)
{
	if (value <= INT16_MAX) {
		return (int16_t)value;
	}

	return (int16_t)(-1 - (int16_t)(UINT16_MAX - value));
}

static int32_t decode_i32(uint32_t value)
{
	if (value <= INT32_MAX) {
		return (int32_t)value;
	}

	return -1 - (int32_t)(UINT32_MAX - value);
}

int lichen_compact_cot_pli_encode(const struct lichen_compact_cot_pli *pli,
				  uint8_t *output, size_t output_size)
{
	uint8_t encoded[LICHEN_COMPACT_COT_PLI_SIZE];
	int ret;

	if (pli == NULL || output == NULL) {
		return -EINVAL;
	}
	if (output_size < sizeof(encoded)) {
		return -EMSGSIZE;
	}

	ret = validate_pli(pli);
	if (ret < 0) {
		return ret;
	}

	encoded[0] = pli->subtype;
	write_u32_be(&encoded[1], (uint32_t)pli->latitude_microdegrees);
	write_u32_be(&encoded[5], (uint32_t)pli->longitude_microdegrees);
	write_u16_be(&encoded[9], (uint16_t)pli->altitude_decimeters);
	write_u16_be(&encoded[11], pli->course_centidegrees);
	write_u16_be(&encoded[13], pli->speed_cm_s);
	encoded[15] = pli->team;
	encoded[16] = pli->role;

	memcpy(output, encoded, sizeof(encoded));
	return 0;
}

int lichen_compact_cot_pli_decode(const uint8_t *input, size_t input_size,
				  struct lichen_compact_cot_pli *pli)
{
	struct lichen_compact_cot_pli decoded;
	int ret;

	if (input == NULL || pli == NULL) {
		return -EINVAL;
	}
	if (input_size != LICHEN_COMPACT_COT_PLI_SIZE) {
		return -EMSGSIZE;
	}

	decoded.subtype = input[0];
	decoded.latitude_microdegrees = decode_i32(read_u32_be(&input[1]));
	decoded.longitude_microdegrees = decode_i32(read_u32_be(&input[5]));
	decoded.altitude_decimeters = decode_i16(read_u16_be(&input[9]));
	decoded.course_centidegrees = read_u16_be(&input[11]);
	decoded.speed_cm_s = read_u16_be(&input[13]);
	decoded.team = input[15];
	decoded.role = input[16];

	ret = validate_pli(&decoded);
	if (ret < 0) {
		return ret;
	}

	*pli = decoded;
	return 0;
}
