/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/compact_cot_pli.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct pli_vector {
	const char *name;
	struct lichen_compact_cot_pli value;
	uint8_t wire[LICHEN_COMPACT_COT_PLI_SIZE];
};

/* Exact positive PLI cases from test/vectors/compact_cot.json. */
static const struct pli_vector vectors[] = {
	{
		.name = "friendly_origin",
		.value = {0x02, 0, 0, 0, 0, 0, 1, 1},
		.wire = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01},
	},
	{
		.name = "hostile_negative",
		.value = {0x03, -45500000, -122500000, 1000, 27000, 500, 2, 1},
		.wire = {0x03, 0xfd, 0x49, 0xb9, 0xa0, 0xf8, 0xb2, 0xcc, 0x60,
			 0x03, 0xe8, 0x69, 0x78, 0x01, 0xf4, 0x02, 0x01},
	},
	{
		.name = "neutral_london",
		.value = {0x04, 51507400, -127800, 110, 4500, 150, 3, 1},
		.wire = {0x04, 0x03, 0x11, 0xf0, 0xc8, 0xff, 0xfe, 0x0c, 0xc8,
			 0x00, 0x6e, 0x11, 0x94, 0x00, 0x96, 0x03, 0x01},
	},
	{
		.name = "unknown_tokyo",
		.value = {0x05, 35676200, 139650300, 400, 18000, 0, 9, 1},
		.wire = {0x05, 0x02, 0x20, 0x60, 0x28, 0x08, 0x52, 0xe4, 0xfc,
			 0x01, 0x90, 0x46, 0x50, 0x00, 0x00, 0x09, 0x01},
	},
	{
		.name = "maximum_positive",
		.value = {0x02, 90000000, 180000000, 32767, 35999, 65535, 1, 1},
		.wire = {0x02, 0x05, 0x5d, 0x4a, 0x80, 0x0a, 0xba, 0x95, 0x00,
			 0x7f, 0xff, 0x8c, 0x9f, 0xff, 0xff, 0x01, 0x01},
	},
	{
		.name = "maximum_negative",
		.value = {0x02, -90000000, -180000000, -32768, 0, 0, 1, 1},
		.wire = {0x02, 0xfa, 0xa2, 0xb5, 0x80, 0xf5, 0x45, 0x6b, 0x00,
			 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01},
	},
	{
		.name = "zero_altitude",
		.value = {0x02, 51507400, -127800, 0, 0, 0, 1, 1},
		.wire = {0x02, 0x03, 0x11, 0xf0, 0xc8, 0xff, 0xfe, 0x0c, 0xc8,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01},
	},
	{
		.name = "maximum_speed",
		.value = {0x02, 0, 0, 0, 0, 65535, 1, 1},
		.wire = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x01},
	},
};

static bool pli_equal(const struct lichen_compact_cot_pli *left,
		      const struct lichen_compact_cot_pli *right)
{
	return left->subtype == right->subtype &&
	       left->latitude_microdegrees == right->latitude_microdegrees &&
	       left->longitude_microdegrees == right->longitude_microdegrees &&
	       left->altitude_decimeters == right->altitude_decimeters &&
	       left->course_centidegrees == right->course_centidegrees &&
	       left->speed_cm_s == right->speed_cm_s && left->team == right->team &&
	       left->role == right->role;
}

static bool bytes_are(const uint8_t *bytes, size_t size, uint8_t value)
{
	for (size_t i = 0; i < size; i++) {
		if (bytes[i] != value) {
			return false;
		}
	}
	return true;
}

static int test_vectors(void)
{
	for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		uint8_t encoded[LICHEN_COMPACT_COT_PLI_SIZE + 1U];
		struct lichen_compact_cot_pli decoded;

		memset(encoded, 0xa5, sizeof(encoded));
		if (lichen_compact_cot_pli_encode(&vectors[i].value, encoded,
						 sizeof(encoded)) != 0 ||
		    memcmp(encoded, vectors[i].wire, LICHEN_COMPACT_COT_PLI_SIZE) != 0 ||
		    encoded[LICHEN_COMPACT_COT_PLI_SIZE] != 0xa5) {
			fprintf(stderr, "%s: encode failed\n", vectors[i].name);
			return 1;
		}

		memset(&decoded, 0xa5, sizeof(decoded));
		if (lichen_compact_cot_pli_decode(vectors[i].wire,
						 LICHEN_COMPACT_COT_PLI_SIZE,
						 &decoded) != 0 ||
		    !pli_equal(&decoded, &vectors[i].value)) {
			fprintf(stderr, "%s: decode failed\n", vectors[i].name);
			return 1;
		}
	}

	return 0;
}

static int test_encode_rejections(void)
{
	static const struct lichen_compact_cot_pli invalid[] = {
		{0x02, 90000001, 0, 0, 0, 0, 1, 1},
		{0x02, -90000001, 0, 0, 0, 0, 1, 1},
		{0x02, 0, 180000001, 0, 0, 0, 1, 1},
		{0x02, 0, -180000001, 0, 0, 0, 1, 1},
		{0x02, 0, 0, 0, 36000, 0, 1, 1},
		{0x01, 0, 0, 0, 0, 0, 1, 1},
		{0x06, 0, 0, 0, 0, 0, 1, 1},
		{0x10, 0, 0, 0, 0, 0, 1, 1},
		{0xff, 0, 0, 0, 0, 0, 1, 1},
	};
	uint8_t output[LICHEN_COMPACT_COT_PLI_SIZE + 1U];

	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		memset(output, 0xa5, sizeof(output));
		if (lichen_compact_cot_pli_encode(&invalid[i], output, sizeof(output)) !=
			    -EINVAL ||
		    !bytes_are(output, sizeof(output), 0xa5)) {
			fprintf(stderr, "invalid encode %zu was not atomic\n", i);
			return 1;
		}
	}

	for (size_t size = 0; size < LICHEN_COMPACT_COT_PLI_SIZE; size++) {
		memset(output, 0xa5, sizeof(output));
		if (lichen_compact_cot_pli_encode(&vectors[0].value, output, size) !=
			    -EMSGSIZE ||
		    !bytes_are(output, sizeof(output), 0xa5)) {
			fprintf(stderr, "short encode size %zu was not atomic\n", size);
			return 1;
		}
	}

	memset(output, 0xa5, sizeof(output));
	if (lichen_compact_cot_pli_encode(NULL, output, sizeof(output)) != -EINVAL ||
	    !bytes_are(output, sizeof(output), 0xa5) ||
	    lichen_compact_cot_pli_encode(&vectors[0].value, NULL,
					  sizeof(output)) != -EINVAL) {
		fprintf(stderr, "NULL encode behavior failed\n");
		return 1;
	}

	return 0;
}

static int expect_decode_error(const uint8_t *wire, size_t size, int expected)
{
	struct lichen_compact_cot_pli output;
	struct lichen_compact_cot_pli sentinel;

	memset(&output, 0xa5, sizeof(output));
	sentinel = output;
	if (lichen_compact_cot_pli_decode(wire, size, &output) != expected ||
	    memcmp(&output, &sentinel, sizeof(output)) != 0) {
		return 1;
	}
	return 0;
}

static int test_decode_rejections(void)
{
	static const uint8_t invalid_fields[][LICHEN_COMPACT_COT_PLI_SIZE] = {
		{0x02, 0x05, 0x5d, 0x4a, 0x81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1},
		{0x02, 0xfa, 0xa2, 0xb5, 0x7f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1},
		{0x02, 0, 0, 0, 0, 0x0a, 0xba, 0x95, 0x01, 0, 0, 0, 0, 0, 0, 1, 1},
		{0x02, 0, 0, 0, 0, 0xf5, 0x45, 0x6a, 0xff, 0, 0, 0, 0, 0, 0, 1, 1},
		{0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x8c, 0xa0, 0, 0, 1, 1},
		{0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	};
	uint8_t trailing[LICHEN_COMPACT_COT_PLI_SIZE + 1U];

	for (size_t size = 0; size < LICHEN_COMPACT_COT_PLI_SIZE; size++) {
		if (expect_decode_error(vectors[0].wire, size, -EMSGSIZE) != 0) {
			fprintf(stderr, "truncated decode size %zu was not atomic\n", size);
			return 1;
		}
	}

	memcpy(trailing, vectors[0].wire, LICHEN_COMPACT_COT_PLI_SIZE);
	trailing[LICHEN_COMPACT_COT_PLI_SIZE] = 0;
	if (expect_decode_error(trailing, sizeof(trailing), -EMSGSIZE) != 0) {
		fprintf(stderr, "trailing decode was not rejected atomically\n");
		return 1;
	}

	for (size_t i = 0; i < sizeof(invalid_fields) / sizeof(invalid_fields[0]); i++) {
		if (expect_decode_error(invalid_fields[i], sizeof(invalid_fields[i]),
					-EINVAL) != 0) {
			fprintf(stderr, "invalid decode %zu was not atomic\n", i);
			return 1;
		}
	}

	if (expect_decode_error(NULL, LICHEN_COMPACT_COT_PLI_SIZE, -EINVAL) != 0 ||
	    lichen_compact_cot_pli_decode(NULL, LICHEN_COMPACT_COT_PLI_SIZE,
					  NULL) != -EINVAL ||
	    lichen_compact_cot_pli_decode(vectors[0].wire,
					  LICHEN_COMPACT_COT_PLI_SIZE, NULL) != -EINVAL) {
		fprintf(stderr, "NULL decode behavior failed\n");
		return 1;
	}

	return 0;
}

static int test_overlap_and_opaque_enums(void)
{
	union overlap {
		struct lichen_compact_cot_pli value;
		uint8_t wire[sizeof(struct lichen_compact_cot_pli)];
	} overlap;
	struct lichen_compact_cot_pli edge = {
		LICHEN_COMPACT_COT_PLI_UNKNOWN, 0, 0, 0, 0, 0, UINT8_MAX, UINT8_MAX,
	};

	_Static_assert(sizeof(overlap.wire) >= LICHEN_COMPACT_COT_PLI_SIZE,
		       "overlap storage must hold one PLI datagram");

	overlap.value = vectors[1].value;
	if (lichen_compact_cot_pli_encode(&overlap.value, overlap.wire,
					  sizeof(overlap.wire)) != 0 ||
	    memcmp(overlap.wire, vectors[1].wire, LICHEN_COMPACT_COT_PLI_SIZE) != 0) {
		fprintf(stderr, "overlapping encode failed\n");
		return 1;
	}

	memcpy(overlap.wire, vectors[2].wire, LICHEN_COMPACT_COT_PLI_SIZE);
	if (lichen_compact_cot_pli_decode(overlap.wire,
					  LICHEN_COMPACT_COT_PLI_SIZE,
					  &overlap.value) != 0 ||
	    !pli_equal(&overlap.value, &vectors[2].value)) {
		fprintf(stderr, "overlapping decode failed\n");
		return 1;
	}

	if (lichen_compact_cot_pli_encode(&edge, overlap.wire,
					  sizeof(overlap.wire)) != 0 ||
	    lichen_compact_cot_pli_decode(overlap.wire,
					  LICHEN_COMPACT_COT_PLI_SIZE,
					  &overlap.value) != 0 ||
	    !pli_equal(&overlap.value, &edge)) {
		fprintf(stderr, "opaque enumeration edge failed\n");
		return 1;
	}

	return 0;
}

int main(void)
{
	if (test_vectors() != 0 || test_encode_rejections() != 0 ||
	    test_decode_rejections() != 0 || test_overlap_and_opaque_enums() != 0) {
		return 1;
	}

	return 0;
}
