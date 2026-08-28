/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "schc_internal.h"

#include <stdio.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { \
	printf("FAIL line %d: %s\n", __LINE__, #c); return 1; \
} } while (0)

enum {
	RULE5_FIXED_COMPRESSED = 23,
	RULE5_FIXED_RAW = IPV6_HDR_LEN + UDP_HDR_LEN + SCHC_COAP_FIXED_LEN,
	RULE5_MAX_TAIL = SCHC_FRAGMENT_MAX_PACKET_SIZE - RULE5_FIXED_COMPRESSED,
	RULE5_MAX_RAW = RULE5_FIXED_RAW + RULE5_MAX_TAIL,
};

static const uint8_t canonical_compressed[] = {
	5,0x40,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,2,
	0x33,0x08,0x04,0x48,0xD0,0,1,0x92,9,0,0xFF,0xDE,0xAD,0xBE,0xEF
};
static const uint8_t canonical_packet[] = {
	0x60,0,0,0,0,0x16,0x11,0x40,
	0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
	0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,2,
	0x16,0x33,0x16,0x33,0,0x16,0x51,0x7B,
	0x42,1,0x12,0x34,0,1,0x92,9,0,0xFF,0xDE,0xAD,0xBE,0xEF
};

static int unchanged(const uint8_t *data, size_t len, uint8_t *out,
		     size_t out_len, int expected)
{
	memset(out, 0xA5, out_len);
	CHECK(lichen_schc_decompress(data, len, out, out_len) == expected);
	for (size_t i = 0; i < out_len; i++) CHECK(out[i] == 0xA5);
	return 0;
}

static int test_canonical_shared_vector(void)
{
	uint8_t out[sizeof(canonical_packet)];
	int length = lichen_schc_decompress(canonical_compressed,
					    sizeof(canonical_compressed),
					    out, sizeof(out));
	CHECK(length == (int)sizeof(canonical_packet));
	CHECK(memcmp(out, canonical_packet, sizeof(canonical_packet)) == 0);
	return 0;
}

static int test_independent_fields_and_round_trip(void)
{
	static const uint8_t residue[] = {
		5,1,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		1,2,3,4,5,6,7,8,
		0x0F,0xC9,0x16,0xFB,0xBC,
		0xAA,0x55,0x92,9,1,0xFF,1,2,3
	};
	uint8_t packet[128];
	uint8_t recompressed[128];
	int length = lichen_schc_decompress(residue, sizeof(residue),
					    packet, sizeof(packet));
	CHECK(length == 61);
	CHECK(packet[7] == 1);
	CHECK(memcmp(&packet[8],
		     "\xFE\x80\0\0\0\0\0\0\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
		     16) == 0);
	CHECK(memcmp(&packet[24],
		     "\xFE\x80\0\0\0\0\0\0\x01\x02\x03\x04\x05\x06\x07\x08",
		     16) == 0);
	CHECK(read_be16(&packet[40]) == 5680);
	CHECK(read_be16(&packet[42]) == 5695);
	CHECK(read_be16(&packet[46]) != 0);
	CHECK(memcmp(&packet[48], "\x72\x45\xBE\xEF\xAA\x55\x92\x09\x01\xFF\x01\x02\x03",
		     13) == 0);
	int compressed = lichen_schc_compress(packet, (size_t)length,
					      recompressed, sizeof(recompressed));
	CHECK(compressed == (int)sizeof(residue));
	CHECK(memcmp(recompressed, residue, sizeof(residue)) == 0);
	return 0;
}

static int test_truncation_and_padding_are_atomic(void)
{
	uint8_t out[128];
	for (size_t len = 1; len < RULE5_FIXED_COMPRESSED; len++) {
		CHECK(unchanged(canonical_compressed, len, out, sizeof(out),
				SCHC_ERR_TOO_SHORT) == 0);
	}

	uint8_t malformed[sizeof(canonical_compressed)];
	for (uint8_t bit = 1; bit <= 2; bit++) {
		memcpy(malformed, canonical_compressed, sizeof(malformed));
		malformed[RULE5_FIXED_COMPRESSED - 1] |= bit;
		CHECK(unchanged(malformed, sizeof(malformed), out, sizeof(out),
				SCHC_ERR_INVALID_ARGUMENT) == 0);
	}
	return 0;
}

static int expect_bad_tail(const uint8_t *tail, size_t tail_len)
{
	uint8_t encoded[64];
	uint8_t out[128];
	CHECK(RULE5_FIXED_COMPRESSED + tail_len <= sizeof(encoded));
	memcpy(encoded, canonical_compressed, RULE5_FIXED_COMPRESSED);
	if (tail_len > 0) {
		memcpy(&encoded[RULE5_FIXED_COMPRESSED], tail, tail_len);
	}
	return unchanged(encoded, RULE5_FIXED_COMPRESSED + tail_len,
			 out, sizeof(out), SCHC_ERR_INVALID_ARGUMENT);
}

static int test_malformed_profiles_are_atomic(void)
{
	static const uint8_t no_oscore[] = { 0, 1 };
	static const uint8_t reserved_length[] = { 0, 1, 0x9F };
	static const uint8_t truncated_length[] = { 0, 1, 0x9D };
	static const uint8_t missing_piv[] = { 0, 1, 0x91, 1 };
	static const uint8_t duplicate[] = { 0, 1, 0x90, 0, 0x90 };
	static const uint8_t empty_payload[] = { 0, 1, 0x90, 0xFF };
	uint8_t out[128];
	uint8_t reserved_tkl[RULE5_FIXED_COMPRESSED + 9] = { 0 };

	CHECK(expect_bad_tail(NULL, 0) == 0);
	CHECK(expect_bad_tail(no_oscore, sizeof(no_oscore)) == 0);
	CHECK(expect_bad_tail(reserved_length, sizeof(reserved_length)) == 0);
	CHECK(expect_bad_tail(truncated_length, sizeof(truncated_length)) == 0);
	CHECK(expect_bad_tail(missing_piv, sizeof(missing_piv)) == 0);
	CHECK(expect_bad_tail(duplicate, sizeof(duplicate)) == 0);
	CHECK(expect_bad_tail(empty_payload, sizeof(empty_payload)) == 0);

	memcpy(reserved_tkl, canonical_compressed, RULE5_FIXED_COMPRESSED);
	reserved_tkl[19] = (uint8_t)((reserved_tkl[19] & 0xC3u) | (9u << 2));
	CHECK(unchanged(reserved_tkl, sizeof(reserved_tkl), out, sizeof(out),
			SCHC_ERR_INVALID_ARGUMENT) == 0);
	return 0;
}

static int test_output_and_profile_bounds_are_atomic(void)
{
	uint8_t small[sizeof(canonical_packet) - 1];
	CHECK(unchanged(canonical_compressed, sizeof(canonical_compressed),
			small, sizeof(small), SCHC_ERR_BUFFER_TOO_SMALL) == 0);

	static uint8_t encoded[SCHC_FRAGMENT_MAX_PACKET_SIZE + 1];
	static uint8_t output[RULE5_MAX_RAW];
	memcpy(encoded, canonical_compressed, RULE5_FIXED_COMPRESSED);
	encoded[RULE5_FIXED_COMPRESSED] = 0;
	encoded[RULE5_FIXED_COMPRESSED + 1] = 1;
	encoded[RULE5_FIXED_COMPRESSED + 2] = 0x90;
	encoded[RULE5_FIXED_COMPRESSED + 3] = 0xFF;
	CHECK(lichen_schc_decompress(encoded, SCHC_FRAGMENT_MAX_PACKET_SIZE,
				      output, sizeof(output)) == RULE5_MAX_RAW);

	memset(output, 0xA5, sizeof(output));
	CHECK(lichen_schc_decompress(encoded, SCHC_FRAGMENT_MAX_PACKET_SIZE + 1,
				      output, sizeof(output)) ==
	      SCHC_ERR_BUFFER_TOO_SMALL);
	for (size_t i = 0; i < sizeof(output); i++) CHECK(output[i] == 0xA5);
	return 0;
}

int main(void)
{
	CHECK(test_canonical_shared_vector() == 0);
	CHECK(test_independent_fields_and_round_trip() == 0);
	CHECK(test_truncation_and_padding_are_atomic() == 0);
	CHECK(test_malformed_profiles_are_atomic() == 0);
	CHECK(test_output_and_profile_bounds_are_atomic() == 0);
	puts("SCHC Rule 5 decompression: PASS");
	return 0;
}
