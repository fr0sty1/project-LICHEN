/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "schc_internal.h"

#include <stdio.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { \
	printf("FAIL line %d: %s\n", __LINE__, #c); return 1; \
} } while (0)

static const uint8_t canonical_compressed[] = {
	1,0x40,0x7D,0xD5,0xCF,0xC6,0x79,0xAB,0x63,0x7D,0xD5,0xCF,
	0xC6,0x79,0xAB,0x63,0x42,0xF7,0x7A,0x7B,0xAA,0x12,0x26,0xB5,
	0xF5,0x7A,0x7B,0xAA,0x12,0x26,0xB5,0x0C,0x33,0,0x04,0x48,0xD0,
	0xFF,'s','t','a','t','u','s'
};
static const uint8_t canonical_packet[] = {
	0x60,0,0,0,0,0x13,0x11,0x40,
	0x02,0x7D,0xD5,0xCF,0xC6,0x79,0xAB,0x63,0x7D,0xD5,0xCF,0xC6,0x79,0xAB,0x63,0x42,
	0x02,0xF7,0x7A,0x7B,0xAA,0x12,0x26,0xB5,0xF5,0x7A,0x7B,0xAA,0x12,0x26,0xB5,0x0C,
	0x16,0x33,0x16,0x33,0,0x13,0x2A,0x9B,
	0x40,1,0x12,0x34,0xFF,'s','t','a','t','u','s'
};

static int test_canonical_vector(void)
{
	uint8_t out[128], recompressed[128];
	int n = lichen_schc_decompress(canonical_compressed,
				      sizeof(canonical_compressed), out, sizeof(out));

	CHECK(n == (int)sizeof(canonical_packet));
	CHECK(memcmp(out, canonical_packet, sizeof(canonical_packet)) == 0);
	int m = lichen_schc_compress(out, (size_t)n, recompressed,
				    sizeof(recompressed));
	CHECK(m == (int)sizeof(canonical_compressed));
	CHECK(memcmp(recompressed, canonical_compressed,
		     sizeof(canonical_compressed)) == 0);
	return 0;
}

static int test_independent_fields_and_tail(void)
{
	static const uint8_t fixed[] = {
		1,1,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
		0x0F,0xC9,0x16,0xFB,0xBC
	};
	static const uint8_t tail[] = { 0xAA,0x55,0xB1,'x',0x11,'y',0xFF,'p' };
	uint8_t compressed[sizeof(fixed) + sizeof(tail)];
	uint8_t out[128], recompressed[128];
	memcpy(compressed, fixed, sizeof(fixed));
	memcpy(&compressed[sizeof(fixed)], tail, sizeof(tail));

	int n = lichen_schc_decompress(compressed, sizeof(compressed), out,
				      sizeof(out));
	CHECK(n == 52 + (int)sizeof(tail));
	CHECK(out[7] == 1 && out[8] == 2 && out[9] == 0xFF && out[23] == 0xFF);
	CHECK(out[24] == 2 && out[39] == 1);
	CHECK(read_be16(&out[40]) == 5680 && read_be16(&out[42]) == 5695);
	CHECK(out[48] == 0x72 && out[49] == 0x45 && read_be16(&out[50]) == 0xBEEF);
	CHECK(memcmp(&out[52], tail, sizeof(tail)) == 0);
	CHECK(read_be16(&out[44]) == (uint16_t)(12 + sizeof(tail)));
	uint16_t expected_checksum;
	CHECK(udp_checksum(&out[8], &out[24], 5680, 5695, &out[48],
			   4 + sizeof(tail), &expected_checksum) == 0);
	CHECK(expected_checksum != 0 && read_be16(&out[46]) == expected_checksum);

	int m = lichen_schc_compress(out, (size_t)n, recompressed,
				    sizeof(recompressed));
	CHECK(m == (int)sizeof(compressed));
	CHECK(memcmp(recompressed, compressed, sizeof(compressed)) == 0);
	return 0;
}

static int test_malformed_and_bounds_are_atomic(void)
{
	uint8_t out[128];
	for (size_t len = 0; len < 37; len++) {
		memset(out, 0xA5, sizeof(out));
		CHECK(lichen_schc_decompress(canonical_compressed, len,
					    out, sizeof(out)) < 0);
		CHECK(out[0] == 0xA5);
	}
	for (uint8_t padding = 1; padding <= 2; padding++) {
		uint8_t invalid[sizeof(canonical_compressed)];
		memcpy(invalid, canonical_compressed, sizeof(invalid));
		invalid[36] |= padding;
		memset(out, 0xA5, sizeof(out));
		CHECK(lichen_schc_decompress(invalid, sizeof(invalid),
					    out, sizeof(out)) < 0);
		CHECK(out[0] == 0xA5);
	}

	uint8_t invalid_tkl[37];
	memcpy(invalid_tkl, canonical_compressed, sizeof(invalid_tkl));
	/* TKL occupies residue bits 258..261: set it to reserved value 9. */
	invalid_tkl[33] = (uint8_t)((invalid_tkl[33] & 0xC3u) | (9u << 2));
	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_decompress(invalid_tkl, sizeof(invalid_tkl),
				    out, sizeof(out)) < 0);
	CHECK(out[0] == 0xA5);
	memcpy(invalid_tkl, canonical_compressed, sizeof(invalid_tkl));
	invalid_tkl[33] = (uint8_t)((invalid_tkl[33] & 0xC3u) | (1u << 2));
	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_decompress(invalid_tkl, sizeof(invalid_tkl),
				    out, sizeof(out)) < 0);
	CHECK(out[0] == 0xA5);

	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_decompress(canonical_compressed,
				    sizeof(canonical_compressed), out,
				    sizeof(canonical_packet) - 1) < 0);
	CHECK(out[0] == 0xA5);
	return 0;
}

static int test_profile_limit(void)
{
	enum { RAW_EXACT = SCHC_FRAGMENT_MAX_PACKET_SIZE + 15 };
	static uint8_t compressed[SCHC_FRAGMENT_MAX_PACKET_SIZE + 1];
	static uint8_t out[RAW_EXACT];

	memcpy(compressed, canonical_compressed, 37);
	memset(&compressed[37], 0, SCHC_FRAGMENT_MAX_PACKET_SIZE - 37);
	int n = lichen_schc_decompress(compressed, SCHC_FRAGMENT_MAX_PACKET_SIZE,
				      out, sizeof(out));
	CHECK(n == RAW_EXACT);
	CHECK(read_be16(&out[4]) == RAW_EXACT - IPV6_HDR_LEN);
	compressed[SCHC_FRAGMENT_MAX_PACKET_SIZE] = 0;
	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_decompress(compressed,
				    SCHC_FRAGMENT_MAX_PACKET_SIZE + 1,
				    out, sizeof(out)) < 0);
	CHECK(out[0] == 0xA5);
	return 0;
}

int main(void)
{
	CHECK(test_canonical_vector() == 0);
	CHECK(test_independent_fields_and_tail() == 0);
	CHECK(test_malformed_and_bounds_are_atomic() == 0);
	CHECK(test_profile_limit() == 0);
	puts("SCHC Rule 1 decompression: PASS");
	return 0;
}
