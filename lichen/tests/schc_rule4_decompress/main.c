/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "schc_internal.h"

#include <stdio.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { \
	printf("FAIL line %d: %s\n", __LINE__, #c); return 1; \
} } while (0)

static const uint8_t canonical_compressed[] = {
	4,0x40,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,2,
	0,0x40,5,0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1
};
static const uint8_t canonical_packet[] = {
	0x60,0,0,0,0,0x18,0x3A,0x40,
	0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
	0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,2,
	0x9B,0x02,0x68,0xDF,0,0x40,0,5,
	0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1
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
	static const uint8_t tail[] = { 0, 0xFF, 5, 0, 6, 1, 0xA5 };
	uint8_t compressed[sizeof(canonical_compressed) + sizeof(tail)];
	uint8_t out[128], recompressed[128];

	memcpy(compressed, canonical_compressed, sizeof(canonical_compressed));
	compressed[1] = 255;
	memset(&compressed[2], 0xFF, 8);       /* source IID */
	compressed[10] = 1;
	compressed[11] = 2;
	compressed[12] = 3;
	compressed[13] = 4;
	compressed[14] = 5;
	compressed[15] = 6;
	compressed[16] = 7;
	compressed[17] = 8;                    /* destination IID */
	compressed[18] = 255;                  /* instance */
	compressed[19] = 255;                  /* K/D/flags, D set */
	compressed[20] = 255;                  /* sequence */
	memset(&compressed[21], 0xFF, 16);     /* DODAGID */
	memcpy(&compressed[37], tail, sizeof(tail));

	int n = lichen_schc_decompress(compressed, sizeof(compressed), out,
				      sizeof(out));
	CHECK(n == 64 + (int)sizeof(tail));
	CHECK(out[7] == 255);
	CHECK(out[23] == 0xFF && out[32] == 1 && out[39] == 8);
	CHECK(out[44] == 255 && out[45] == 255 && out[46] == 0 && out[47] == 255);
	CHECK(memcmp(&out[48], &compressed[21], 16) == 0);
	CHECK(memcmp(&out[64], tail, sizeof(tail)) == 0);
	CHECK(icmpv6_checksum_valid(&out[8], &out[24], &out[40],
				    (uint16_t)(n - IPV6_HDR_LEN)));

	int m = lichen_schc_compress(out, (size_t)n, recompressed,
				    sizeof(recompressed));
	CHECK(m == (int)sizeof(compressed));
	CHECK(memcmp(recompressed, compressed, sizeof(compressed)) == 0);
	return 0;
}

static int test_malformed_is_atomic(void)
{
	uint8_t out[128];
	for (size_t len = 0; len < sizeof(canonical_compressed); len++) {
		memset(out, 0xA5, sizeof(out));
		CHECK(lichen_schc_decompress(canonical_compressed, len,
					    out, sizeof(out)) < 0);
		CHECK(out[0] == 0xA5);
	}

	uint8_t invalid[sizeof(canonical_compressed)];
	memcpy(invalid, canonical_compressed, sizeof(invalid));
	invalid[19] &= (uint8_t)~0x40u;
	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_decompress(invalid, sizeof(invalid), out, sizeof(out)) < 0);
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
	enum { RAW_EXACT = SCHC_FRAGMENT_MAX_PACKET_SIZE + 27 };
	static uint8_t compressed[SCHC_FRAGMENT_MAX_PACKET_SIZE + 1];
	static uint8_t out[RAW_EXACT];

	memcpy(compressed, canonical_compressed, sizeof(canonical_compressed));
	memset(&compressed[sizeof(canonical_compressed)], 0,
	       SCHC_FRAGMENT_MAX_PACKET_SIZE - sizeof(canonical_compressed));
	int n = lichen_schc_decompress(compressed, SCHC_FRAGMENT_MAX_PACKET_SIZE,
				      out, sizeof(out));
	CHECK(n == RAW_EXACT);
	CHECK(read_be16(&out[SCHC_IPV6_PAYLOAD_LEN_OFFSET]) == RAW_EXACT - IPV6_HDR_LEN);
	CHECK(icmpv6_checksum_valid(&out[8], &out[24], &out[40],
				    (uint16_t)(n - IPV6_HDR_LEN)));

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
	CHECK(test_malformed_is_atomic() == 0);
	CHECK(test_profile_limit() == 0);
	puts("SCHC Rule 4 decompression: PASS");
	return 0;
}
