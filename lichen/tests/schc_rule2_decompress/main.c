/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "schc_internal.h"

#include <stdio.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { \
	printf("FAIL line %d: %s\n", __LINE__, #c); return 1; \
} } while (0)

static const uint8_t request_compressed[] = {
	2,0x40,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,2,0x80,0xAB,0xCD,0,7,
	'p','i','n','g'
};
static const uint8_t request_packet[] = {
	0x60,0,0,0,0,0x0C,0x3A,0x40,
	0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
	0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,2,
	0x80,0,0xF8,0x0E,0xAB,0xCD,0,7,'p','i','n','g'
};
static const uint8_t reply_compressed[] = {
	2,0x40,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,2,0x81,0x12,0x34,0,42,
	'p','o','n','g'
};
static const uint8_t reply_packet[] = {
	0x60,0,0,0,0,0x0C,0x3A,0x40,
	0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
	0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,2,
	0x81,0,0x90,0x7F,0x12,0x34,0,42,'p','o','n','g'
};

static int round_trip(const uint8_t *compressed, size_t compressed_len,
		      const uint8_t *packet, size_t packet_len)
{
	uint8_t out[128], recompressed[128];
	int n = lichen_schc_decompress(compressed, compressed_len, out, sizeof(out));

	CHECK(n == (int)packet_len && memcmp(out, packet, packet_len) == 0);
	int m = lichen_schc_compress(out, (size_t)n, recompressed,
				    sizeof(recompressed));
	CHECK(m == (int)compressed_len);
	CHECK(memcmp(recompressed, compressed, compressed_len) == 0);
	return 0;
}

static int test_canonical_vectors(void)
{
	CHECK(round_trip(request_compressed, sizeof(request_compressed),
			 request_packet, sizeof(request_packet)) == 0);
	CHECK(round_trip(reply_compressed, sizeof(reply_compressed),
			 reply_packet, sizeof(reply_packet)) == 0);
	return 0;
}

static int test_fields_and_every_first_payload_octet(void)
{
	uint8_t compressed[28];
	uint8_t out[64], recompressed[64];

	memcpy(compressed, request_compressed, 23);
	compressed[1] = 255;
	memset(&compressed[2], 0, 8);
	memset(&compressed[10], 0xFF, 8);
	compressed[18] = ICMPV6_TYPE_ECHO_REPLY;
	compressed[19] = 0;
	compressed[20] = 0;
	compressed[21] = 0xFF;
	compressed[22] = 0xFF;
	for (unsigned int first = 0; first <= UINT8_MAX; first++) {
		compressed[23] = (uint8_t)first;
		memcpy(&compressed[24], "tail", 4);
		int n = lichen_schc_decompress(compressed, sizeof(compressed), out,
					      sizeof(out));
		CHECK(n == 53 && out[7] == 255 && out[23] == 0);
		CHECK(out[32] == 0xFF && out[39] == 0xFF);
		CHECK(out[40] == ICMPV6_TYPE_ECHO_REPLY && out[44] == 0 &&
		      out[45] == 0 && out[46] == 0xFF && out[47] == 0xFF);
		CHECK(out[48] == (uint8_t)first && memcmp(&out[49], "tail", 4) == 0);
		CHECK(icmpv6_checksum_valid(&out[8], &out[24], &out[40],
					    (uint16_t)(n - IPV6_HDR_LEN)));
		int m = lichen_schc_compress(out, (size_t)n, recompressed,
					    sizeof(recompressed));
		CHECK(m == (int)sizeof(compressed));
		CHECK(memcmp(recompressed, compressed, sizeof(compressed)) == 0);
	}
	return 0;
}

static int test_malformed_and_bounds_are_atomic(void)
{
	uint8_t out[128];
	for (size_t len = 0; len < 23; len++) {
		memset(out, 0xA5, sizeof(out));
		CHECK(lichen_schc_decompress(request_compressed, len,
					    out, sizeof(out)) < 0);
		CHECK(out[0] == 0xA5);
	}

	uint8_t invalid[sizeof(request_compressed)];
	for (unsigned int type = 0; type <= UINT8_MAX; type++) {
		if (type == ICMPV6_TYPE_ECHO_REQUEST || type == ICMPV6_TYPE_ECHO_REPLY) continue;
		memcpy(invalid, request_compressed, sizeof(invalid));
		invalid[18] = (uint8_t)type;
		memset(out, 0xA5, sizeof(out));
		CHECK(lichen_schc_decompress(invalid, sizeof(invalid),
					    out, sizeof(out)) < 0);
		CHECK(out[0] == 0xA5);
	}

	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_decompress(request_compressed, sizeof(request_compressed),
				    out, sizeof(request_packet) - 1) < 0);
	CHECK(out[0] == 0xA5);
	return 0;
}

static int test_profile_limit(void)
{
	enum { RAW_EXACT = SCHC_FRAGMENT_MAX_PACKET_SIZE + 25 };
	static uint8_t compressed[SCHC_FRAGMENT_MAX_PACKET_SIZE + 1];
	static uint8_t out[RAW_EXACT];

	memcpy(compressed, request_compressed, 23);
	memset(&compressed[23], 0, SCHC_FRAGMENT_MAX_PACKET_SIZE - 23);
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
	CHECK(test_canonical_vectors() == 0);
	CHECK(test_fields_and_every_first_payload_octet() == 0);
	CHECK(test_malformed_and_bounds_are_atomic() == 0);
	CHECK(test_profile_limit() == 0);
	puts("SCHC Rule 2 decompression: PASS");
	return 0;
}
