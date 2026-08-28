/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "schc_internal.h"

#include <stdio.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { \
	printf("FAIL line %d: %s\n", __LINE__, #c); return 1; \
} } while (0)

static const uint8_t src_ygg[16] = {
	0x02,0x7D,0xD5,0xCF,0xC6,0x79,0xAB,0x63,
	0x7D,0xD5,0xCF,0xC6,0x79,0xAB,0x63,0x42
};
static const uint8_t dst_ygg[16] = {
	0x02,0xF7,0x7A,0x7B,0xAA,0x12,0x26,0xB5,
	0xF5,0x7A,0x7B,0xAA,0x12,0x26,0xB5,0x0C
};

static size_t make_coap(uint8_t *packet, size_t capacity,
			const uint8_t src[16], const uint8_t dst[16],
			uint16_t src_port, uint16_t dst_port, uint8_t hop_limit,
			uint8_t version, uint8_t type, const uint8_t *token,
			uint8_t tkl, uint8_t code, uint16_t mid,
			const uint8_t *tail, size_t tail_len)
{
	size_t coap_len = SCHC_COAP_FIXED_LEN + tkl + tail_len;
	size_t udp_length = UDP_HDR_LEN + coap_len;
	size_t total = IPV6_HDR_LEN + udp_length;

	if (udp_length > UINT16_MAX || total > capacity || tkl > 15) return 0;
	ipv6_write_base(packet, (uint16_t)udp_length, IPV6_NH_UDP,
			hop_limit, src, dst);
	uint8_t *udp = ipv6_payload_mut(packet);
	udp_write_header(udp, src_port, dst_port, (uint16_t)udp_length, 0);
	uint8_t *coap = udp_payload_mut(udp);
	coap[0] = (uint8_t)((version << 6) | ((type & 3u) << 4) | tkl);
	coap[1] = code;
	write_be16(&coap[2], mid);
	if (tkl > 0) memcpy(&coap[4], token, tkl);
	if (tail_len > 0) memcpy(&coap[4 + tkl], tail, tail_len);
	uint16_t checksum;
	CHECK(udp_checksum(src, dst, src_port, dst_port, coap, coap_len,
			   &checksum) == 0);
	udp_write_checksum(udp, checksum);
	return total;
}

static size_t make_canonical(uint8_t *packet, size_t capacity,
			     const uint8_t *tail, size_t tail_len)
{
	return make_coap(packet, capacity, src_ygg, dst_ygg, 5683, 5683, 64,
			 1, 0, NULL, 0, 1, 0x1234, tail, tail_len);
}

static int test_canonical_vector(void)
{
	static const uint8_t tail[] = { 0xFF,'s','t','a','t','u','s' };
	static const uint8_t expected[] = {
		1,0x40,0x7D,0xD5,0xCF,0xC6,0x79,0xAB,0x63,0x7D,0xD5,0xCF,
		0xC6,0x79,0xAB,0x63,0x42,0xF7,0x7A,0x7B,0xAA,0x12,0x26,0xB5,
		0xF5,0x7A,0x7B,0xAA,0x12,0x26,0xB5,0x0C,0x33,0,0x04,0x48,0xD0,
		0xFF,'s','t','a','t','u','s'
	};
	uint8_t packet[96], out[96];
	size_t len = make_canonical(packet, sizeof(packet), tail, sizeof(tail));
	int n = lichen_schc_compress(packet, len, out, sizeof(out));

	CHECK(n == (int)sizeof(expected));
	CHECK(memcmp(out, expected, sizeof(expected)) == 0);
	return 0;
}

static int expect_fallback(uint8_t *packet, size_t len)
{
	uint8_t out[256];
	int n = lichen_schc_compress(packet, len, out, sizeof(out));

	CHECK(n == (int)len + 1 && out[0] == SCHC_RULE_UNCOMPRESSED);
	CHECK(memcmp(&out[1], packet, len) == 0);
	return 0;
}

static int test_nonmatches_and_checksum(void)
{
	uint8_t packet[128];
	uint8_t other_src[16];
	memcpy(other_src, src_ygg, 16);
	other_src[0] = 0x20;
	size_t len = make_coap(packet, sizeof(packet), other_src, dst_ygg,
			       5683, 5683, 64, 1, 0, NULL, 0, 1, 1, NULL, 0);
	CHECK(expect_fallback(packet, len) == 0);
	len = make_coap(packet, sizeof(packet), src_ygg, dst_ygg,
			5696, 5683, 64, 1, 0, NULL, 0, 1, 1, NULL, 0);
	CHECK(expect_fallback(packet, len) == 0);
	len = make_coap(packet, sizeof(packet), src_ygg, dst_ygg,
			5683, 5683, 64, 2, 0, NULL, 0, 1, 1, NULL, 0);
	CHECK(expect_fallback(packet, len) == 0);

	len = make_canonical(packet, sizeof(packet), NULL, 0);
	packet[1] = 0x10;
	CHECK(expect_fallback(packet, len) == 0);
	packet[1] = 0;
	packet[3] = 1;
	CHECK(expect_fallback(packet, len) == 0);

	len = make_canonical(packet, sizeof(packet), NULL, 0);
	packet[46] ^= 1;
	uint8_t out[128];
	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_compress(packet, len, out, sizeof(out)) < 0);
	CHECK(out[0] == 0xA5);
	return 0;
}

static int test_variable_fields_tail_and_atomic_bounds(void)
{
	static const uint8_t token[] = { 0xAA,0x55 };
	static const uint8_t tail[] = { 0xB1,'x',0x11,'y',0xFF,'p','a','y' };
	uint8_t packet[128], out[128];
	size_t len = make_coap(packet, sizeof(packet), src_ygg, dst_ygg,
			       5680, 5695, 255, 1, 3, token, sizeof(token),
			       0x45, 0xBEEF, tail, sizeof(tail));
	int n = lichen_schc_compress(packet, len, out, sizeof(out));

	CHECK(n == 37 + (int)sizeof(token) + (int)sizeof(tail));
	CHECK(out[0] == SCHC_RULE_GLOBAL_COAP && out[1] == 255);
	CHECK(out[32] == 0x0F && out[33] == 0xC9 && out[34] == 0x16);
	CHECK(memcmp(&out[37], token, sizeof(token)) == 0);
	CHECK(memcmp(&out[37 + sizeof(token)], tail, sizeof(tail)) == 0);

	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_compress(packet, len, out, (size_t)n - 1) < 0);
	CHECK(out[0] == 0xA5);
	return 0;
}

static int test_profile_limit(void)
{
	enum { FIXED_RAW = 52, FIXED_COMPRESSED = 37,
	       TAIL_EXACT = SCHC_FRAGMENT_MAX_PACKET_SIZE - FIXED_COMPRESSED };
	static uint8_t packet[FIXED_RAW + TAIL_EXACT + 1];
	static uint8_t tail[TAIL_EXACT + 1];
	static uint8_t out[SCHC_FRAGMENT_MAX_PACKET_SIZE + 1];
	size_t len = make_canonical(packet, sizeof(packet), tail, TAIL_EXACT);

	CHECK(lichen_schc_compress(packet, len, out, sizeof(out)) ==
	      SCHC_FRAGMENT_MAX_PACKET_SIZE);
	len = make_canonical(packet, sizeof(packet), tail, TAIL_EXACT + 1);
	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_compress(packet, len, out, sizeof(out)) < 0);
	CHECK(out[0] == 0xA5);
	return 0;
}

int main(void)
{
	CHECK(test_canonical_vector() == 0);
	CHECK(test_nonmatches_and_checksum() == 0);
	CHECK(test_variable_fields_tail_and_atomic_bounds() == 0);
	CHECK(test_profile_limit() == 0);
	puts("SCHC Rule 1 compression: PASS");
	return 0;
}
