/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "schc_internal.h"

#include <stdio.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { \
	printf("FAIL line %d: %s\n", __LINE__, #c); return 1; \
} } while (0)

enum {
	RULE6_FIXED_RAW = IPV6_HDR_LEN + UDP_HDR_LEN + SCHC_COAP_FIXED_LEN,
	RULE6_FIXED_COMPRESSED = 37,
	RULE6_MAX_TAIL = SCHC_FRAGMENT_MAX_PACKET_SIZE - RULE6_FIXED_COMPRESSED,
};

static const uint8_t global_src[16] = {
	0x02,0x7D,0xD5,0xCF,0xC6,0x79,0xAB,0x63,
	0x7D,0xD5,0xCF,0xC6,0x79,0xAB,0x63,0x42
};
static const uint8_t global_dst[16] = {
	0x02,0xF7,0x7A,0x7B,0xAA,0x12,0x26,0xB5,
	0xF5,0x7A,0x7B,0xAA,0x12,0x26,0xB5,0x0C
};

static size_t make_packet(uint8_t *packet, size_t capacity,
			  const uint8_t src[16], const uint8_t dst[16],
			  uint16_t src_port, uint16_t dst_port, uint8_t hop_limit,
			  uint8_t type, uint8_t code, uint16_t mid,
			  const uint8_t *token, size_t token_len,
			  const uint8_t *tail, size_t tail_len)
{
	if (token_len > 8 || token_len > SIZE_MAX - SCHC_COAP_FIXED_LEN ||
	    tail_len > SIZE_MAX - SCHC_COAP_FIXED_LEN - token_len) {
		return 0;
	}
	size_t coap_len = SCHC_COAP_FIXED_LEN + token_len + tail_len;
	if (coap_len > UINT16_MAX - UDP_HDR_LEN ||
	    RULE6_FIXED_RAW + token_len + tail_len > capacity) {
		return 0;
	}
	uint16_t udp_length = (uint16_t)(UDP_HDR_LEN + coap_len);
	ipv6_write_base(packet, udp_length, IPV6_NH_UDP, hop_limit, src, dst);
	uint8_t *udp = ipv6_payload_mut(packet);
	udp_write_header(udp, src_port, dst_port, udp_length, 0);
	uint8_t *coap = udp_payload_mut(udp);
	coap_write_fixed(coap, type, (uint8_t)token_len, code, mid);
	if (token_len > 0) memcpy(coap_tail_mut(coap), token, token_len);
	if (tail_len > 0) {
		memcpy(coap_tail_mut(coap) + token_len, tail, tail_len);
	}
	uint16_t checksum;
	if (udp_checksum(src, dst, src_port, dst_port, coap, coap_len,
			 &checksum) < 0) {
		return 0;
	}
	udp_write_checksum(udp, checksum);
	return IPV6_HDR_LEN + udp_length;
}

static int test_canonical_shared_vector(void)
{
	static const uint8_t packet[] = {
		0x60,0,0,0,0,0x16,0x11,0x40,
		0x02,0x7D,0xD5,0xCF,0xC6,0x79,0xAB,0x63,
		0x7D,0xD5,0xCF,0xC6,0x79,0xAB,0x63,0x42,
		0x02,0xF7,0x7A,0x7B,0xAA,0x12,0x26,0xB5,
		0xF5,0x7A,0x7B,0xAA,0x12,0x26,0xB5,0x0C,
		0x16,0x33,0x16,0x33,0,0x16,0x53,0x39,
		0x42,1,0x12,0x34,0,1,0x92,9,0,0xFF,0xDE,0xAD,0xBE,0xEF
	};
	static const uint8_t expected[] = {
		6,0x40,
		0x7D,0xD5,0xCF,0xC6,0x79,0xAB,0x63,
		0x7D,0xD5,0xCF,0xC6,0x79,0xAB,0x63,0x42,
		0xF7,0x7A,0x7B,0xAA,0x12,0x26,0xB5,
		0xF5,0x7A,0x7B,0xAA,0x12,0x26,0xB5,0x0C,
		0x33,0x08,0x04,0x48,0xD0,0,1,0x92,9,0,0xFF,0xDE,0xAD,0xBE,0xEF
	};
	uint8_t out[sizeof(expected)];
	int length = lichen_schc_compress(packet, sizeof(packet), out, sizeof(out));
	CHECK(length == (int)sizeof(expected));
	CHECK(memcmp(out, expected, sizeof(expected)) == 0);
	return 0;
}

static int test_independent_canonical_packing(void)
{
	static const uint8_t src[16] = {
		0x02,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
	};
	static const uint8_t dst[16] = { 0x02, [15] = 1 };
	static const uint8_t token[] = { 0xAA, 0x55 };
	static const uint8_t tail[] = { 0x92,9,1,0xFF,1,2,3 };
	static const uint8_t expected[] = {
		6,1,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
		0x0F,0xC9,0x16,0xFB,0xBC,0xAA,0x55,
		0x92,9,1,0xFF,1,2,3
	};
	uint8_t packet[128], out[128];
	size_t length = make_packet(packet, sizeof(packet), src, dst, 5680, 5695,
				    1, 3, 0x45, 0xBEEF, token, sizeof(token),
				    tail, sizeof(tail));
	CHECK(length > 0);
	int compressed = lichen_schc_compress(packet, length, out, sizeof(out));
	CHECK(compressed == (int)sizeof(expected));
	CHECK(memcmp(out, expected, sizeof(expected)) == 0);
	return 0;
}

static int expect_rule(uint8_t expected_rule, const uint8_t *tail,
		       size_t tail_len)
{
	uint8_t packet[128], out[256];
	size_t length = make_packet(packet, sizeof(packet), global_src, global_dst,
				    5683, 5683, 64, 0, 1, 0x1234,
				    NULL, 0, tail, tail_len);
	CHECK(length > 0);
	CHECK(lichen_schc_compress(packet, length, out, sizeof(out)) > 0);
	CHECK(out[0] == expected_rule);
	return 0;
}

static int test_strict_oscore_selector(void)
{
	static const uint8_t valid_empty[] = { 0x90 };
	static const uint8_t valid_piv_kid[] = { 0x92,9,1 };
	static const uint8_t valid_piv[] = { 0x92,1,1 };
	static const uint8_t valid_context[] = { 0x95,0x19,1,1,0xAA,0xBB };
	static const uint8_t reserved_length[] = { 0x9F };
	static const uint8_t truncated_length[] = { 0x9D };
	static const uint8_t missing_piv[] = { 0x91,1 };
	static const uint8_t duplicate[] = { 0x90,0 };
	static const uint8_t empty_payload[] = { 0x90,0xFF };

	CHECK(expect_rule(SCHC_RULE_GLOBAL_OSCORE, valid_empty,
			  sizeof(valid_empty)) == 0);
	CHECK(expect_rule(SCHC_RULE_GLOBAL_OSCORE, valid_piv_kid,
			  sizeof(valid_piv_kid)) == 0);
	CHECK(expect_rule(SCHC_RULE_GLOBAL_OSCORE, valid_piv,
			  sizeof(valid_piv)) == 0);
	CHECK(expect_rule(SCHC_RULE_GLOBAL_OSCORE, valid_context,
			  sizeof(valid_context)) == 0);
	CHECK(expect_rule(SCHC_RULE_GLOBAL_COAP, NULL, 0) == 0);
	CHECK(expect_rule(SCHC_RULE_GLOBAL_COAP, reserved_length,
			  sizeof(reserved_length)) == 0);
	CHECK(expect_rule(SCHC_RULE_GLOBAL_COAP, truncated_length,
			  sizeof(truncated_length)) == 0);
	CHECK(expect_rule(SCHC_RULE_GLOBAL_COAP, missing_piv,
			  sizeof(missing_piv)) == 0);
	CHECK(expect_rule(SCHC_RULE_GLOBAL_COAP, duplicate,
			  sizeof(duplicate)) == 0);
	CHECK(expect_rule(SCHC_RULE_GLOBAL_COAP, empty_payload,
			  sizeof(empty_payload)) == 0);
	return 0;
}

static int test_rule_constraints_and_checksum(void)
{
	static const uint8_t oscore[] = { 0x90 };
	static const uint8_t non_ygg[16] = {
		0x20,1,0x0D,0xB8,0,0,0,0,0,0,0,0,0,0,0,1
	};
	uint8_t packet[128], out[256];
	size_t length = make_packet(packet, sizeof(packet), non_ygg, global_dst,
				    5683, 5683, 64, 0, 1, 0x1234,
				    NULL, 0, oscore, sizeof(oscore));
	CHECK(length > 0);
	CHECK(lichen_schc_compress(packet, length, out, sizeof(out)) > 0);
	CHECK(out[0] == SCHC_RULE_UNCOMPRESSED);

	length = make_packet(packet, sizeof(packet), global_src, global_dst,
			     5700, 5683, 64, 0, 1, 0x1234,
			     NULL, 0, oscore, sizeof(oscore));
	CHECK(length > 0);
	CHECK(lichen_schc_compress(packet, length, out, sizeof(out)) > 0);
	CHECK(out[0] == SCHC_RULE_UNCOMPRESSED);

	length = make_packet(packet, sizeof(packet), global_src, global_dst,
			     5683, 5683, 64, 0, 1, 0x1234,
			     NULL, 0, oscore, sizeof(oscore));
	CHECK(length > 0);
	packet[1] = 1;
	CHECK(lichen_schc_compress(packet, length, out, sizeof(out)) > 0);
	CHECK(out[0] == SCHC_RULE_UNCOMPRESSED);

	packet[1] = 0;
	packet[47] ^= 1;
	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_compress(packet, length, out, sizeof(out)) ==
	      SCHC_ERR_INVALID_ARGUMENT);
	for (size_t i = 0; i < sizeof(out); i++) CHECK(out[i] == 0xA5);
	return 0;
}

static int test_atomic_bounds_and_profile_limit(void)
{
	static const uint8_t oscore_payload[] = { 0x90,0xFF,0xAA };
	uint8_t packet[128], out[128];
	size_t length = make_packet(packet, sizeof(packet), global_src, global_dst,
				    5683, 5683, 64, 0, 1, 0x1234,
				    NULL, 0, oscore_payload,
				    sizeof(oscore_payload));
	CHECK(length > 0);
	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_compress(packet, length, out, 39) ==
	      SCHC_ERR_BUFFER_TOO_SMALL);
	for (size_t i = 0; i < sizeof(out); i++) CHECK(out[i] == 0xA5);

	static uint8_t max_packet[RULE6_FIXED_RAW + RULE6_MAX_TAIL + 1];
	static uint8_t max_tail[RULE6_MAX_TAIL + 1];
	static uint8_t max_out[SCHC_FRAGMENT_MAX_PACKET_SIZE + 1];
	max_tail[0] = 0x90;
	max_tail[1] = 0xFF;
	length = make_packet(max_packet, sizeof(max_packet), global_src, global_dst,
			     5683, 5683, 64, 0, 1, 0x1234,
			     NULL, 0, max_tail, RULE6_MAX_TAIL);
	CHECK(length > 0);
	CHECK(lichen_schc_compress(max_packet, length, max_out, sizeof(max_out)) ==
	      SCHC_FRAGMENT_MAX_PACKET_SIZE);
	CHECK(max_out[0] == SCHC_RULE_GLOBAL_OSCORE);

	length = make_packet(max_packet, sizeof(max_packet), global_src, global_dst,
			     5683, 5683, 64, 0, 1, 0x1234,
			     NULL, 0, max_tail, RULE6_MAX_TAIL + 1);
	CHECK(length > 0);
	memset(max_out, 0xA5, sizeof(max_out));
	CHECK(lichen_schc_compress(max_packet, length, max_out, sizeof(max_out)) ==
	      SCHC_ERR_BUFFER_TOO_SMALL);
	for (size_t i = 0; i < sizeof(max_out); i++) CHECK(max_out[i] == 0xA5);
	return 0;
}

int main(void)
{
	CHECK(test_canonical_shared_vector() == 0);
	CHECK(test_independent_canonical_packing() == 0);
	CHECK(test_strict_oscore_selector() == 0);
	CHECK(test_rule_constraints_and_checksum() == 0);
	CHECK(test_atomic_bounds_and_profile_limit() == 0);
	puts("SCHC Rule 6 compression: PASS");
	return 0;
}
