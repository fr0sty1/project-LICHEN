/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "schc_internal.h"

#include <stdio.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { \
	printf("FAIL line %d: %s\n", __LINE__, #c); return 1; \
} } while (0)

static const uint8_t src_canonical[16] = {
	0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1
};
static const uint8_t dst_canonical[16] = {
	0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,2
};

static size_t make_echo(uint8_t *packet, size_t capacity,
			const uint8_t src[16], const uint8_t dst[16],
			uint8_t hop_limit, uint8_t type, uint8_t code,
			uint16_t id, uint16_t sequence,
			const uint8_t *payload, size_t payload_len)
{
	size_t icmp_len = (size_t)SCHC_ICMPV6_ECHO_TAIL_OFFSET + payload_len;
	size_t total = IPV6_HDR_LEN + icmp_len;

	if (icmp_len > UINT16_MAX || total > capacity) return 0;
	ipv6_write_base(packet, (uint16_t)icmp_len, IPV6_NH_ICMPV6,
			hop_limit, src, dst);
	uint8_t *icmp = ipv6_payload_mut(packet);
	icmpv6_write_header(icmp, type, code, 0);
	icmpv6_echo_write_body(icmp, id, sequence);
	if (payload_len > 0) memcpy(icmpv6_echo_tail_mut(icmp), payload, payload_len);
	icmpv6_write_checksum(icmp,
		icmpv6_checksum(src, dst, icmp, (uint16_t)icmp_len));
	return total;
}

static size_t make_canonical(uint8_t *packet, size_t capacity, uint8_t type,
			     const uint8_t *payload, size_t payload_len)
{
	return make_echo(packet, capacity, src_canonical, dst_canonical,
			 64, type, 0, type == ICMPV6_TYPE_ECHO_REQUEST ? 0xABCD : 0x1234,
			 type == ICMPV6_TYPE_ECHO_REQUEST ? 7 : 42,
			 payload, payload_len);
}

static int test_canonical_vectors(void)
{
	static const uint8_t ping[] = { 'p','i','n','g' };
	static const uint8_t pong[] = { 'p','o','n','g' };
	static const uint8_t expected_request[] = {
		2,0x40,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,2,0x80,0xAB,0xCD,0,7,
		'p','i','n','g'
	};
	static const uint8_t expected_reply[] = {
		2,0x40,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,2,0x81,0x12,0x34,0,42,
		'p','o','n','g'
	};
	uint8_t packet[80], out[80];
	size_t len = make_canonical(packet, sizeof(packet), ICMPV6_TYPE_ECHO_REQUEST,
			    ping, sizeof(ping));
	int n = lichen_schc_compress(packet, len, out, sizeof(out));
	CHECK(n == (int)sizeof(expected_request));
	CHECK(memcmp(out, expected_request, sizeof(expected_request)) == 0);

	len = make_canonical(packet, sizeof(packet), ICMPV6_TYPE_ECHO_REPLY,
			     pong, sizeof(pong));
	n = lichen_schc_compress(packet, len, out, sizeof(out));
	CHECK(n == (int)sizeof(expected_reply));
	CHECK(memcmp(out, expected_reply, sizeof(expected_reply)) == 0);
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

static int test_nonmatches(void)
{
	uint8_t packet[128];
	size_t len = make_canonical(packet, sizeof(packet), ICMPV6_TYPE_ECHO_REQUEST,
			    NULL, 0);
	packet[1] = 0x10;
	CHECK(expect_fallback(packet, len) == 0);
	packet[1] = 0;
	packet[3] = 1;
	CHECK(expect_fallback(packet, len) == 0);

	uint8_t scoped_src[16];
	memcpy(scoped_src, src_canonical, sizeof(scoped_src));
	scoped_src[7] = 1;
	len = make_echo(packet, sizeof(packet), scoped_src, dst_canonical, 64,
			ICMPV6_TYPE_ECHO_REQUEST, 0, 1, 2, NULL, 0);
	CHECK(expect_fallback(packet, len) == 0);

	uint8_t global_dst[16] = { 0x20, 1, 0x0D, 0xB8, [15] = 2 };
	len = make_echo(packet, sizeof(packet), src_canonical, global_dst, 64,
			ICMPV6_TYPE_ECHO_REQUEST, 0, 1, 2, NULL, 0);
	CHECK(expect_fallback(packet, len) == 0);
	len = make_echo(packet, sizeof(packet), src_canonical, dst_canonical, 64,
			1, 0, 1, 2, NULL, 0);
	CHECK(expect_fallback(packet, len) == 0);
	len = make_echo(packet, sizeof(packet), src_canonical, dst_canonical, 64,
			ICMPV6_TYPE_ECHO_REQUEST, 1, 1, 2, NULL, 0);
	CHECK(expect_fallback(packet, len) == 0);

	len = make_canonical(packet, sizeof(packet), ICMPV6_TYPE_ECHO_REQUEST,
			     NULL, 0);
	packet[42] ^= 1;
	CHECK(expect_fallback(packet, len) == 0);
	return 0;
}

static int test_payload_and_atomic_bounds(void)
{
	static const uint8_t payload[] = { 0,0xFF,0x80,0x7F,'o','p','a','q','u','e' };
	uint8_t packet[96], out[96];
	size_t len = make_echo(packet, sizeof(packet), src_canonical, dst_canonical,
			       1, ICMPV6_TYPE_ECHO_REPLY, 0, 0, UINT16_MAX,
			       payload, sizeof(payload));
	int n = lichen_schc_compress(packet, len, out, sizeof(out));

	CHECK(n == 23 + (int)sizeof(payload));
	CHECK(out[1] == 1 && out[18] == ICMPV6_TYPE_ECHO_REPLY);
	CHECK(out[19] == 0 && out[20] == 0 && out[21] == 0xFF && out[22] == 0xFF);
	CHECK(memcmp(&out[23], payload, sizeof(payload)) == 0);
	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_compress(packet, len, out, (size_t)n - 1) < 0);
	CHECK(out[0] == 0xA5);
	return 0;
}

static int test_profile_limit(void)
{
	enum { FIXED_RAW = 48, FIXED_COMPRESSED = 23,
	       PAYLOAD_EXACT = SCHC_FRAGMENT_MAX_PACKET_SIZE - FIXED_COMPRESSED };
	static uint8_t packet[FIXED_RAW + PAYLOAD_EXACT + 1];
	static uint8_t payload[PAYLOAD_EXACT + 1];
	static uint8_t out[SCHC_FRAGMENT_MAX_PACKET_SIZE + 1];
	size_t len = make_canonical(packet, sizeof(packet), ICMPV6_TYPE_ECHO_REQUEST,
			    payload, PAYLOAD_EXACT);

	CHECK(lichen_schc_compress(packet, len, out, sizeof(out)) ==
	      SCHC_FRAGMENT_MAX_PACKET_SIZE);
	len = make_canonical(packet, sizeof(packet), ICMPV6_TYPE_ECHO_REQUEST,
			     payload, PAYLOAD_EXACT + 1);
	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_compress(packet, len, out, sizeof(out)) < 0);
	CHECK(out[0] == 0xA5);
	return 0;
}

int main(void)
{
	CHECK(test_canonical_vectors() == 0);
	CHECK(test_nonmatches() == 0);
	CHECK(test_payload_and_atomic_bounds() == 0);
	CHECK(test_profile_limit() == 0);
	puts("SCHC Rule 2 compression: PASS");
	return 0;
}
