/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "schc_internal.h"

#include <stdio.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { \
	printf("FAIL line %d: %s\n", __LINE__, #c); return 1; \
} } while (0)

static const uint8_t src_canonical[16] = {
	0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
};
static const uint8_t dst_canonical[16] = {
	0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
};
static const uint8_t dodag_canonical[16] = {
	0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
};

static size_t make_dao(uint8_t *packet, size_t capacity,
		       const uint8_t src[16], const uint8_t dst[16],
		       uint8_t hop_limit, uint8_t instance, uint8_t kd_flags,
		       uint8_t reserved, uint8_t sequence,
		       const uint8_t dodag[16], const uint8_t *tail,
		       size_t tail_len)
{
	size_t icmp_len = (size_t)SCHC_ICMPV6_BODY_OFFSET +
			  (size_t)SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN + tail_len;
	size_t total = IPV6_HDR_LEN + icmp_len;

	if (icmp_len > UINT16_MAX || total > capacity) return 0;
	ipv6_write_base(packet, (uint16_t)icmp_len, IPV6_NH_ICMPV6,
			hop_limit, src, dst);
	uint8_t *icmp = ipv6_payload_mut(packet);
	icmpv6_write_header(icmp, ICMPV6_TYPE_RPL, ICMPV6_CODE_RPL_DAO, 0);
	uint8_t *rpl = icmpv6_body_mut(icmp);
	rpl[SCHC_RPL_INSTANCE_OFFSET] = instance;
	rpl[SCHC_RPL_DAO_KD_FLAGS_OFFSET] = kd_flags;
	rpl[SCHC_RPL_DAO_RESERVED_OFFSET] = reserved;
	rpl[SCHC_RPL_DAO_SEQUENCE_OFFSET] = sequence;
	memcpy(&rpl[SCHC_RPL_DAO_DODAGID_OFFSET], dodag, 16);
	if (tail_len > 0) memcpy(&rpl[SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN], tail, tail_len);
	icmpv6_write_checksum(icmp,
		icmpv6_checksum(src, dst, icmp, (uint16_t)icmp_len));
	return total;
}

static int test_canonical_vector(void)
{
	static const uint8_t expected_packet[] = {
		0x60,0,0,0,0,0x18,0x3A,0x40,
		0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
		0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,2,
		0x9B,0x02,0x68,0xDF,0,0x40,0,5,
		0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1
	};
	static const uint8_t expected_compressed[] = {
		4,0x40,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,2,
		0,0x40,5,0xFE,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1
	};
	uint8_t packet[80], out[80];
	size_t len = make_dao(packet, sizeof(packet), src_canonical, dst_canonical,
			      64, 0, 0x40, 0, 5, dodag_canonical, NULL, 0);

	CHECK(len == sizeof(expected_packet));
	CHECK(memcmp(packet, expected_packet, len) == 0);
	int n = lichen_schc_compress(packet, len, out, sizeof(out));
	CHECK(n == (int)sizeof(expected_compressed));
	CHECK(memcmp(out, expected_compressed, sizeof(expected_compressed)) == 0);
	return 0;
}

static int expect_fallback(uint8_t *packet, size_t len)
{
	uint8_t out[256];
	int n = lichen_schc_compress(packet, len, out, sizeof(out));

	CHECK(n == (int)len + 1);
	CHECK(out[0] == SCHC_RULE_UNCOMPRESSED);
	CHECK(memcmp(&out[1], packet, len) == 0);
	return 0;
}

static int test_nonmatches_and_checksum(void)
{
	uint8_t packet[128];
	size_t len = make_dao(packet, sizeof(packet), src_canonical, dst_canonical,
			      64, 0, 0, 0, 5, dodag_canonical, NULL, 0);
	CHECK(expect_fallback(packet, len) == 0); /* DODAGID flag clear */

	len = make_dao(packet, sizeof(packet), src_canonical, dst_canonical,
		       64, 0, 0x40, 1, 5, dodag_canonical, NULL, 0);
	CHECK(expect_fallback(packet, len) == 0); /* reserved field */

	len = make_dao(packet, sizeof(packet), src_canonical, dst_canonical,
		       64, 0, 0x40, 0, 5, dodag_canonical, NULL, 0);
	packet[1] = 0x10;
	CHECK(expect_fallback(packet, len) == 0); /* traffic class */
	packet[1] = 0;
	packet[3] = 1;
	CHECK(expect_fallback(packet, len) == 0); /* flow label */

	uint8_t scoped_src[16];
	memcpy(scoped_src, src_canonical, sizeof(scoped_src));
	scoped_src[7] = 1; /* fe80:0:0:1::/64 is in fe80::/10, not canonical /64. */
	len = make_dao(packet, sizeof(packet), scoped_src, dst_canonical,
		       64, 0, 0x40, 0, 5, dodag_canonical, NULL, 0);
	CHECK(expect_fallback(packet, len) == 0);

	len = make_dao(packet, sizeof(packet), src_canonical, dst_canonical,
		       64, 0, 0x40, 0, 5, dodag_canonical, NULL, 0);
	packet[42] ^= 1; /* Corrupt the checksum: current profile preserves via 255. */
	CHECK(expect_fallback(packet, len) == 0);
	return 0;
}

static int test_tail_and_atomic_bounds(void)
{
	static const uint8_t tail[] = {
		5, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		6, 4, 0, 1, 2, 3
	};
	uint8_t packet[128], out[128];
	size_t len = make_dao(packet, sizeof(packet), src_canonical, dst_canonical,
			      1, 255, 0xC0, 0, 255, dodag_canonical,
			      tail, sizeof(tail));
	int n = lichen_schc_compress(packet, len, out, sizeof(out));

	CHECK(n == 37 + (int)sizeof(tail));
	CHECK(out[0] == SCHC_RULE_RPL_DAO);
	CHECK(out[1] == 1 && out[18] == 255 && out[19] == 0xC0 && out[20] == 255);
	CHECK(memcmp(&out[37], tail, sizeof(tail)) == 0);

	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_compress(packet, len, out, (size_t)n - 1) < 0);
	CHECK(out[0] == 0xA5);
	return 0;
}

static int test_profile_limit(void)
{
	enum { FIXED_RAW = 64, FIXED_COMPRESSED = 37,
	       TAIL_EXACT = SCHC_FRAGMENT_MAX_PACKET_SIZE - FIXED_COMPRESSED };
	static uint8_t packet[FIXED_RAW + TAIL_EXACT + 1];
	static uint8_t tail[TAIL_EXACT + 1];
	static uint8_t out[SCHC_FRAGMENT_MAX_PACKET_SIZE + 1];
	size_t len = make_dao(packet, sizeof(packet), src_canonical, dst_canonical,
			      64, 0, 0x40, 0, 5, dodag_canonical,
			      tail, TAIL_EXACT);
	CHECK(lichen_schc_compress(packet, len, out, sizeof(out)) ==
	      SCHC_FRAGMENT_MAX_PACKET_SIZE);

	len = make_dao(packet, sizeof(packet), src_canonical, dst_canonical,
		       64, 0, 0x40, 0, 5, dodag_canonical,
		       tail, TAIL_EXACT + 1);
	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_compress(packet, len, out, sizeof(out)) < 0);
	CHECK(out[0] == 0xA5);
	return 0;
}

int main(void)
{
	CHECK(test_canonical_vector() == 0);
	CHECK(test_nonmatches_and_checksum() == 0);
	CHECK(test_tail_and_atomic_bounds() == 0);
	CHECK(test_profile_limit() == 0);
	puts("SCHC Rule 4 compression: PASS");
	return 0;
}
