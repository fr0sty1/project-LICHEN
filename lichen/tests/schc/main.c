/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief SCHC round-trip tests using test vectors from Rust implementation
 *
 * Test vectors are hex-encoded IPv6 packets and their expected SCHC-compressed
 * forms. Each test verifies:
 *   1. compress(packet) == expected_compressed
 *   2. decompress(compressed) == packet
 *
 * Note: This test uses 1500-byte buffers (4x per round_trip call) to handle
 * arbitrary MTU-sized packets. This is intentional for test coverage of
 * edge cases. Production code should use appropriately sized buffers.
 */

#include <lichen/schc.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ─── hex helpers ─────────────────────────────────────────────────────────── */

static int hex_to_byte(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static size_t hex_decode(const char *hex, uint8_t *out, size_t out_len)
{
	size_t len = strlen(hex);
	if (len % 2 != 0) {
		return 0;  /* odd-length hex is invalid */
	}
	size_t bytes = len / 2;

	if (bytes > out_len) {
		return 0;
	}

	for (size_t i = 0; i < bytes; i++) {
		int hi = hex_to_byte(hex[i * 2]);
		int lo = hex_to_byte(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0) {
			return 0;
		}
		out[i] = (hi << 4) | lo;
	}
	return bytes;
}

/* ─── test framework ──────────────────────────────────────────────────────── */

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT_EQ(a, b, msg) do { \
	if ((a) != (b)) { \
		printf("  FAIL: %s (got %d, expected %d)\n", msg, (int)(a), (int)(b)); \
		return 0; \
	} \
} while (0)

#define ASSERT_MEM_EQ(a, b, len, msg) do { \
	if (memcmp((a), (b), (len)) != 0) { \
		printf("  FAIL: %s (memory mismatch)\n", msg); \
		return 0; \
	} \
} while (0)

static int round_trip(const char *packet_hex, const char *compressed_hex,
		      uint8_t expected_rule_id)
{
	uint8_t packet[1500];
	uint8_t expected[1500];
	uint8_t comp_buf[1500];
	uint8_t decomp_buf[1500];

	size_t pkt_len = hex_decode(packet_hex, packet, sizeof(packet));
	size_t exp_len = hex_decode(compressed_hex, expected, sizeof(expected));

	if (pkt_len == 0 || exp_len == 0) {
		printf("  FAIL: hex decode error\n");
		return 0;
	}

	/* Test compression */
	int n = lichen_schc_compress(packet, pkt_len, comp_buf, sizeof(comp_buf));
	ASSERT_EQ(n, (int)exp_len, "compress length");
	ASSERT_EQ(comp_buf[0], expected_rule_id, "rule_id");
	ASSERT_MEM_EQ(comp_buf, expected, exp_len, "compress output");

	/* Test decompression */
	int m = lichen_schc_decompress(expected, exp_len, decomp_buf, sizeof(decomp_buf));
	ASSERT_EQ(m, (int)pkt_len, "decompress length");
	ASSERT_MEM_EQ(decomp_buf, packet, pkt_len, "decompress output");

	return 1;
}

/* ─── test vectors (from test/vectors/schc_compression.json) ─────────────── */

static int test_coap_linklocal(void)
{
	return round_trip(
		/* IPv6 + UDP + CoAP link-local packet */
		"6000000000131140fe800000000000000000000000000001"
		"fe80000000000000000000000000000216331633001328dd"
		"40011234ff737461747573",
		/* Expected compressed */
		"00400000000000000001000000000000000216331633000448d0"
		"ff737461747573",
		0 /* SCHC_RULE_LINK_LOCAL_COAP */
	);
}

static int test_coap_global(void)
{
	return round_trip(
		/* IPv6 + UDP + CoAP global packet */
		"600000000013114020010db8000000000000000000000001"
		"20010db800000000000000000000000216331633001"
		"3ca6c40011234ff737461747573",
		/* Expected compressed */
		"014020010db800000000000000000000000120010db8000000"
		"00000000000000000216331633000448d0ff737461747573",
		1 /* SCHC_RULE_GLOBAL_COAP */
	);
}

static int test_icmpv6_echo(void)
{
	return round_trip(
		/* IPv6 + ICMPv6 Echo Request link-local */
		"60000000000c3a40fe800000000000000000000000000001"
		"fe8000000000000000000000000000028000f80eabcd0007"
		"70696e67",
		/* Expected compressed */
		"02400000000000000001000000000000000280abcd0007"
		"70696e67",
		2 /* SCHC_RULE_ICMPV6_ECHO */
	);
}

static int test_rpl_dio(void)
{
	return round_trip(
		/* IPv6 + ICMPv6 RPL DIO */
		"60000000001c3a40fe800000000000000000000000000001"
		"fe8000000000000000000000000000029b01e01f00010100"
		"88000000fe800000000000000000000000000001",
		/* Expected compressed */
		"034000000000000000010000000000000002000101008800"
		"fe800000000000000000000000000001",
		3 /* SCHC_RULE_RPL_DIO */
	);
}

static int test_rpl_dao(void)
{
	return round_trip(
		/* RPL DAO with routable ULA source (multi-hop model) */
		"6000000000183a40fd000db8000000000000000000000001"
		"fd000db80000000000000000000000029b02443700400005"
		"fd000db8000000000000000000000001",
		/* Expected compressed per updated vector */
		"0440fd000db8000000000000000000000001fd000db8000000000000000000000002004005"
		"fd000db8000000000000000000000001",
		4 /* SCHC_RULE_RPL_DAO */
	);
}

static int test_oscore_linklocal(void)
{
	return round_trip(
		/* IPv6 + UDP + OSCORE-protected CoAP link-local (rule 5) */
		"6000000000161140fe800000000000000000000000000001"
		"fe800000000000000000000000000002163316330016517b42"
		"0112340001920900ffdeadbeef",
		/* Expected compressed */
		"05400000000000000001000000000000000216331633080448d0"
		"0001920900ffdeadbeef",
		5 /* SCHC_RULE_LINK_LOCAL_OSCORE */
	);
}

static int test_oscore_global(void)
{
	return round_trip(
		/* IPv6 + UDP + OSCORE-protected CoAP global (rule 6) */
		"600000000016114020010db8000000000000000000000001"
		"20010db8000000000000000000000002163316330016f30a42"
		"0112340001920900ffdeadbeef",
		/* Expected compressed */
		"064020010db800000000000000000000000120010db8000000"
		"00000000000000000216331633080448d00001920900ffdeadbeef",
		6 /* SCHC_RULE_GLOBAL_OSCORE */
	);
}

static int test_uncompressed_fallback(void)
{
	uint8_t packet[4] = { 0xde, 0xad, 0xbe, 0xef };
	uint8_t comp_buf[8];
	uint8_t decomp_buf[8];

	int n = lichen_schc_compress(packet, 4, comp_buf, sizeof(comp_buf));
	if (n != 5) {
		printf("  FAIL: uncompressed length (got %d, expected 5)\n", n);
		return 0;
	}
	if (comp_buf[0] != 255) {
		printf("  FAIL: uncompressed rule_id (got %d, expected 255)\n", comp_buf[0]);
		return 0;
	}
	if (memcmp(&comp_buf[1], packet, 4) != 0) {
		printf("  FAIL: uncompressed payload mismatch\n");
		return 0;
	}

	int m = lichen_schc_decompress(comp_buf, n, decomp_buf, sizeof(decomp_buf));
	if (m != 4) {
		printf("  FAIL: uncompressed decompress length (got %d, expected 4)\n", m);
		return 0;
	}
	if (memcmp(decomp_buf, packet, 4) != 0) {
		printf("  FAIL: uncompressed decompress mismatch\n");
		return 0;
	}

	return 1;
}

static int test_unknown_rule_id(void)
{
	uint8_t data[5] = { 0x7e, 0xde, 0xad, 0xbe, 0xef };
	uint8_t out[64];

	int ret = lichen_schc_decompress(data, 5, out, sizeof(out));
	if (ret != SCHC_ERR_UNKNOWN_RULE_ID) {
		printf("  FAIL: expected SCHC_ERR_UNKNOWN_RULE_ID (got %d)\n", ret);
		return 0;
	}
	return 1;
}

static int test_truncated_coap_linklocal(void)
{
	/* Rule 0 (link-local CoAP) needs at least 26 bytes (1 rule + 25 residue).
	 * Verify truncated packets are rejected with SCHC_ERR_TOO_SHORT. */
	uint8_t data[25] = { 0 }; /* rule_id=0, plus 24 bytes (1 short) */
	uint8_t out[64];

	int ret = lichen_schc_decompress(data, sizeof(data), out, sizeof(out));
	if (ret != SCHC_ERR_TOO_SHORT) {
		printf("  FAIL: expected SCHC_ERR_TOO_SHORT for 25-byte input (got %d)\n", ret);
		return 0;
	}
	return 1;
}

static int test_truncated_coap_global(void)
{
	/* Rule 1 (global CoAP) needs at least 42 bytes (1 rule + 41 residue).
	 * Verify truncated packets are rejected with SCHC_ERR_TOO_SHORT. */
	uint8_t data[41] = { 1 }; /* rule_id=1, plus 40 bytes (1 short) */
	uint8_t out[64];

	int ret = lichen_schc_decompress(data, sizeof(data), out, sizeof(out));
	if (ret != SCHC_ERR_TOO_SHORT) {
		printf("  FAIL: expected SCHC_ERR_TOO_SHORT for 41-byte input (got %d)\n", ret);
		return 0;
	}
	return 1;
}

static int test_null_public_args(void)
{
	uint8_t packet[40] = { 0x60 };
	uint8_t data[1] = { SCHC_RULE_UNCOMPRESSED };
	uint8_t out[64];
	volatile uint8_t *null_ptr = NULL;
	int ret;

	ret = lichen_schc_compress((const uint8_t *)null_ptr,
				    sizeof(packet), out, sizeof(out));
	if (ret != SCHC_ERR_INVALID_ARGUMENT) {
		printf("  FAIL: compress NULL packet expected SCHC_ERR_INVALID_ARGUMENT (got %d)\n", ret);
		return 0;
	}

	ret = lichen_schc_compress(packet, sizeof(packet),
				    (uint8_t *)null_ptr, sizeof(out));
	if (ret != SCHC_ERR_BUFFER_TOO_SMALL) {
		printf("  FAIL: compress NULL out expected SCHC_ERR_BUFFER_TOO_SMALL (got %d)\n", ret);
		return 0;
	}

	ret = lichen_schc_decompress((const uint8_t *)null_ptr,
				      sizeof(data), out, sizeof(out));
	if (ret != SCHC_ERR_TOO_SHORT) {
		printf("  FAIL: decompress NULL data expected SCHC_ERR_TOO_SHORT (got %d)\n", ret);
		return 0;
	}

	ret = lichen_schc_decompress(data, sizeof(data),
				      (uint8_t *)null_ptr, sizeof(out));
	if (ret != SCHC_ERR_BUFFER_TOO_SMALL) {
		printf("  FAIL: decompress NULL out expected SCHC_ERR_BUFFER_TOO_SMALL (got %d)\n", ret);
		return 0;
	}

	return 1;
}

static int test_reject_bad_ipv6_payload_len(void)
{
	uint8_t packet[1500];
	uint8_t comp_buf[1500];
	size_t pkt_len = hex_decode(
		"6000000000131140fe800000000000000000000000000001"
		"fe80000000000000000000000000000216331633001328dd"
		"40011234ff737461747573",
		packet, sizeof(packet));

	if (pkt_len == 0) {
		printf("  FAIL: hex decode error\n");
		return 0;
	}

	packet[5]--; /* IPv6 Payload Length no longer matches pkt_len. */

	int ret = lichen_schc_compress(packet, pkt_len, comp_buf, sizeof(comp_buf));
	if (ret != SCHC_ERR_NO_MATCHING_RULE) {
		printf("  FAIL: bad IPv6 Payload Length expected SCHC_ERR_NO_MATCHING_RULE (got %d)\n",
		       ret);
		return 0;
	}

	return 1;
}

static int test_reject_bad_udp_len(void)
{
	uint8_t packet[1500];
	uint8_t comp_buf[1500];
	size_t pkt_len = hex_decode(
		"6000000000131140fe800000000000000000000000000001"
		"fe80000000000000000000000000000216331633001328dd"
		"40011234ff737461747573",
		packet, sizeof(packet));

	if (pkt_len == 0) {
		printf("  FAIL: hex decode error\n");
		return 0;
	}

	packet[45]--; /* UDP Length no longer matches the IPv6 payload length. */

	int ret = lichen_schc_compress(packet, pkt_len, comp_buf, sizeof(comp_buf));
	if (ret != SCHC_ERR_NO_MATCHING_RULE) {
		printf("  FAIL: bad UDP Length expected SCHC_ERR_NO_MATCHING_RULE (got %d)\n",
		       ret);
		return 0;
	}

	return 1;
}

static int test_uncompressed_length_exceeds_int(void)
{
	static const uint8_t packet = 0;
	volatile size_t pkt_len = (size_t)INT_MAX;
	uint8_t out;
	int ret = lichen_schc_compress(&packet, pkt_len, &out, SIZE_MAX);

	ASSERT_EQ(ret, SCHC_ERR_BUFFER_TOO_SMALL, "uncompressed int length overflow");
	return 1;
}

/* ─── test runner ─────────────────────────────────────────────────────────── */

#define RUN_TEST(fn) do { \
	printf("  %s...", #fn); \
	tests_run++; \
	if (fn()) { \
		printf(" OK\n"); \
		tests_passed++; \
	} \
} while (0)

int main(void)
{
	printf("SCHC Round-Trip Tests\n");
	printf("=====================\n\n");

	RUN_TEST(test_coap_linklocal);
	RUN_TEST(test_coap_global);
	RUN_TEST(test_icmpv6_echo);
	RUN_TEST(test_rpl_dio);
	RUN_TEST(test_rpl_dao);
	RUN_TEST(test_oscore_linklocal);
	RUN_TEST(test_oscore_global);
	RUN_TEST(test_uncompressed_fallback);
	RUN_TEST(test_unknown_rule_id);
	RUN_TEST(test_truncated_coap_linklocal);
	RUN_TEST(test_truncated_coap_global);
	RUN_TEST(test_null_public_args);
	RUN_TEST(test_reject_bad_ipv6_payload_len);
	RUN_TEST(test_reject_bad_udp_len);
	RUN_TEST(test_uncompressed_length_exceeds_int);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
