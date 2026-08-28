/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief LICHEN ICMPv6 unit tests
 */

#include <zephyr/ztest.h>

#include "icmpv6.h"
#include "ipv6_addr.h"

#include <string.h>

/* Test link-local addresses */
static const struct in6_addr test_src = {
    .s6_addr = {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
};

static const struct in6_addr test_dst = {
    .s6_addr = {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
};

static void make_invoking_packet(uint8_t *packet, size_t packet_len, const struct in6_addr *src,
				 const struct in6_addr *dst, uint8_t next_header)
{
	size_t payload_len = packet_len - LICHEN_IPV6_HEADER_LEN;

	memset(packet, 0, packet_len);
	packet[0] = 0x60;
	packet[4] = (uint8_t)(payload_len >> 8);
	packet[5] = (uint8_t)payload_len;
	packet[6] = next_header;
	packet[7] = 64;
	memcpy(&packet[8], src->s6_addr, 16);
	memcpy(&packet[24], dst->s6_addr, 16);
}

static uint8_t hex_nibble(char value)
{
	if (value >= '0' && value <= '9') {
		return (uint8_t)(value - '0');
	}
	if (value >= 'a' && value <= 'f') {
		return (uint8_t)(value - 'a' + 10);
	}
	return UINT8_MAX;
}

static bool decode_hex(const char *hex, uint8_t *out, size_t out_len)
{
	for (size_t i = 0; i < out_len; ++i) {
		uint8_t high = hex_nibble(hex[2U * i]);
		uint8_t low = hex_nibble(hex[2U * i + 1U]);

		if (high == UINT8_MAX || low == UINT8_MAX) {
			return false;
		}
		out[i] = (uint8_t)((high << 4) | low);
	}

	return hex[2U * out_len] == '\0';
}

static void set_icmpv6_checksum(const struct in6_addr *src, const struct in6_addr *dst,
				uint8_t *icmpv6, size_t icmpv6_len)
{
	uint16_t checksum;

	icmpv6[2] = 0;
	icmpv6[3] = 0;
	checksum = lichen_icmpv6_checksum(src, dst, icmpv6, icmpv6_len);
	icmpv6[2] = (uint8_t)(checksum >> 8);
	icmpv6[3] = (uint8_t)checksum;
}

/**
 * Test basic Internet checksum calculation.
 */
ZTEST(icmpv6, test_internet_checksum_basic)
{
    /* RFC 1071 example: 00 01 F2 03 F4 F5 F6 F7 = checksum 220D */
    const uint8_t data[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    uint16_t checksum = lichen_internet_checksum(data, sizeof(data));
    zassert_equal(checksum, 0x220d, "RFC 1071 checksum mismatch: 0x%04x", checksum);
}

/**
 * Test checksum with odd-length data.
 */
ZTEST(icmpv6, test_internet_checksum_odd_length)
{
    const uint8_t data[] = {0x00, 0x01, 0x02};
    uint16_t checksum = lichen_internet_checksum(data, sizeof(data));
    /* Padded with 0x00: 0x0001 + 0x0200 = 0x0201, ~0x0201 = 0xFDFE */
    zassert_equal(checksum, 0xfdfe, "Odd-length checksum mismatch: 0x%04x", checksum);
}

/**
 * Test building an Echo Request packet.
 */
ZTEST(icmpv6, test_build_echo_request)
{
    uint8_t buf[64];
    const uint8_t ping_data[] = "ping";
    int ret;

    ret = lichen_icmpv6_build_echo_request(&test_src, &test_dst,
                                           0x1234, 7,
                                           ping_data, sizeof(ping_data) - 1,
                                           buf, sizeof(buf));

    /* Expected: 40 (IPv6) + 8 (echo header) + 4 (data) = 52 bytes */
    zassert_equal(ret, 52, "Unexpected packet length: %d", ret);

    /* Check IPv6 header */
    zassert_equal(buf[0] >> 4, 6, "IPv6 version wrong");
    zassert_equal(buf[6], LICHEN_ICMPV6_NEXT_HEADER, "Next header wrong");
    zassert_equal(buf[7], 64, "Hop limit wrong");
    zassert_mem_equal(&buf[8], test_src.s6_addr, 16, "Source address mismatch");
    zassert_mem_equal(&buf[24], test_dst.s6_addr, 16, "Dest address mismatch");

    /* Check ICMPv6 header */
    zassert_equal(buf[40], LICHEN_ICMPV6_ECHO_REQUEST, "Type wrong");
    zassert_equal(buf[41], 0, "Code wrong");

    /* Check echo fields */
    zassert_equal((buf[44] << 8) | buf[45], 0x1234, "Identifier wrong");
    zassert_equal((buf[46] << 8) | buf[47], 7, "Sequence wrong");

    /* Check data */
    zassert_mem_equal(&buf[48], "ping", 4, "Data mismatch");
}

/**
 * Test building an Echo Reply packet.
 */
ZTEST(icmpv6, test_build_echo_reply)
{
    uint8_t buf[64];
    int ret;

    ret = lichen_icmpv6_build_echo_reply(&test_src, &test_dst,
                                         0xabcd, 42,
                                         NULL, 0,
                                         buf, sizeof(buf));

    /* Expected: 40 (IPv6) + 8 (echo header) = 48 bytes */
    zassert_equal(ret, 48, "Unexpected packet length: %d", ret);
    zassert_equal(buf[40], LICHEN_ICMPV6_ECHO_REPLY, "Type wrong");
    zassert_equal((buf[44] << 8) | buf[45], 0xabcd, "Identifier wrong");
    zassert_equal((buf[46] << 8) | buf[47], 42, "Sequence wrong");
}

ZTEST(icmpv6, test_echo_request_reply_match_shared_vectors)
{
	static const char request_hex[] = "60000000000c3a40fe800000000000000000000000000001"
					  "fe800000000000000000000000000002800088a51234000174657374";
	static const char reply_hex[] = "60000000000c3a40fe800000000000000000000000000002"
					"fe800000000000000000000000000001810087a51234000174657374";
	static const char ygg_hex[] = "6000000000113a400200389e777ace07c7d6ca08166ecd20"
				      "0200514acffcfa9dea90556802586d378000ec65abcd002a"
				      "68656c6c6f20796767";
	const struct in6_addr ygg_src = {.s6_addr = {0x02, 0x00, 0x38, 0x9e, 0x77, 0x7a, 0xce,
						     0x07, 0xc7, 0xd6, 0xca, 0x08, 0x16, 0x6e,
						     0xcd, 0x20}};
	const struct in6_addr ygg_dst = {.s6_addr = {0x02, 0x00, 0x51, 0x4a, 0xcf, 0xfc, 0xfa,
						     0x9d, 0xea, 0x90, 0x55, 0x68, 0x02, 0x58,
						     0x6d, 0x37}};
	uint8_t expected[(sizeof(request_hex) - 1U) / 2U];
	uint8_t ygg_expected[(sizeof(ygg_hex) - 1U) / 2U];
	uint8_t actual[sizeof(ygg_expected)];
	int ret;

	zassert_true(decode_hex(request_hex, expected, sizeof(expected)));
	ret = lichen_icmpv6_build_echo_request(&test_src, &test_dst, 0x1234, 1,
					      (const uint8_t *)"test", 4U, actual,
					      sizeof(actual));
	zassert_equal(ret, (int)sizeof(expected));
	zassert_mem_equal(actual, expected, sizeof(expected));

	zassert_true(decode_hex(reply_hex, expected, sizeof(expected)));
	ret = lichen_icmpv6_build_echo_reply(&test_dst, &test_src, 0x1234, 1,
					    (const uint8_t *)"test", 4U, actual,
					    sizeof(expected));
	zassert_equal(ret, (int)sizeof(expected));
	zassert_mem_equal(actual, expected, sizeof(expected));

	zassert_true(decode_hex(ygg_hex, ygg_expected, sizeof(ygg_expected)));
	ret = lichen_icmpv6_build_echo_request(&ygg_src, &ygg_dst, 0xabcd, 42,
					      (const uint8_t *)"hello ygg", 9U, actual,
					      sizeof(actual));
	zassert_equal(ret, (int)sizeof(ygg_expected));
	zassert_mem_equal(actual, ygg_expected, sizeof(ygg_expected));
}

ZTEST(icmpv6, test_echo_payload_and_output_boundaries)
{
	static uint8_t data[UINT16_MAX - LICHEN_ICMPV6_ECHO_HEADER_LEN];
	static uint8_t out[LICHEN_IPV6_HEADER_LEN + UINT16_MAX + 1U];
	const size_t total_len = LICHEN_IPV6_HEADER_LEN + UINT16_MAX;
	int ret;

	memset(data, 0x5c, sizeof(data));
	memset(out, 0xa5, sizeof(out));
	ret = lichen_icmpv6_build_echo_request(&test_src, &test_dst, UINT16_MAX, UINT16_MAX,
					      data, sizeof(data), out, sizeof(out));
	zassert_equal(ret, (int)total_len);
	zassert_equal(((uint16_t)out[4] << 8) | out[5], UINT16_MAX);
	zassert_equal(out[40], LICHEN_ICMPV6_ECHO_REQUEST);
	zassert_equal(out[41], 0);
	zassert_mem_equal(&out[44], "\xff\xff\xff\xff", 4U);
	zassert_mem_equal(&out[48], data, sizeof(data));
	zassert_equal(out[total_len], 0xa5);
	zassert_true(lichen_icmpv6_verify_checksum(&test_src, &test_dst, &out[40], UINT16_MAX));

	memset(out, 0x6d, sizeof(out));
	zassert_equal(lichen_icmpv6_build_echo_request(&test_src, &test_dst, 0, 0, data,
						      sizeof(data), out, total_len - 1U),
		      0);
	for (size_t i = 0; i < sizeof(out); ++i) {
		zassert_equal(out[i], 0x6d, "short-buffer failure mutated byte %zu", i);
	}

	zassert_equal(lichen_icmpv6_build_echo_request(
			      &test_src, &test_dst, 0, 0, data,
			      (size_t)UINT16_MAX - LICHEN_ICMPV6_ECHO_HEADER_LEN + 1U, out,
			      sizeof(out)),
		      -EMSGSIZE);
	for (size_t i = 0; i < sizeof(out); ++i) {
		zassert_equal(out[i], 0x6d, "oversized-input failure mutated byte %zu", i);
	}
	zassert_equal(lichen_icmpv6_build_echo_request(&test_src, &test_dst, 0, 0, data, SIZE_MAX,
						      out, sizeof(out)),
		      -EMSGSIZE);
	for (size_t i = 0; i < sizeof(out); ++i) {
		zassert_equal(out[i], 0x6d, "overflow-input failure mutated byte %zu", i);
	}
}

ZTEST(icmpv6, test_echo_builder_rejects_invalid_addresses_without_mutation)
{
	struct in6_addr unspecified = {0};
	struct in6_addr multicast = {.s6_addr = {0xff, 0x02, 0, 0, 0, 0, 0, 0,
							 0, 0, 0, 0, 0, 0, 0, 1}};
	uint8_t out[64];
	uint8_t pristine[sizeof(out)];

	memset(pristine, 0x3a, sizeof(pristine));

#define ASSERT_ECHO_BUILD_REJECTED(call, expected)                                                \
	do {                                                                                         \
		memcpy(out, pristine, sizeof(out));                                                    \
		zassert_equal(call, expected);                                                        \
		zassert_mem_equal(out, pristine, sizeof(out));                                         \
	} while (false)

	ASSERT_ECHO_BUILD_REJECTED(lichen_icmpv6_build_echo_request(
					   &unspecified, &test_dst, 0, 0, NULL, 0, out, sizeof(out)),
				   -EINVAL);
	ASSERT_ECHO_BUILD_REJECTED(lichen_icmpv6_build_echo_request(
					   &multicast, &test_dst, 0, 0, NULL, 0, out, sizeof(out)),
				   -EINVAL);
	ASSERT_ECHO_BUILD_REJECTED(lichen_icmpv6_build_echo_request(
					   &test_src, &unspecified, 0, 0, NULL, 0, out, sizeof(out)),
				   -EINVAL);
	ASSERT_ECHO_BUILD_REJECTED(lichen_icmpv6_build_echo_reply(
					   &test_src, &multicast, 0, 0, NULL, 0, out, sizeof(out)),
				   -EINVAL);
	ASSERT_ECHO_BUILD_REJECTED(lichen_icmpv6_build_echo_request(
					   &test_src, &test_dst, 0, 0, NULL, 1U, out, sizeof(out)),
				   -EINVAL);
	ASSERT_ECHO_BUILD_REJECTED(lichen_icmpv6_build_echo_request(
					   &test_src, &test_dst, 0, 0, NULL, 0, NULL, sizeof(out)),
				   -EINVAL);

	/* Multicast is a legal Echo Request destination; handling needs a unicast reply source. */
	zassert_true(lichen_icmpv6_build_echo_request(&test_src, &multicast, 0, 0, NULL, 0, out,
						     sizeof(out)) > 0);

#undef ASSERT_ECHO_BUILD_REJECTED
}

/**
 * Test buffer too small returns 0.
 */
ZTEST(icmpv6, test_build_echo_buffer_too_small)
{
    uint8_t buf[47]; /* One byte short of minimum */
    int ret;

    ret = lichen_icmpv6_build_echo_request(&test_src, &test_dst,
                                           0x1234, 1,
                                           NULL, 0,
                                           buf, sizeof(buf));

    zassert_equal(ret, 0, "Should return 0 for small buffer: %d", ret);
}

/**
 * Test checksum verification passes for valid packet.
 */
ZTEST(icmpv6, test_checksum_verification_valid)
{
    uint8_t buf[64];
    int ret;
    bool valid;

    ret = lichen_icmpv6_build_echo_request(&test_src, &test_dst,
                                           0x1234, 1,
                                           NULL, 0,
                                           buf, sizeof(buf));
    zassert_true(ret > 0, "Build failed");

    /* Verify checksum on the ICMPv6 portion */
    valid = lichen_icmpv6_verify_checksum(&test_src, &test_dst,
                                          &buf[40], ret - 40);
    zassert_true(valid, "Valid checksum rejected");
}

/**
 * Test checksum verification fails for corrupted packet.
 */
ZTEST(icmpv6, test_checksum_verification_invalid)
{
    uint8_t buf[64];
    int ret;
    bool valid;

    ret = lichen_icmpv6_build_echo_request(&test_src, &test_dst,
                                           0x1234, 1,
                                           NULL, 0,
                                           buf, sizeof(buf));
    zassert_true(ret > 0, "Build failed");

    /* Corrupt a byte in the ICMPv6 portion */
    buf[44] ^= 0x01;

    valid = lichen_icmpv6_verify_checksum(&test_src, &test_dst,
                                          &buf[40], ret - 40);
    zassert_false(valid, "Corrupted checksum should fail");
}

/**
 * Test parsing an Echo Request.
 */
ZTEST(icmpv6, test_parse_echo_request)
{
    uint8_t buf[64];
    struct lichen_icmpv6_msg msg;
    struct lichen_icmpv6_echo echo;
    const uint8_t data[] = "test";
    int ret;

    ret = lichen_icmpv6_build_echo_request(&test_src, &test_dst,
                                           0x5678, 99,
                                           data, sizeof(data) - 1,
                                           buf, sizeof(buf));
    zassert_true(ret > 0, "Build failed");

    ret = lichen_icmpv6_parse(&buf[40], ret - 40, &msg);
    zassert_equal(ret, 0, "Parse failed: %d", ret);
    zassert_equal(msg.type, LICHEN_ICMPV6_ECHO_REQUEST, "Type wrong");
    zassert_equal(msg.code, 0, "Code wrong");

    ret = lichen_icmpv6_parse_echo(&msg, &echo);
    zassert_equal(ret, 0, "Echo parse failed: %d", ret);
    zassert_equal(echo.identifier, 0x5678, "Identifier wrong");
    zassert_equal(echo.sequence, 99, "Sequence wrong");
    zassert_equal(echo.data_len, 4, "Data length wrong");
    zassert_mem_equal(echo.data, "test", 4, "Data mismatch");
}

/**
 * Test parsing fails for truncated message.
 */
ZTEST(icmpv6, test_parse_truncated)
{
    const uint8_t short_data[] = {0x80, 0x00, 0x00}; /* 3 bytes, need 4 minimum */
    struct lichen_icmpv6_msg msg;
    int ret;

    ret = lichen_icmpv6_parse(short_data, sizeof(short_data), &msg);
    zassert_equal(ret, -EINVAL, "Should fail for truncated: %d", ret);
}

/**
 * Test parsing echo fails for wrong type.
 */
ZTEST(icmpv6, test_parse_echo_wrong_type)
{
    struct lichen_icmpv6_msg msg = {
        .type = LICHEN_ICMPV6_DEST_UNREACHABLE,
        .code = 0,
        .body = NULL,
        .body_len = 0
    };
    struct lichen_icmpv6_echo echo;
    int ret;

    ret = lichen_icmpv6_parse_echo(&msg, &echo);
    zassert_equal(ret, -EINVAL, "Should fail for wrong type: %d", ret);
}

ZTEST(icmpv6, test_parse_echo_rejects_nonzero_code_and_malformed_body_without_mutation)
{
	const uint8_t body[4] = {0x12, 0x34, 0x56, 0x78};
	struct lichen_icmpv6_msg msg = {
		.type = LICHEN_ICMPV6_ECHO_REQUEST,
		.code = 1,
		.body = body,
		.body_len = sizeof(body),
	};
	struct lichen_icmpv6_echo echo;
	struct lichen_icmpv6_echo pristine;

	memset(&pristine, 0x5d, sizeof(pristine));
	echo = pristine;
	zassert_equal(lichen_icmpv6_parse_echo(&msg, &echo), -EINVAL);
	zassert_mem_equal(&echo, &pristine, sizeof(echo));

	msg.code = 0;
	msg.body = NULL;
	echo = pristine;
	zassert_equal(lichen_icmpv6_parse_echo(&msg, &echo), -EINVAL);
	zassert_mem_equal(&echo, &pristine, sizeof(echo));

	msg.body = body;
	msg.body_len = 3U;
	echo = pristine;
	zassert_equal(lichen_icmpv6_parse_echo(&msg, &echo), -EINVAL);
	zassert_mem_equal(&echo, &pristine, sizeof(echo));
}

/**
 * Test building Destination Unreachable.
 */
ZTEST(icmpv6, test_build_dest_unreachable)
{
    uint8_t buf[128];
    uint8_t invoking[48];
    int ret;

    make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);

    ret = lichen_icmpv6_build_dest_unreachable(&test_src, &test_dst, LICHEN_ICMPV6_PORT_UNREACHABLE,
					       invoking, sizeof(invoking),
					       LICHEN_ICMPV6_INVOKING_UNICAST, buf, sizeof(buf));

    /* Expected: 40 (IPv6) + 8 (ICMPv6 header) + 48 (invoking) = 96 bytes */
    zassert_equal(ret, 96, "Unexpected length: %d", ret);
    zassert_equal(buf[40], LICHEN_ICMPV6_DEST_UNREACHABLE, "Type wrong");
    zassert_equal(buf[41], LICHEN_ICMPV6_PORT_UNREACHABLE, "Code wrong");
    /* Rest of header should be zero */
    zassert_equal(buf[44], 0, "Rest of header[0] not zero");
    zassert_equal(buf[45], 0, "Rest of header[1] not zero");
    zassert_equal(buf[46], 0, "Rest of header[2] not zero");
    zassert_equal(buf[47], 0, "Rest of header[3] not zero");
    /* Invoking packet follows */
    zassert_mem_equal(&buf[48], invoking, sizeof(invoking), "Invoking mismatch");
    zassert_true(lichen_icmpv6_verify_checksum(&test_src, &test_dst, &buf[40], (size_t)ret - 40U),
		 "Destination Unreachable checksum invalid");
}

ZTEST(icmpv6, test_dest_unreachable_matches_shared_vector)
{
	static const char invoking_hex[] = "60000000001911400200389e777ace07c7d6ca08166ecd20"
					   "0200514acffcfa9dea90556802586d371633163300193098"
					   "7061796c6f616420666f72206572726f72";
	static const char port_expected_hex[] = "6000000000493a400200514acffcfa9dea90556802586d37"
						"0200389e777ace07c7d6ca08166ecd200104ca4c00000000"
						"60000000001911400200389e777ace07c7d6ca08166ecd20"
						"0200514acffcfa9dea90556802586d371633163300193098"
						"7061796c6f616420666f72206572726f72";
	static const char no_route_expected_hex[] =
		"6000000000493a400200514acffcfa9dea90556802586d37"
		"0200389e777ace07c7d6ca08166ecd200100ca5000000000"
		"60000000001911400200389e777ace07c7d6ca08166ecd20"
		"0200514acffcfa9dea90556802586d371633163300193098"
		"7061796c6f616420666f72206572726f72";
	const struct in6_addr src = {.s6_addr = {0x02, 0x00, 0x51, 0x4a, 0xcf, 0xfc, 0xfa, 0x9d,
						 0xea, 0x90, 0x55, 0x68, 0x02, 0x58, 0x6d, 0x37}};
	const struct in6_addr dst = {.s6_addr = {0x02, 0x00, 0x38, 0x9e, 0x77, 0x7a, 0xce, 0x07,
						 0xc7, 0xd6, 0xca, 0x08, 0x16, 0x6e, 0xcd, 0x20}};
	uint8_t invoking[(sizeof(invoking_hex) - 1U) / 2U];
	uint8_t expected[(sizeof(port_expected_hex) - 1U) / 2U];
	uint8_t actual[sizeof(expected)];
	int ret;

	zassert_true(decode_hex(invoking_hex, invoking, sizeof(invoking)));
	zassert_true(decode_hex(port_expected_hex, expected, sizeof(expected)));
	ret = lichen_icmpv6_build_dest_unreachable(
		&src, &dst, LICHEN_ICMPV6_PORT_UNREACHABLE, invoking, sizeof(invoking),
		LICHEN_ICMPV6_INVOKING_UNICAST, actual, sizeof(actual));

	zassert_equal(ret, (int)sizeof(expected));
	zassert_mem_equal(actual, expected, sizeof(expected));

	zassert_true(decode_hex(no_route_expected_hex, expected, sizeof(expected)));
	ret = lichen_icmpv6_build_dest_unreachable(&src, &dst, LICHEN_ICMPV6_NO_ROUTE, invoking,
						   sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST,
						   actual, sizeof(actual));
	zassert_equal(ret, (int)sizeof(expected));
	zassert_mem_equal(actual, expected, sizeof(expected));
}

ZTEST(icmpv6, test_dest_unreachable_all_rfc4443_codes)
{
	uint8_t invoking[48];
	uint8_t buf[sizeof(invoking) + 48U];

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);
	for (unsigned int code = LICHEN_ICMPV6_NO_ROUTE; code <= LICHEN_ICMPV6_REJECT_ROUTE;
	     ++code) {
		int ret = lichen_icmpv6_build_dest_unreachable(
			&test_src, &test_dst, (enum lichen_icmpv6_dest_unreach_code)code, invoking,
			sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, buf, sizeof(buf));

		zassert_equal(ret, (int)sizeof(buf), "code %u failed", code);
		zassert_equal(buf[40], LICHEN_ICMPV6_DEST_UNREACHABLE);
		zassert_equal(buf[41], code);
		zassert_mem_equal(&buf[44], "\0\0\0\0", 4);
		zassert_true(lichen_icmpv6_verify_checksum(&test_src, &test_dst, &buf[40],
							   sizeof(buf) - 40U));
	}
}

ZTEST(icmpv6, test_dest_unreachable_rfc4443_suppression)
{
	uint8_t invoking[48];
	uint8_t out[sizeof(invoking) + 48U];
	uint8_t pristine[sizeof(out)];

	memset(pristine, 0xa5, sizeof(pristine));
	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src,
			     LICHEN_ICMPV6_NEXT_HEADER);
	invoking[40] = LICHEN_ICMPV6_DEST_UNREACHABLE;

	const uint8_t flags[] = {
		LICHEN_ICMPV6_INVOKING_LINK_MULTICAST,
		LICHEN_ICMPV6_INVOKING_LINK_BROADCAST,
		LICHEN_ICMPV6_INVOKING_SOURCE_ANYCAST,
		LICHEN_ICMPV6_INVOKING_CONGESTION,
	};
	for (size_t i = 0; i < ARRAY_SIZE(flags); ++i) {
		memcpy(out, pristine, sizeof(out));
		zassert_equal(lichen_icmpv6_build_dest_unreachable(
				      &test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking,
				      sizeof(invoking), flags[i], out, sizeof(out)),
			      0);
		zassert_mem_equal(out, pristine, sizeof(out));
	}

	memcpy(out, pristine, sizeof(out));
	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "must suppress response to ICMPv6 error");
	zassert_mem_equal(out, pristine, sizeof(out));

	invoking[40] = 137U;
	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "must suppress response to Redirect");

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);
	invoking[24] = 0xff;
	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "must suppress multicast destination");

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);
	invoking[8] = 0xff;
	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "must suppress multicast source");

	memset(&invoking[8], 0, 16);
	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "must suppress unspecified source");
}

ZTEST(icmpv6, test_dest_unreachable_inspects_extension_headers_fail_closed)
{
	uint8_t invoking[56];
	uint8_t out[sizeof(invoking) + 48U];

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 0);
	invoking[40] = LICHEN_ICMPV6_NEXT_HEADER;
	invoking[41] = 0;
	invoking[48] = LICHEN_ICMPV6_DEST_UNREACHABLE;
	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "ICMPv6 error behind Hop-by-Hop header must be suppressed");

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 44);
	invoking[40] = 17;
	invoking[42] = 0;
	invoking[43] = 8;
	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "non-initial fragment must fail closed");

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 50);
	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "uninspectable ESP payload must fail closed");

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 0);
	invoking[40] = LICHEN_ICMPV6_NEXT_HEADER;
	invoking[41] = 2;
	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      -EINVAL, "truncated extension header must be rejected");
}

ZTEST(icmpv6, test_dest_unreachable_rejects_malformed_input_without_mutation)
{
	uint8_t invoking[48];
	uint8_t out[sizeof(invoking) + 48U];
	uint8_t pristine[sizeof(out)];

	memset(pristine, 0x3c, sizeof(pristine));
	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);

	memcpy(out, pristine, sizeof(out));
	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_dst, (enum lichen_icmpv6_dest_unreach_code)7,
			      invoking, sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out,
			      sizeof(out)),
		      -EINVAL);
	zassert_mem_equal(out, pristine, sizeof(out));

	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking, 39U,
			      LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      -EINVAL);
	invoking[0] = 0x40;
	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      -EINVAL);

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);
	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_src, LICHEN_ICMPV6_NO_ROUTE, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      -EINVAL, "reply destination must equal invoking source");
	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking,
			      sizeof(invoking), 0x80U, out, sizeof(out)),
		      -EINVAL, "unknown metadata flags must fail closed");
	zassert_equal(lichen_icmpv6_build_dest_unreachable(
			      &test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out,
			      sizeof(out) - 1U),
		      0, "short output buffer must not produce a partial packet");
	zassert_mem_equal(out, pristine, sizeof(out));
}

ZTEST(icmpv6, test_packet_too_big_matches_shared_vector)
{
	static const char invoking_hex[] = "60000000001911400200389e777ace07c7d6ca08166ecd20"
					   "0200514acffcfa9dea90556802586d371633163300193098"
					   "7061796c6f616420666f72206572726f72";
	static const char expected_hex[] = "6000000000493a400200514acffcfa9dea90556802586d37"
					   "0200389e777ace07c7d6ca08166ecd200200c45000000500"
					   "60000000001911400200389e777ace07c7d6ca08166ecd20"
					   "0200514acffcfa9dea90556802586d371633163300193098"
					   "7061796c6f616420666f72206572726f72";
	const struct in6_addr src = {.s6_addr = {0x02, 0x00, 0x51, 0x4a, 0xcf, 0xfc, 0xfa, 0x9d,
						 0xea, 0x90, 0x55, 0x68, 0x02, 0x58, 0x6d, 0x37}};
	const struct in6_addr dst = {.s6_addr = {0x02, 0x00, 0x38, 0x9e, 0x77, 0x7a, 0xce, 0x07,
						 0xc7, 0xd6, 0xca, 0x08, 0x16, 0x6e, 0xcd, 0x20}};
	uint8_t invoking[(sizeof(invoking_hex) - 1U) / 2U];
	uint8_t expected[(sizeof(expected_hex) - 1U) / 2U];
	uint8_t actual[sizeof(expected)];
	int ret;

	zassert_true(decode_hex(invoking_hex, invoking, sizeof(invoking)));
	zassert_true(decode_hex(expected_hex, expected, sizeof(expected)));
	ret = lichen_icmpv6_build_packet_too_big(&src, &dst, LICHEN_IPV6_MIN_MTU, invoking,
						 sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST,
						 actual, sizeof(actual));

	zassert_equal(ret, (int)sizeof(expected));
	zassert_mem_equal(actual, expected, sizeof(expected));
	zassert_true(lichen_icmpv6_verify_checksum(&src, &dst, &actual[40], sizeof(actual) - 40U));
}

ZTEST(icmpv6, test_packet_too_big_quote_and_output_boundaries)
{
	static uint8_t invoking[LICHEN_ICMPV6_MAX_INVOKING_PACKET + 1U];
	static uint8_t out[LICHEN_IPV6_MIN_MTU + 1U];
	int ret;

	memset(invoking, 0x3c, sizeof(invoking));
	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);
	memset(out, 0xa5, sizeof(out));
	ret = lichen_icmpv6_build_packet_too_big(&test_src, &test_dst, UINT32_MAX, invoking,
						 sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST,
						 out, sizeof(out));

	zassert_equal(ret, LICHEN_IPV6_MIN_MTU);
	zassert_equal(((uint16_t)out[4] << 8) | out[5],
		      LICHEN_IPV6_MIN_MTU - LICHEN_IPV6_HEADER_LEN);
	zassert_mem_equal(&out[44], "\xff\xff\xff\xff", 4);
	zassert_mem_equal(&out[48], invoking, LICHEN_ICMPV6_MAX_INVOKING_PACKET);
	zassert_equal(out[LICHEN_IPV6_MIN_MTU], 0xa5, "builder overran the minimum-MTU packet");
	zassert_true(lichen_icmpv6_verify_checksum(&test_src, &test_dst, &out[40],
						   LICHEN_IPV6_MIN_MTU - LICHEN_IPV6_HEADER_LEN));

	memset(out, 0x6d, sizeof(out));
	zassert_equal(lichen_icmpv6_build_packet_too_big(
			  &test_src, &test_dst, LICHEN_IPV6_MIN_MTU, invoking,
			  LICHEN_ICMPV6_MAX_INVOKING_PACKET, LICHEN_ICMPV6_INVOKING_UNICAST, out,
			  LICHEN_IPV6_MIN_MTU - 1U),
		      0);
	for (size_t i = 0; i < sizeof(out); ++i) {
		zassert_equal(out[i], 0x6d, "short-buffer failure mutated byte %zu", i);
	}
}

ZTEST(icmpv6, test_packet_too_big_rfc4443_suppression_and_exceptions)
{
	uint8_t invoking[48];
	uint8_t out[sizeof(invoking) + 48U];
	uint8_t pristine[sizeof(out)];
	int ret;

	memset(pristine, 0x5a, sizeof(pristine));
	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);
	for (uint8_t flags = LICHEN_ICMPV6_INVOKING_LINK_MULTICAST;
	     flags <= LICHEN_ICMPV6_INVOKING_LINK_BROADCAST; ++flags) {
		ret = lichen_icmpv6_build_packet_too_big(&test_src, &test_dst, 1280, invoking,
							 sizeof(invoking), flags, out, sizeof(out));
		zassert_equal(ret, (int)sizeof(out), "PTB exception rejected link flags %u", flags);
	}

	invoking[24] = 0xff;
	ret = lichen_icmpv6_build_packet_too_big(
	    &test_src, &test_dst, 1280, invoking, sizeof(invoking),
	    LICHEN_ICMPV6_INVOKING_LINK_MULTICAST | LICHEN_ICMPV6_INVOKING_LINK_BROADCAST, out,
	    sizeof(out));
	zassert_equal(ret, (int)sizeof(out), "PTB must be allowed for multicast destinations");

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);
	const uint8_t source_suppression_flags[] = {
	    LICHEN_ICMPV6_INVOKING_SOURCE_ANYCAST,
	    LICHEN_ICMPV6_INVOKING_CONGESTION,
	};
	for (size_t i = 0; i < ARRAY_SIZE(source_suppression_flags); ++i) {
		memcpy(out, pristine, sizeof(out));
		ret = lichen_icmpv6_build_packet_too_big(
		    &test_src, &test_dst, 1280, invoking, sizeof(invoking),
		    source_suppression_flags[i], out, sizeof(out));
		zassert_equal(ret, 0);
		zassert_mem_equal(out, pristine, sizeof(out));
	}

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src,
			     LICHEN_ICMPV6_NEXT_HEADER);
	invoking[40] = LICHEN_ICMPV6_PACKET_TOO_BIG;
	memcpy(out, pristine, sizeof(out));
	ret = lichen_icmpv6_build_packet_too_big(&test_src, &test_dst, 1280, invoking,
						 sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST,
						 out, sizeof(out));
	zassert_equal(ret, 0);
	zassert_mem_equal(out, pristine, sizeof(out));

	invoking[40] = 137U;
	zassert_equal(lichen_icmpv6_build_packet_too_big(
			  &test_src, &test_dst, 1280, invoking, sizeof(invoking),
			  LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "PTB must not be sent in response to Redirect");

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);
	invoking[8] = 0xff;
	zassert_equal(lichen_icmpv6_build_packet_too_big(
			  &test_src, &test_dst, 1280, invoking, sizeof(invoking),
			  LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "multicast source must be suppressed");
	memset(&invoking[8], 0, 16);
	zassert_equal(lichen_icmpv6_build_packet_too_big(
			      &test_src, &test_dst, 1280, invoking, sizeof(invoking),
			      LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "unspecified source must be suppressed");

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 44);
	invoking[40] = 17;
	invoking[42] = 0;
	invoking[43] = 8;
	zassert_equal(lichen_icmpv6_build_packet_too_big(
			      &test_src, &test_dst, 1280, invoking, sizeof(invoking),
			      LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "non-initial fragment must fail closed");
	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 50);
	zassert_equal(lichen_icmpv6_build_packet_too_big(
			      &test_src, &test_dst, 1280, invoking, sizeof(invoking),
			      LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "uninspectable ESP packet must fail closed");
}

ZTEST(icmpv6, test_packet_too_big_rejects_malformed_input_without_mutation)
{
	uint8_t invoking[56];
	uint8_t out[sizeof(invoking) + 48U];
	uint8_t pristine[sizeof(out)];
	struct in6_addr invalid_src = {.s6_addr = {0xff, 0x02}};

	memset(pristine, 0x7e, sizeof(pristine));
	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);

#define ASSERT_PTB_REJECTED(...)                                                                   \
	do {                                                                                       \
		memcpy(out, pristine, sizeof(out));                                                \
		zassert_equal(lichen_icmpv6_build_packet_too_big(__VA_ARGS__), -EINVAL);           \
		zassert_mem_equal(out, pristine, sizeof(out));                                     \
	} while (false)

	ASSERT_PTB_REJECTED(&invalid_src, &test_dst, 1280, invoking, sizeof(invoking),
			    LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out));
	ASSERT_PTB_REJECTED(&test_src, &test_dst, 1280, invoking, 39U,
			    LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out));
	invoking[0] = 0x40;
	ASSERT_PTB_REJECTED(&test_src, &test_dst, 1280, invoking, sizeof(invoking),
			    LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out));
	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);
	ASSERT_PTB_REJECTED(&test_src, &test_src, 1280, invoking, sizeof(invoking),
			    LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out));
	ASSERT_PTB_REJECTED(&test_src, &test_dst, 1280, invoking, sizeof(invoking), 0x80U, out,
			    sizeof(out));
	ASSERT_PTB_REJECTED(&test_src, &test_dst, 1280, NULL, sizeof(invoking),
			    LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out));

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 0);
	invoking[40] = LICHEN_ICMPV6_NEXT_HEADER;
	invoking[41] = 2;
	ASSERT_PTB_REJECTED(&test_src, &test_dst, 1280, invoking, sizeof(invoking),
			    LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out));

#undef ASSERT_PTB_REJECTED
}

ZTEST(icmpv6, test_time_exceeded_matches_shared_vector)
{
	static const char invoking_hex[] = "60000000001911400200389e777ace07c7d6ca08166ecd20"
					   "0200514acffcfa9dea90556802586d371633163300193098"
					   "7061796c6f616420666f72206572726f72";
	static const char expected_hex[] = "6000000000493a400200514acffcfa9dea90556802586d37"
					   "0200389e777ace07c7d6ca08166ecd200300c85000000000"
					   "60000000001911400200389e777ace07c7d6ca08166ecd20"
					   "0200514acffcfa9dea90556802586d371633163300193098"
					   "7061796c6f616420666f72206572726f72";
	const struct in6_addr src = {.s6_addr = {0x02, 0x00, 0x51, 0x4a, 0xcf, 0xfc, 0xfa, 0x9d,
						 0xea, 0x90, 0x55, 0x68, 0x02, 0x58, 0x6d, 0x37}};
	const struct in6_addr dst = {.s6_addr = {0x02, 0x00, 0x38, 0x9e, 0x77, 0x7a, 0xce, 0x07,
						 0xc7, 0xd6, 0xca, 0x08, 0x16, 0x6e, 0xcd, 0x20}};
	uint8_t invoking[(sizeof(invoking_hex) - 1U) / 2U];
	uint8_t expected[(sizeof(expected_hex) - 1U) / 2U];
	uint8_t actual[sizeof(expected)];
	int ret;

	zassert_true(decode_hex(invoking_hex, invoking, sizeof(invoking)));
	zassert_true(decode_hex(expected_hex, expected, sizeof(expected)));
	ret = lichen_icmpv6_build_time_exceeded(
		&src, &dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking, sizeof(invoking),
		LICHEN_ICMPV6_INVOKING_UNICAST, actual, sizeof(actual));

	zassert_equal(ret, (int)sizeof(expected));
	zassert_mem_equal(actual, expected, sizeof(expected));
	zassert_true(lichen_icmpv6_verify_checksum(&src, &dst, &actual[40], sizeof(actual) - 40U));
}

ZTEST(icmpv6, test_time_exceeded_fragment_reassembly_code)
{
	uint8_t invoking[56];
	uint8_t out[sizeof(invoking) + 48U];
	int ret;

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 44);
	invoking[40] = 17;
	invoking[43] = 1; /* First fragment with M flag set. */
	ret = lichen_icmpv6_build_time_exceeded(
		&test_src, &test_dst, LICHEN_ICMPV6_FRAGMENT_REASSEMBLY, invoking,
		sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out));

	zassert_equal(ret, (int)sizeof(out));
	zassert_equal(out[40], LICHEN_ICMPV6_TIME_EXCEEDED);
	zassert_equal(out[41], LICHEN_ICMPV6_FRAGMENT_REASSEMBLY);
	zassert_mem_equal(&out[44], "\0\0\0\0", 4U);
	zassert_mem_equal(&out[48], invoking, sizeof(invoking));
	zassert_true(lichen_icmpv6_verify_checksum(&test_src, &test_dst, &out[40],
					   sizeof(out) - 40U));
}

ZTEST(icmpv6, test_time_exceeded_quote_and_output_boundaries)
{
	static uint8_t invoking[LICHEN_ICMPV6_MAX_INVOKING_PACKET + 1U];
	static uint8_t out[LICHEN_IPV6_MIN_MTU + 1U];
	int ret;

	memset(invoking, 0x4d, sizeof(invoking));
	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);
	memset(out, 0xa5, sizeof(out));
	ret = lichen_icmpv6_build_time_exceeded(
		&test_src, &test_dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking,
		sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out));

	zassert_equal(ret, LICHEN_IPV6_MIN_MTU);
	zassert_equal(((uint16_t)out[4] << 8) | out[5],
		      LICHEN_IPV6_MIN_MTU - LICHEN_IPV6_HEADER_LEN);
	zassert_mem_equal(&out[44], "\0\0\0\0", 4U);
	zassert_mem_equal(&out[48], invoking, LICHEN_ICMPV6_MAX_INVOKING_PACKET);
	zassert_equal(out[LICHEN_IPV6_MIN_MTU], 0xa5);
	zassert_true(lichen_icmpv6_verify_checksum(&test_src, &test_dst, &out[40],
					   LICHEN_IPV6_MIN_MTU - LICHEN_IPV6_HEADER_LEN));

	memset(out, 0x6c, sizeof(out));
	zassert_equal(lichen_icmpv6_build_time_exceeded(
			      &test_src, &test_dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking,
			      LICHEN_ICMPV6_MAX_INVOKING_PACKET,
			      LICHEN_ICMPV6_INVOKING_UNICAST, out, LICHEN_IPV6_MIN_MTU - 1U),
		      0);
	for (size_t i = 0; i < sizeof(out); ++i) {
		zassert_equal(out[i], 0x6c, "short-buffer failure mutated byte %zu", i);
	}
}

ZTEST(icmpv6, test_time_exceeded_rfc4443_suppression)
{
	uint8_t invoking[56];
	uint8_t out[sizeof(invoking) + 48U];
	uint8_t pristine[sizeof(out)];
	const uint8_t flags[] = {
		LICHEN_ICMPV6_INVOKING_LINK_MULTICAST,
		LICHEN_ICMPV6_INVOKING_LINK_BROADCAST,
		LICHEN_ICMPV6_INVOKING_SOURCE_ANYCAST,
		LICHEN_ICMPV6_INVOKING_CONGESTION,
	};

	memset(pristine, 0x5a, sizeof(pristine));
	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);
	for (size_t i = 0; i < ARRAY_SIZE(flags); ++i) {
		memcpy(out, pristine, sizeof(out));
		zassert_equal(lichen_icmpv6_build_time_exceeded(
				      &test_src, &test_dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED,
				      invoking, sizeof(invoking), flags[i], out, sizeof(out)),
			      0);
		zassert_mem_equal(out, pristine, sizeof(out));
	}

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src,
			     LICHEN_ICMPV6_NEXT_HEADER);
	invoking[40] = LICHEN_ICMPV6_DEST_UNREACHABLE;
	zassert_equal(lichen_icmpv6_build_time_exceeded(
			      &test_src, &test_dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "must suppress response to ICMPv6 error");
	invoking[40] = 137U;
	zassert_equal(lichen_icmpv6_build_time_exceeded(
			      &test_src, &test_dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "must suppress response to Redirect");

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);
	invoking[24] = 0xff;
	zassert_equal(lichen_icmpv6_build_time_exceeded(
			      &test_src, &test_dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "must suppress multicast destination");
	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 50);
	zassert_equal(lichen_icmpv6_build_time_exceeded(
			      &test_src, &test_dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "uninspectable ESP packet must fail closed");
	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 44);
	invoking[40] = 17;
	invoking[42] = 0;
	invoking[43] = 8;
	zassert_equal(lichen_icmpv6_build_time_exceeded(
			      &test_src, &test_dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking,
			      sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out)),
		      0, "non-initial fragment must fail closed");
}

ZTEST(icmpv6, test_time_exceeded_rejects_malformed_input_without_mutation)
{
	uint8_t invoking[48];
	uint8_t out[sizeof(invoking) + 48U];
	uint8_t pristine[sizeof(out)];
	struct in6_addr invalid_src = {.s6_addr = {0xff, 0x02}};

	memset(pristine, 0x7d, sizeof(pristine));
	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);

#define ASSERT_TIME_REJECTED(...)                                                                  \
	do {                                                                                         \
		memcpy(out, pristine, sizeof(out));                                                    \
		zassert_equal(lichen_icmpv6_build_time_exceeded(__VA_ARGS__), -EINVAL);                \
		zassert_mem_equal(out, pristine, sizeof(out));                                         \
	} while (false)

	ASSERT_TIME_REJECTED(&test_src, &test_dst, (enum lichen_icmpv6_time_exceeded_code)2,
			     invoking, sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out,
			     sizeof(out));
	ASSERT_TIME_REJECTED(&invalid_src, &test_dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking,
			     sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out,
			     sizeof(out));
	ASSERT_TIME_REJECTED(NULL, &test_dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking,
			     sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out,
			     sizeof(out));
	ASSERT_TIME_REJECTED(&test_src, &test_dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking,
			     39U, LICHEN_ICMPV6_INVOKING_UNICAST, out, sizeof(out));
	invoking[0] = 0x40;
	ASSERT_TIME_REJECTED(&test_src, &test_dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking,
			     sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out,
			     sizeof(out));
	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);
	ASSERT_TIME_REJECTED(&test_src, &test_src, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking,
			     sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out,
			     sizeof(out));
	ASSERT_TIME_REJECTED(&test_src, &test_dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking,
			     sizeof(invoking), 0x80U, out, sizeof(out));
	ASSERT_TIME_REJECTED(&test_src, &test_dst, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, NULL,
			     sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, out,
			     sizeof(out));

#undef ASSERT_TIME_REJECTED
}

/**
 * Test building Parameter Problem with pointer.
 */
ZTEST(icmpv6, test_build_param_problem)
{
    uint8_t buf[128];
    int ret;

    ret = lichen_icmpv6_build_param_problem(&test_src, &test_dst,
                                            LICHEN_ICMPV6_UNRECOGNIZED_NEXT_HEADER,
                                            6, /* Pointer to Next Header field */
                                            NULL, 0,
                                            buf, sizeof(buf));

    zassert_true(ret > 0, "Build failed: %d", ret);
    zassert_equal(buf[40], LICHEN_ICMPV6_PARAM_PROBLEM, "Type wrong");
    zassert_equal(buf[41], LICHEN_ICMPV6_UNRECOGNIZED_NEXT_HEADER, "Code wrong");

    /* Pointer at offset 44-47 */
    uint32_t pointer = ((uint32_t)buf[44] << 24) | ((uint32_t)buf[45] << 16) |
                       ((uint32_t)buf[46] << 8) | buf[47];
    zassert_equal(pointer, 6, "Pointer wrong: %u", pointer);
}

/**
 * Test handle generates reply for Echo Request.
 */
ZTEST(icmpv6, test_handle_echo_request)
{
    uint8_t request_buf[64];
    uint8_t reply_buf[64];
    const uint8_t data[] = "echo";
    int req_len, reply_len;

    req_len = lichen_icmpv6_build_echo_request(&test_src, &test_dst,
                                               0xbeef, 123,
                                               data, sizeof(data) - 1,
                                               request_buf, sizeof(request_buf));
    zassert_true(req_len > 0, "Build request failed");

    reply_len = lichen_icmpv6_handle(&test_src, &test_dst,
                                     &request_buf[40], req_len - 40,
				     LICHEN_ICMPV6_ECHO_DESTINATION_UNICAST,
                                     reply_buf, sizeof(reply_buf));

    zassert_true(reply_len > 0, "Handle should produce reply: %d", reply_len);

    /* Reply should be Echo Reply */
    zassert_equal(reply_buf[40], LICHEN_ICMPV6_ECHO_REPLY, "Reply type wrong");

    /* Reply source should be original destination */
    zassert_mem_equal(&reply_buf[8], test_dst.s6_addr, 16, "Reply src wrong");

    /* Reply destination should be original source */
    zassert_mem_equal(&reply_buf[24], test_src.s6_addr, 16, "Reply dst wrong");

    /* Identifier and sequence should match */
    zassert_equal((reply_buf[44] << 8) | reply_buf[45], 0xbeef, "Reply ID wrong");
    zassert_equal((reply_buf[46] << 8) | reply_buf[47], 123, "Reply seq wrong");

    /* Data should match */
    zassert_mem_equal(&reply_buf[48], "echo", 4, "Reply data wrong");
	zassert_equal(reply_buf[41], 0, "Reply code must be zero");
	zassert_true(lichen_icmpv6_verify_checksum(&test_dst, &test_src, &reply_buf[40],
					   (size_t)reply_len - 40U));
}

ZTEST(icmpv6, test_handle_echo_request_matches_shared_reply_vector)
{
	static const char request_hex[] = "60000000000c3a40fe800000000000000000000000000001"
					  "fe800000000000000000000000000002800088a51234000174657374";
	static const char reply_hex[] = "60000000000c3a40fe800000000000000000000000000002"
					"fe800000000000000000000000000001810087a51234000174657374";
	uint8_t request[(sizeof(request_hex) - 1U) / 2U];
	uint8_t expected[(sizeof(reply_hex) - 1U) / 2U];
	uint8_t actual[sizeof(expected)];
	int ret;

	zassert_true(decode_hex(request_hex, request, sizeof(request)));
	zassert_true(decode_hex(reply_hex, expected, sizeof(expected)));
	ret = lichen_icmpv6_handle(&test_src, &test_dst, &request[40], sizeof(request) - 40U,
				   LICHEN_ICMPV6_ECHO_DESTINATION_UNICAST, actual,
				   sizeof(actual));
	zassert_equal(ret, (int)sizeof(expected));
	zassert_mem_equal(actual, expected, sizeof(expected));
}

ZTEST(icmpv6, test_handle_echo_suppresses_unsafe_requests_and_errors_without_mutation)
{
	struct in6_addr unspecified = {0};
	struct in6_addr multicast = {.s6_addr = {0xff, 0x02, 0, 0, 0, 0, 0, 0,
							 0, 0, 0, 0, 0, 0, 0, 1}};
	uint8_t request[64];
	uint8_t invoking[48];
	uint8_t error[sizeof(invoking) + 48U];
	uint8_t out[sizeof(error)];
	uint8_t pristine[sizeof(out)];
	int request_len;
	int error_len;

	memset(pristine, 0x6a, sizeof(pristine));
	request_len = lichen_icmpv6_build_echo_request(&test_src, &test_dst, 0x1234, 1, NULL, 0,
						      request, sizeof(request));
	zassert_true(request_len > 0);

#define ASSERT_HANDLE_SUPPRESSED(source, destination, flags)                                      \
	do {                                                                                         \
		memcpy(out, pristine, sizeof(out));                                                    \
		zassert_equal(lichen_icmpv6_handle(source, destination, &request[40],                  \
						       (size_t)request_len - 40U, flags, out,         \
						       sizeof(out)),                                  \
			      0);                                                                     \
		zassert_mem_equal(out, pristine, sizeof(out));                                         \
	} while (false)

	ASSERT_HANDLE_SUPPRESSED(&test_src, &test_dst, LICHEN_ICMPV6_ECHO_DESTINATION_ANYCAST);
	ASSERT_HANDLE_SUPPRESSED(&test_src, &test_dst, LICHEN_ICMPV6_ECHO_SOURCE_ANYCAST);

	request_len = lichen_icmpv6_build_echo_request(&test_src, &multicast, 0x1234, 1, NULL, 0,
						      request, sizeof(request));
	zassert_true(request_len > 0);
	ASSERT_HANDLE_SUPPRESSED(&test_src, &multicast, LICHEN_ICMPV6_ECHO_DESTINATION_UNICAST);

	request_len = lichen_icmpv6_build_echo_request(&test_src, &test_dst, 0x1234, 1, NULL, 0,
						      request, sizeof(request));
	set_icmpv6_checksum(&multicast, &test_dst, &request[40], (size_t)request_len - 40U);
	ASSERT_HANDLE_SUPPRESSED(&multicast, &test_dst, LICHEN_ICMPV6_ECHO_DESTINATION_UNICAST);
	set_icmpv6_checksum(&unspecified, &test_dst, &request[40], (size_t)request_len - 40U);
	ASSERT_HANDLE_SUPPRESSED(&unspecified, &test_dst, LICHEN_ICMPV6_ECHO_DESTINATION_UNICAST);

	request[41] = 1;
	set_icmpv6_checksum(&test_src, &test_dst, &request[40], (size_t)request_len - 40U);
	ASSERT_HANDLE_SUPPRESSED(&test_src, &test_dst, LICHEN_ICMPV6_ECHO_DESTINATION_UNICAST);

	make_invoking_packet(invoking, sizeof(invoking), &test_dst, &test_src, 17);
	error_len = lichen_icmpv6_build_dest_unreachable(
		&test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, invoking, sizeof(invoking),
		LICHEN_ICMPV6_INVOKING_UNICAST, error, sizeof(error));
	zassert_true(error_len > 0);
	memcpy(out, pristine, sizeof(out));
	zassert_equal(lichen_icmpv6_handle(&test_src, &test_dst, &error[40],
					  (size_t)error_len - 40U,
					  LICHEN_ICMPV6_ECHO_DESTINATION_UNICAST, out,
					  sizeof(out)),
		      0);
	zassert_mem_equal(out, pristine, sizeof(out));

#undef ASSERT_HANDLE_SUPPRESSED
}

ZTEST(icmpv6, test_handle_echo_invalid_metadata_and_short_output_do_not_mutate)
{
	uint8_t request[64];
	uint8_t out[64];
	uint8_t pristine[sizeof(out)];
	int request_len;

	request_len = lichen_icmpv6_build_echo_request(&test_src, &test_dst, 0, 0, NULL, 0,
						      request, sizeof(request));
	zassert_true(request_len > 0);
	memset(pristine, 0x2d, sizeof(pristine));
	memcpy(out, pristine, sizeof(out));
	zassert_equal(lichen_icmpv6_handle(&test_src, &test_dst, &request[40],
					  (size_t)request_len - 40U, 0x80U, out, sizeof(out)),
		      -EINVAL);
	zassert_mem_equal(out, pristine, sizeof(out));

	memcpy(out, pristine, sizeof(out));
	zassert_equal(lichen_icmpv6_handle(
			      &test_src, &test_dst, &request[40], (size_t)request_len - 40U,
			      LICHEN_ICMPV6_ECHO_DESTINATION_UNICAST, out,
			      LICHEN_IPV6_HEADER_LEN + LICHEN_ICMPV6_ECHO_HEADER_LEN - 1U),
		      0);
	zassert_mem_equal(out, pristine, sizeof(out));
}

/**
 * Test handle returns 0 for Echo Reply (no reply needed).
 */
ZTEST(icmpv6, test_handle_echo_reply_no_response)
{
    uint8_t reply_pkt[64];
    uint8_t response_buf[64];
	uint8_t pristine[sizeof(response_buf)];
    int pkt_len, response_len;

    pkt_len = lichen_icmpv6_build_echo_reply(&test_src, &test_dst,
                                             0x1234, 1,
                                             NULL, 0,
                                             reply_pkt, sizeof(reply_pkt));
    zassert_true(pkt_len > 0, "Build reply failed");
	memset(pristine, 0x4b, sizeof(pristine));
	memcpy(response_buf, pristine, sizeof(response_buf));

    response_len = lichen_icmpv6_handle(&test_src, &test_dst,
                                        &reply_pkt[40], pkt_len - 40,
					LICHEN_ICMPV6_ECHO_DESTINATION_UNICAST,
                                        response_buf, sizeof(response_buf));

    zassert_equal(response_len, 0, "Should return 0 for echo reply: %d", response_len);
	zassert_mem_equal(response_buf, pristine, sizeof(response_buf));
}

/**
 * Test handle silently discards invalid checksum.
 */
ZTEST(icmpv6, test_handle_invalid_checksum)
{
    uint8_t request_buf[64];
    uint8_t reply_buf[64];
	uint8_t pristine[sizeof(reply_buf)];
    int req_len, reply_len;

    req_len = lichen_icmpv6_build_echo_request(&test_src, &test_dst,
                                               0x1234, 1,
                                               NULL, 0,
                                               request_buf, sizeof(request_buf));
    zassert_true(req_len > 0, "Build request failed");

    /* Corrupt the checksum */
    request_buf[42] ^= 0xff;
	memset(pristine, 0x7b, sizeof(pristine));
	memcpy(reply_buf, pristine, sizeof(reply_buf));

    reply_len = lichen_icmpv6_handle(&test_src, &test_dst,
                                     &request_buf[40], req_len - 40,
				     LICHEN_ICMPV6_ECHO_DESTINATION_UNICAST,
                                     reply_buf, sizeof(reply_buf));

    zassert_equal(reply_len, 0, "Should silently discard invalid checksum: %d", reply_len);
	zassert_mem_equal(reply_buf, pristine, sizeof(reply_buf));
}

/**
 * Test type string conversion.
 */
ZTEST(icmpv6, test_type_str)
{
    zassert_str_equal(lichen_icmpv6_type_str(LICHEN_ICMPV6_ECHO_REQUEST),
                      "Echo Request", "Echo Request str wrong");
    zassert_str_equal(lichen_icmpv6_type_str(LICHEN_ICMPV6_ECHO_REPLY),
                      "Echo Reply", "Echo Reply str wrong");
    zassert_str_equal(lichen_icmpv6_type_str(LICHEN_ICMPV6_DEST_UNREACHABLE),
                      "Destination Unreachable", "Dest Unreachable str wrong");
    zassert_str_equal(lichen_icmpv6_type_str(LICHEN_ICMPV6_PACKET_TOO_BIG),
                      "Packet Too Big", "Packet Too Big str wrong");
    zassert_str_equal(lichen_icmpv6_type_str(LICHEN_ICMPV6_TIME_EXCEEDED),
                      "Time Exceeded", "Time Exceeded str wrong");
    zassert_str_equal(lichen_icmpv6_type_str(LICHEN_ICMPV6_PARAM_PROBLEM),
                      "Parameter Problem", "Parameter Problem str wrong");
    zassert_str_equal(lichen_icmpv6_type_str(255),
                      "Unknown", "Unknown str wrong");
}

/**
 * Test checksum is stable across rebuilds.
 */
ZTEST(icmpv6, test_checksum_stable)
{
    uint8_t buf1[64];
    uint8_t buf2[64];
    int len1, len2;

    len1 = lichen_icmpv6_build_echo_request(&test_src, &test_dst,
                                            0x1234, 1,
                                            NULL, 0,
                                            buf1, sizeof(buf1));
    len2 = lichen_icmpv6_build_echo_request(&test_src, &test_dst,
                                            0x1234, 1,
                                            NULL, 0,
                                            buf2, sizeof(buf2));

    zassert_equal(len1, len2, "Lengths differ");
    zassert_mem_equal(buf1, buf2, len1, "Packets differ on rebuild");
}

/**
 * Test invoking packet is truncated to max size.
 */
ZTEST(icmpv6, test_invoking_packet_truncation)
{
	static uint8_t buf[LICHEN_IPV6_MIN_MTU + 1U];
	static uint8_t large_invoking[LICHEN_ICMPV6_MAX_INVOKING_PACKET + 1U];
	int ret;

	memset(large_invoking, 0xaa, sizeof(large_invoking));
	make_invoking_packet(large_invoking, sizeof(large_invoking), &test_dst, &test_src, 17);
	memset(buf, 0x5a, sizeof(buf));

	ret = lichen_icmpv6_build_dest_unreachable(
		&test_src, &test_dst, LICHEN_ICMPV6_NO_ROUTE, large_invoking,
		sizeof(large_invoking), LICHEN_ICMPV6_INVOKING_UNICAST, buf, sizeof(buf));

	zassert_equal(ret, LICHEN_IPV6_MIN_MTU, "ICMPv6 error must be bounded to minimum MTU");
	zassert_equal(((uint16_t)buf[4] << 8) | buf[5],
		      LICHEN_IPV6_MIN_MTU - LICHEN_IPV6_HEADER_LEN);
	zassert_mem_equal(&buf[48], large_invoking, LICHEN_ICMPV6_MAX_INVOKING_PACKET);
	zassert_equal(buf[LICHEN_IPV6_MIN_MTU], 0x5a,
		      "builder wrote past the bounded error packet");
	zassert_true(lichen_icmpv6_verify_checksum(&test_src, &test_dst, &buf[40],
						   LICHEN_IPV6_MIN_MTU - LICHEN_IPV6_HEADER_LEN));
}

ZTEST_SUITE(icmpv6, NULL, NULL, NULL, NULL, NULL);
