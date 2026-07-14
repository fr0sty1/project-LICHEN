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

/**
 * Test building Destination Unreachable.
 */
ZTEST(icmpv6, test_build_dest_unreachable)
{
    uint8_t buf[128];
    const uint8_t invoking[] = {0x60, 0x00, 0x00, 0x00, 0x00, 0x10};
    int ret;

    ret = lichen_icmpv6_build_dest_unreachable(&test_src, &test_dst,
                                               LICHEN_ICMPV6_PORT_UNREACHABLE,
                                               invoking, sizeof(invoking),
                                               buf, sizeof(buf));

    /* Expected: 40 (IPv6) + 8 (ICMPv6 header) + 6 (invoking) = 54 bytes */
    zassert_equal(ret, 54, "Unexpected length: %d", ret);
    zassert_equal(buf[40], LICHEN_ICMPV6_DEST_UNREACHABLE, "Type wrong");
    zassert_equal(buf[41], LICHEN_ICMPV6_PORT_UNREACHABLE, "Code wrong");
    /* Rest of header should be zero */
    zassert_equal(buf[44], 0, "Rest of header[0] not zero");
    zassert_equal(buf[45], 0, "Rest of header[1] not zero");
    zassert_equal(buf[46], 0, "Rest of header[2] not zero");
    zassert_equal(buf[47], 0, "Rest of header[3] not zero");
    /* Invoking packet follows */
    zassert_mem_equal(&buf[48], invoking, sizeof(invoking), "Invoking mismatch");
}

/**
 * Test building Packet Too Big with MTU.
 */
ZTEST(icmpv6, test_build_packet_too_big)
{
    uint8_t buf[128];
    const uint8_t invoking[] = {0x60, 0x00};
    int ret;

    ret = lichen_icmpv6_build_packet_too_big(&test_src, &test_dst,
                                             1280,
                                             invoking, sizeof(invoking),
                                             buf, sizeof(buf));

    zassert_true(ret > 0, "Build failed: %d", ret);
    zassert_equal(buf[40], LICHEN_ICMPV6_PACKET_TOO_BIG, "Type wrong");
    zassert_equal(buf[41], 0, "Code wrong");

    /* MTU in network byte order at offset 44-47 */
    uint32_t mtu = ((uint32_t)buf[44] << 24) | ((uint32_t)buf[45] << 16) |
                   ((uint32_t)buf[46] << 8) | buf[47];
    zassert_equal(mtu, 1280, "MTU wrong: %u", mtu);
}

/**
 * Test building Time Exceeded.
 */
ZTEST(icmpv6, test_build_time_exceeded)
{
    uint8_t buf[128];
    int ret;

    ret = lichen_icmpv6_build_time_exceeded(&test_src, &test_dst,
                                            LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED,
                                            NULL, 0,
                                            buf, sizeof(buf));

    /* Expected: 40 (IPv6) + 8 (ICMPv6 header) = 48 bytes */
    zassert_equal(ret, 48, "Unexpected length: %d", ret);
    zassert_equal(buf[40], LICHEN_ICMPV6_TIME_EXCEEDED, "Type wrong");
    zassert_equal(buf[41], LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, "Code wrong");
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
}

/**
 * Test handle returns 0 for Echo Reply (no reply needed).
 */
ZTEST(icmpv6, test_handle_echo_reply_no_response)
{
    uint8_t reply_pkt[64];
    uint8_t response_buf[64];
    int pkt_len, response_len;

    pkt_len = lichen_icmpv6_build_echo_reply(&test_src, &test_dst,
                                             0x1234, 1,
                                             NULL, 0,
                                             reply_pkt, sizeof(reply_pkt));
    zassert_true(pkt_len > 0, "Build reply failed");

    response_len = lichen_icmpv6_handle(&test_src, &test_dst,
                                        &reply_pkt[40], pkt_len - 40,
                                        response_buf, sizeof(response_buf));

    zassert_equal(response_len, 0, "Should return 0 for echo reply: %d", response_len);
}

/**
 * Test handle silently discards invalid checksum.
 */
ZTEST(icmpv6, test_handle_invalid_checksum)
{
    uint8_t request_buf[64];
    uint8_t reply_buf[64];
    int req_len, reply_len;

    req_len = lichen_icmpv6_build_echo_request(&test_src, &test_dst,
                                               0x1234, 1,
                                               NULL, 0,
                                               request_buf, sizeof(request_buf));
    zassert_true(req_len > 0, "Build request failed");

    /* Corrupt the checksum */
    request_buf[42] ^= 0xff;

    reply_len = lichen_icmpv6_handle(&test_src, &test_dst,
                                     &request_buf[40], req_len - 40,
                                     reply_buf, sizeof(reply_buf));

    zassert_equal(reply_len, 0, "Should silently discard invalid checksum: %d", reply_len);
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
    uint8_t buf[512];
    uint8_t large_invoking[300];
    int ret;

    memset(large_invoking, 0xaa, sizeof(large_invoking));

    ret = lichen_icmpv6_build_dest_unreachable(&test_src, &test_dst,
                                               LICHEN_ICMPV6_NO_ROUTE,
                                               large_invoking, sizeof(large_invoking),
                                               buf, sizeof(buf));

    /* Should truncate to MAX_INVOKING_PACKET (256 bytes) */
    /* Expected: 40 (IPv6) + 8 (ICMPv6 header) + 256 (invoking) = 304 bytes */
    zassert_equal(ret, 304, "Unexpected length with truncation: %d", ret);
}

ZTEST_SUITE(icmpv6, NULL, NULL, NULL, NULL, NULL);
