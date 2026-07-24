/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief LICHEN frame parse/write tests
 */

#include <lichen/link.h>
#include <lichen/errno.h>
#include <stdio.h>
#include <string.h>

static int tests_run;
static int tests_passed;

#define ASSERT_EQ(a, b, msg) do { \
	if ((a) != (b)) { \
		printf("  FAIL: %s (got %d, expected %d)\n", msg, (int)(a), (int)(b)); \
		return 0; \
	} \
} while (0)

static int test_parse_rejects_null_frame(void)
{
	uint8_t data[9] = { 0 };

	ASSERT_EQ(lichen_frame_parse(NULL, data, sizeof(data)), -EINVAL,
		  "parse rejects NULL frame");

	return 1;
}

static int test_parse_rejects_null_data(void)
{
	struct lichen_frame frame;

	memset(&frame, 0, sizeof(frame));

	ASSERT_EQ(lichen_frame_parse(&frame, NULL, 9), -EINVAL,
		  "parse rejects NULL data");

	return 1;
}

static int test_parse_rejects_canonical_invalid_frames(void)
{
	uint8_t empty = 0U;
	uint8_t truncated[] = { 0x14, 0x00, 0x01, 0x12, 0x34, 0xaa, 0xbb, 0xcc, 0xdd };
	uint8_t reserved[] = { 0x08, 0x80, 0x01, 0x12, 0x34, 0xaa, 0xbb, 0xcc, 0xdd };
	uint8_t too_short[] = { 0x02, 0x00, 0x01 };
	struct lichen_frame frame;

	ASSERT_EQ(lichen_frame_parse(&frame, &empty, 0), -EINVAL,
		  "parse rejects empty frame");
	ASSERT_EQ(lichen_frame_parse(&frame, truncated, sizeof(truncated)), -EINVAL,
		  "parse rejects length mismatch");
	ASSERT_EQ(lichen_frame_parse(&frame, reserved, sizeof(reserved)), -EINVAL,
		  "parse rejects reserved bit");
	ASSERT_EQ(lichen_frame_parse(&frame, too_short, sizeof(too_short)), -EINVAL,
		  "parse rejects short body");

	return 1;
}

static int test_parse_rejects_oversize_frames(void)
{
	uint8_t length_255[] = { 0xff };
	uint8_t frame_256[256] = { 0xfe };
	struct lichen_frame frame;

	ASSERT_EQ(lichen_frame_parse(&frame, length_255, sizeof(length_255)), -EMSGSIZE,
		  "parse rejects LENGTH 255 before truncation");
	ASSERT_EQ(lichen_frame_parse(&frame, frame_256, sizeof(frame_256)), -EMSGSIZE,
		  "parse rejects 256-byte frame");

	return 1;
}

static int test_write_rejects_null_frame(void)
{
	uint8_t buf[16];

	ASSERT_EQ(lichen_frame_write(NULL, buf, sizeof(buf)), -EINVAL,
		  "write rejects NULL frame");

	return 1;
}

static int test_write_rejects_null_buf(void)
{
	struct lichen_frame frame;

	memset(&frame, 0, sizeof(frame));
	frame.mic_len = 0U;

	ASSERT_EQ(lichen_frame_write(&frame, NULL, 16), -EINVAL,
		  "write rejects NULL buf");

	return 1;
}

static int test_write_rejects_invalid_addr_mode(void)
{
	struct lichen_frame frame;
	uint8_t buf[16];

	memset(&frame, 0, sizeof(frame));
	frame.addr_mode = (enum lichen_addr_mode)4;
	frame.mic_len = 0U;

	ASSERT_EQ(lichen_frame_write(&frame, buf, sizeof(buf)), -EINVAL,
		  "write rejects invalid address mode");

	return 1;
}

static int test_write_accepts_mic_selector_without_mic(void)
{
	struct lichen_frame frame;
	uint8_t buf[16];

	memset(&frame, 0, sizeof(frame));
	frame.addr_mode = LICHEN_ADDR_BROADCAST;
	frame.mic_length = LICHEN_MIC_64;
	frame.mic_len = 0U;

	ASSERT_EQ(lichen_frame_write(&frame, buf, sizeof(buf)), 5,
		  "write accepts unsigned frame without MIC");

	return 1;
}

static int test_write_parse_round_trip_unsigned(void)
{
	static const uint8_t payload[] = { 0x15, 0x01, 0x02 };
	struct lichen_frame input;
	struct lichen_frame output;
	uint8_t buf[32];
	int frame_len;

	memset(&input, 0, sizeof(input));
	input.epoch = 7;
	input.seqnum = 0x1234;
	input.payload = payload;
	input.payload_len = sizeof(payload);
	input.mic_len = 0U;
	input.addr_mode = LICHEN_ADDR_BROADCAST;

	frame_len = lichen_frame_write(&input, buf, sizeof(buf));
	ASSERT_EQ(frame_len, 8, "write omits unsigned MIC");
	ASSERT_EQ(buf[1], 0x00, "unsigned frame has no MIC bits in LLSec");

	memset(&output, 0, sizeof(output));
	ASSERT_EQ(lichen_frame_parse(&output, buf, (size_t)frame_len), 0,
		  "parse accepts serialized unsigned frame");
	ASSERT_EQ(output.epoch, input.epoch, "round-trip preserves epoch");
	ASSERT_EQ(output.seqnum, input.seqnum, "round-trip preserves sequence number");
	ASSERT_EQ(output.mic_length, LICHEN_MIC_32, "unsigned MIC length from wire");
	ASSERT_EQ(output.mic_len, 0, "round-trip preserves absent MIC");
	ASSERT_EQ(output.payload_len, sizeof(payload), "round-trip preserves payload length");
	if (memcmp(output.payload, payload, sizeof(payload)) != 0) {
		printf("  FAIL: round-trip preserves payload\n");
		return 0;
	}

	return 1;
}

static int test_signed_encrypted_is_rejected(void)
{
	uint8_t wire[54] = { 0 };
	struct lichen_frame frame;

	wire[0] = 53U;
	wire[1] = 0x60U;
	wire[2] = 3U;
	wire[4] = 4U;
	wire[5] = 0x78U;
	ASSERT_EQ(lichen_frame_parse(&frame, wire, sizeof(wire)), -EPROTONOSUPPORT,
		  "parse rejects encrypted frame as unsupported");

	memset(&frame, 0, sizeof(frame));
	frame.signature_present = true;
	frame.encrypted = true;
	frame.mic_len = LICHEN_SIG_LEN;
	frame.payload = &wire[5];
	frame.payload_len = 1U;
	ASSERT_EQ(lichen_frame_write(&frame, wire, sizeof(wire)), -EPROTONOSUPPORT,
		  "write rejects encrypted frame as unsupported");

	return 1;
}

static int test_authoritative_signed_vector(void)
{
	uint8_t wire[59] = { 0x3a, 0x25, 0x05, 0xab, 0xcd, 0xbe, 0xef };
	struct lichen_frame frame;
	uint8_t rebuilt[sizeof(wire)];

	memset(&wire[7], 0x55, 48);
	wire[55] = 0x11;
	wire[56] = 0x22;
	wire[57] = 0x33;
	wire[58] = 0x44;

	ASSERT_EQ(lichen_frame_parse(&frame, wire, sizeof(wire)), 0,
		  "parse authoritative signed vector");
	ASSERT_EQ(frame.payload_len, 4, "signed vector payload length");
	ASSERT_EQ(frame.mic_len, LICHEN_SIG_LEN, "signed vector MIC length");
	if (memcmp(frame.payload, (uint8_t[]){ 0x55, 0x55, 0x55, 0x55 }, 4) != 0 ||
	    memcmp(frame.mic, &wire[11], LICHEN_SIG_LEN) != 0) {
		printf("  FAIL: signed vector payload/MIC bytes\n");
		return 0;
	}
	ASSERT_EQ(lichen_frame_write(&frame, rebuilt, sizeof(rebuilt)), sizeof(wire),
		  "serialize authoritative signed vector");
	if (memcmp(rebuilt, wire, sizeof(wire)) != 0) {
		printf("  FAIL: signed vector encoded bytes\n");
		return 0;
	}

	return 1;
}

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
	printf("LICHEN Frame Tests\n");
	printf("==================\n\n");

	RUN_TEST(test_parse_rejects_null_frame);
	RUN_TEST(test_parse_rejects_null_data);
	RUN_TEST(test_parse_rejects_canonical_invalid_frames);
	RUN_TEST(test_parse_rejects_oversize_frames);
	RUN_TEST(test_write_rejects_null_frame);
	RUN_TEST(test_write_rejects_null_buf);
	RUN_TEST(test_write_rejects_invalid_addr_mode);
	RUN_TEST(test_write_accepts_mic_selector_without_mic);
	RUN_TEST(test_write_parse_round_trip_unsigned);
	RUN_TEST(test_signed_encrypted_is_rejected);
	RUN_TEST(test_authoritative_signed_vector);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
