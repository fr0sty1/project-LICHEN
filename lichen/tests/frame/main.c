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
	frame.mic_len = LICHEN_MIC_32_LEN;

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
	frame.mic_len = LICHEN_MIC_32_LEN;

	ASSERT_EQ(lichen_frame_write(&frame, buf, sizeof(buf)), -EINVAL,
		  "write rejects invalid address mode");

	return 1;
}

static int test_write_rejects_inconsistent_mic_metadata(void)
{
	struct lichen_frame frame;
	uint8_t buf[16];

	memset(&frame, 0, sizeof(frame));
	frame.addr_mode = LICHEN_ADDR_BROADCAST;
	frame.mic_length = LICHEN_MIC_64;
	frame.mic_len = LICHEN_MIC_32_LEN;

	ASSERT_EQ(lichen_frame_write(&frame, buf, sizeof(buf)), -EINVAL,
		  "write rejects inconsistent MIC metadata");

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
	RUN_TEST(test_write_rejects_null_frame);
	RUN_TEST(test_write_rejects_null_buf);
	RUN_TEST(test_write_rejects_invalid_addr_mode);
	RUN_TEST(test_write_rejects_inconsistent_mic_metadata);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
