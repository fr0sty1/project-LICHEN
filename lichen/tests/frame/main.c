/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief LICHEN frame parse/write tests
 *
 * Positive cases are byte-for-byte canonical vectors from
 * test/vectors/link_frame.json and test/vectors/frame_length_boundaries.json;
 * negative cases assert the canonical error category for each rejection.
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

static size_t hex_decode(const char *hex, uint8_t *out, size_t out_cap)
{
	size_t n = strlen(hex) / 2U;

	if (n > out_cap) {
		return 0U;
	}
	for (size_t i = 0; i < n; i++) {
		unsigned int hi, lo;
		if (sscanf(&hex[i * 2], "%1x", &hi) != 1 ||
		    sscanf(&hex[i * 2 + 1], "%1x", &lo) != 1) {
			return 0U;
		}
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return n;
}

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
	uint8_t bad_selector[] = { 0x08, 0x08, 0x01, 0x12, 0x34,
				   0xaa, 0xbb, 0xcc, 0xdd };
	struct lichen_frame frame;

	memset(&frame, 0, sizeof(frame));

	ASSERT_EQ(lichen_frame_parse(&frame, &empty, 0), -EINVAL,
		  "parse rejects empty frame");
	ASSERT_EQ(lichen_frame_parse(&frame, truncated, sizeof(truncated)), -EINVAL,
		  "parse rejects length mismatch");
	ASSERT_EQ(lichen_frame_parse(&frame, reserved, sizeof(reserved)), -EINVAL,
		  "parse rejects reserved bit");
	ASSERT_EQ(lichen_frame_parse(&frame, too_short, sizeof(too_short)), -EINVAL,
		  "parse rejects short body");
	ASSERT_EQ(lichen_frame_parse(&frame, bad_selector, sizeof(bad_selector)),
		  -EINVAL, "parse rejects reserved MIC-length selector");

	return 1;
}

static int test_parse_rejects_oversize_frames(void)
{
	uint8_t length_255[] = { 0xff };
	uint8_t frame_256[256] = { 0xfe };
	struct lichen_frame frame;

	memset(&frame, 0, sizeof(frame));

	ASSERT_EQ(lichen_frame_parse(&frame, length_255, sizeof(length_255)), -EMSGSIZE,
		  "parse rejects LENGTH 255 before truncation");
	ASSERT_EQ(lichen_frame_parse(&frame, frame_256, sizeof(frame_256)), -EMSGSIZE,
		  "parse rejects 256-byte frame");

	return 1;
}

static int test_parse_accepts_minimum_and_maximum_bodies(void)
{
	/* frame_length_boundaries.json: body_length_4_minimum_valid */
	uint8_t min_body[5];
	/* frame_length_boundaries.json: body_length_254_maximum_valid =
	 * LENGTH 0xfe + LLSec/EPO/SEQ zeros + 250 payload bytes of 0xaa */
	uint8_t max_body[255];
	struct lichen_frame frame;

	memset(&frame, 0, sizeof(frame));
	ASSERT_EQ(hex_decode("0400011234", min_body, sizeof(min_body)), 5U,
		  "decode minimum body vector");
	ASSERT_EQ(lichen_frame_parse(&frame, min_body, sizeof(min_body)), 0,
		  "parse accepts 4-byte minimum body");
	ASSERT_EQ(frame.payload_len, 0, "minimum body has empty payload");
	ASSERT_EQ(frame.seqnum, 4660, "minimum body seqnum");

	memset(&frame, 0, sizeof(frame));
	max_body[0] = 0xfeU;
	memset(&max_body[1], 0x00, 4U);
	memset(&max_body[5], 0xaa, 250U);
	ASSERT_EQ(lichen_frame_parse(&frame, max_body, sizeof(max_body)), 0,
		  "parse accepts 254-byte maximum body");
	ASSERT_EQ(frame.payload_len, 250, "maximum body carries 250-byte payload");

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

static int test_write_rejects_invalid_policy(void)
{
	struct lichen_frame frame;
	uint8_t buf[16];

	memset(&frame, 0, sizeof(frame));
	frame.addr_mode = (enum lichen_addr_mode)4;
	frame.mic_len = 0U;
	ASSERT_EQ(lichen_frame_write(&frame, buf, sizeof(buf)), -EINVAL,
		  "write rejects invalid address mode");

	memset(&frame, 0, sizeof(frame));
	frame.mic_length = (enum lichen_mic_len)2;
	frame.mic_len = 0U;
	ASSERT_EQ(lichen_frame_write(&frame, buf, sizeof(buf)), -EINVAL,
		  "write rejects reserved MIC-length selector");

	memset(&frame, 0, sizeof(frame));
	frame.signer_iid_present = true;
	frame.mic_len = 0U;
	ASSERT_EQ(lichen_frame_write(&frame, buf, sizeof(buf)), -EINVAL,
		  "write rejects Signer IID field");

	memset(&frame, 0, sizeof(frame));
	frame.encrypted = true;
	frame.mic_len = 0U;
	ASSERT_EQ(lichen_frame_write(&frame, buf, sizeof(buf)), -EPROTONOSUPPORT,
		  "write rejects encrypted frame");

	memset(&frame, 0, sizeof(frame));
	frame.payload_len = 251U;
	frame.payload = buf;
	frame.mic_len = 0U;
	ASSERT_EQ(lichen_frame_write(&frame, buf, sizeof(buf)), -EMSGSIZE,
		  "write rejects 251-byte unsigned payload");

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
	ASSERT_EQ(buf[1], 0x04, "compatibility selector is encoded verbatim");

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

static int test_write_parse_round_trip_maximum(void)
{
	static uint8_t payload[LICHEN_FRAME_PAYLOAD_MAX];
	struct lichen_frame input;
	struct lichen_frame output;
	static uint8_t buf[LICHEN_MAX_FRAME_LEN];
	uint8_t echoed[LICHEN_FRAME_PAYLOAD_MAX];
	int frame_len;

	memset(payload, 0xAA, sizeof(payload));
	memset(&input, 0, sizeof(input));
	input.epoch = 0U;
	input.seqnum = 0U;
	input.payload = payload;
	input.payload_len = sizeof(payload);
	input.mic_len = 0U;
	input.addr_mode = LICHEN_ADDR_BROADCAST;

	frame_len = lichen_frame_write(&input, buf, sizeof(buf));
	ASSERT_EQ(frame_len, (int)LICHEN_MAX_FRAME_LEN,
		  "write emits canonical 255-byte maximum frame");
	ASSERT_EQ(buf[0], LICHEN_MAX_FRAME_BODY_LEN, "LENGTH field is 254");
	ASSERT_EQ(buf[1], 0x00, "maximum unsigned frame is plaintext");

	memset(&output, 0, sizeof(output));
	ASSERT_EQ(lichen_frame_parse(&output, buf, (size_t)frame_len), 0,
		  "parse accepts maximum frame");
	ASSERT_EQ(output.payload_len, sizeof(payload),
		  "maximum round-trip preserves payload length");
	memcpy(echoed, output.payload, sizeof(echoed));
	ASSERT_EQ(memcmp(echoed, payload, sizeof(payload)), 0,
		  "maximum round-trip preserves payload bytes");

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

static int test_encryption_beats_reserved_bit(void)
{
	/* link_frame.json signed_encrypted: LLSec=0xE0 sets E, S and the
	 * reserved bit 7; the rejection category must be encryption. */
	static const char hex[] =
		"3de0030004aabbccddaabbccdd78"
		"0000000000000000000000000000000000000000000000000000000000000000"
		"00000000000000000000000000000000";
	uint8_t wire[62];
	struct lichen_frame frame;

	memset(&frame, 0, sizeof(frame));
	ASSERT_EQ(hex_decode(hex, wire, sizeof(wire)), sizeof(wire),
		  "decode signed encrypted vector");
	ASSERT_EQ(lichen_frame_parse(&frame, wire, sizeof(wire)), -EPROTONOSUPPORT,
		  "signed encrypted frame rejected as unsupported encryption");

	return 1;
}

static int test_canonical_signed_vectors_round_trip(void)
{
	/* link_frame.json broadcast_signed */
	static const char bcast_hex[] =
		"3720010002616263"
		"98f74ca1c3d151205e73d61e69917f4f1fe019c59958df6b6d2538ae4df85177"
		"655c86cf4df58ceaef691dfb4a76d102";
	/* link_frame.json short_addr_signed */
	static const char short_hex[] =
		"3c21010002abcd68656c6c6f21"
		"6324ca2dccf490aac8d9fcea6a0b5601edc567d475bbd6e15d653c21bff15173"
		"25722832f9727b53bc86544c55f41a0a";
	/* link_frame.json elided_addr */
	static const char elided_hex[] = "0703051234637478";
	uint8_t wire[64];
	uint8_t rebuilt[sizeof(wire)];
	struct lichen_frame frame;
	size_t len;

	memset(&frame, 0, sizeof(frame));
	len = hex_decode(bcast_hex, wire, sizeof(wire));
	ASSERT_EQ(len, 56U, "decode broadcast_signed vector");
	ASSERT_EQ(len, 4U + 48U + 4U, "broadcast_signed carries 48-byte MIC");
	ASSERT_EQ(lichen_frame_parse(&frame, wire, len), 0,
		  "parse accepts canonical signed broadcast");
	ASSERT_EQ(frame.signature_present, true, "broadcast_signed is signed");
	ASSERT_EQ(frame.mic_length, LICHEN_MIC_32, "broadcast_signed selector");
	ASSERT_EQ(frame.mic_len, LICHEN_SIG_LEN, "signature occupies MIC field");
	ASSERT_EQ(frame.payload_len, 3, "broadcast_signed payload length");
	ASSERT_EQ(frame.dst_addr_len, 0, "broadcast_signed has no destination");
	ASSERT_EQ(frame.signer_iid_present, false, "no SIID parsed from wire");
	ASSERT_EQ(lichen_frame_write(&frame, rebuilt, sizeof(rebuilt)), (int)len,
		  "serialize canonical signed broadcast");
	ASSERT_EQ(memcmp(rebuilt, wire, len), 0,
		  "signed broadcast round-trips byte-for-byte (LLSec 0x20)");

	memset(&frame, 0, sizeof(frame));
	len = hex_decode(short_hex, wire, sizeof(wire));
	ASSERT_EQ(len, 61U, "decode short_addr_signed vector");
	ASSERT_EQ(lichen_frame_parse(&frame, wire, len), 0,
		  "parse accepts canonical signed short-address frame");
	ASSERT_EQ(frame.signature_present, true, "short_addr_signed is signed");
	ASSERT_EQ(frame.dst_addr_len, 2, "short_addr_signed destination length");
	ASSERT_EQ(frame.dst_addr[0], 0xAB, "short_addr_signed destination high byte");
	ASSERT_EQ(frame.dst_addr[1], 0xCD, "short_addr_signed destination low byte");
	ASSERT_EQ(frame.payload_len, 6, "short_addr_signed payload length");
	ASSERT_EQ(lichen_frame_write(&frame, rebuilt, sizeof(rebuilt)), (int)len,
		  "serialize canonical signed short-address frame");
	ASSERT_EQ(memcmp(rebuilt, wire, len), 0,
		  "signed short-address round-trips byte-for-byte");

	memset(&frame, 0, sizeof(frame));
	len = hex_decode(elided_hex, wire, sizeof(wire));
	ASSERT_EQ(len, 8U, "decode elided_addr vector");
	ASSERT_EQ(lichen_frame_parse(&frame, wire, len), 0,
		  "parse accepts canonical elided-address frame");
	ASSERT_EQ(frame.addr_mode, LICHEN_ADDR_ELIDED, "elided address mode");
	ASSERT_EQ(frame.dst_addr_len, 0, "elided mode carries no address bytes");
	ASSERT_EQ(frame.payload_len, 3, "elided_addr payload length");
	ASSERT_EQ(lichen_frame_write(&frame, rebuilt, sizeof(rebuilt)), (int)len,
		  "serialize canonical elided-address frame");
	ASSERT_EQ(memcmp(rebuilt, wire, len), 0,
		  "elided-address frame round-trips byte-for-byte");

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
	RUN_TEST(test_parse_accepts_minimum_and_maximum_bodies);
	RUN_TEST(test_write_rejects_null_frame);
	RUN_TEST(test_write_rejects_null_buf);
	RUN_TEST(test_write_rejects_invalid_policy);
	RUN_TEST(test_write_accepts_mic_selector_without_mic);
	RUN_TEST(test_write_parse_round_trip_unsigned);
	RUN_TEST(test_write_parse_round_trip_maximum);
	RUN_TEST(test_signed_encrypted_is_rejected);
	RUN_TEST(test_encryption_beats_reserved_bit);
	RUN_TEST(test_canonical_signed_vectors_round_trip);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
