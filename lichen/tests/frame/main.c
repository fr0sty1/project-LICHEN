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

#include "frame_vectors.h"

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

static int vector_bytes_equal(const char *name, const char *field,
			      const uint8_t *actual, size_t actual_len,
			      const char *expected_hex)
{
	uint8_t expected[LICHEN_MAX_FRAME_LEN];
	size_t expected_len = hex_decode(expected_hex, expected, sizeof(expected));

	if (expected_len != actual_len ||
	    (actual_len > 0U && memcmp(actual, expected, actual_len) != 0)) {
		printf("  FAIL: %s: %s mismatch\n", name, field);
		return 0;
	}
	return 1;
}

static int frame_from_vector(const struct canonical_frame_vector *vector,
			     struct lichen_frame *frame,
			     uint8_t payload[LICHEN_FRAME_PAYLOAD_MAX + 1U])
{
	size_t dst_len = strlen(vector->dst_hex) / 2U;
	size_t signer_len = strlen(vector->signer_hex) / 2U;
	size_t payload_len = strlen(vector->payload_hex) / 2U;
	size_t mic_len = strlen(vector->mic_hex) / 2U;

	if (dst_len > sizeof(frame->dst_addr) ||
	    signer_len > sizeof(frame->signer_iid) ||
	    payload_len > LICHEN_FRAME_PAYLOAD_MAX + 1U ||
	    mic_len > sizeof(frame->mic)) {
		return 0;
	}

	memset(frame, 0, sizeof(*frame));
	if (hex_decode(vector->dst_hex, frame->dst_addr,
		       sizeof(frame->dst_addr)) != dst_len ||
	    hex_decode(vector->signer_hex, frame->signer_iid,
		       sizeof(frame->signer_iid)) != signer_len ||
	    hex_decode(vector->payload_hex, payload,
		       LICHEN_FRAME_PAYLOAD_MAX + 1U) != payload_len ||
	    hex_decode(vector->mic_hex, frame->mic,
		       sizeof(frame->mic)) != mic_len) {
		return 0;
	}

	frame->epoch = vector->epoch;
	frame->seqnum = vector->seqnum;
	frame->dst_addr_len = (uint8_t)dst_len;
	frame->signer_iid_len = (uint8_t)signer_len;
	frame->signer_iid_present = signer_len > 0U;
	frame->payload = payload_len > 0U ? payload : NULL;
	frame->payload_len = payload_len;
	frame->inner_payload_len = payload_len;
	frame->mic_len = (uint8_t)mic_len;
	frame->addr_mode = (enum lichen_addr_mode)vector->addr_mode;
	frame->mic_length = (enum lichen_mic_len)vector->mic_length;
	frame->signature_present = vector->signature_present;
	frame->encrypted = vector->encrypted;

	return 1;
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
	/* spec frame.json si_without_signature_reject: LLSec 0x80 */
	uint8_t si_only[] = { 0x08, 0x80, 0x01, 0x12, 0x34, 0xaa, 0xbb, 0xcc, 0xdd };
	/* S set without SI: signed frames MUST set both bits (spec 4.2) */
	uint8_t s_only[] = { 0x08, 0x20, 0x01, 0x12, 0x34, 0xaa, 0xbb, 0xcc, 0xdd };
	uint8_t too_short[] = { 0x02, 0x00, 0x01 };
	uint8_t bad_selector[] = { 0x08, 0x08, 0x01, 0x12, 0x34,
				   0xaa, 0xbb, 0xcc, 0xdd };
	struct lichen_frame frame;

	memset(&frame, 0, sizeof(frame));

	ASSERT_EQ(lichen_frame_parse(&frame, &empty, 0), -EINVAL,
		  "parse rejects empty frame");
	ASSERT_EQ(lichen_frame_parse(&frame, truncated, sizeof(truncated)), -EINVAL,
		  "parse rejects length mismatch");
	ASSERT_EQ(lichen_frame_parse(&frame, si_only, sizeof(si_only)), -EINVAL,
		  "parse rejects SI bit without signature");
	ASSERT_EQ(lichen_frame_parse(&frame, s_only, sizeof(s_only)), -EINVAL,
		  "parse rejects signature bit without SI");
	ASSERT_EQ(lichen_frame_parse(&frame, too_short, sizeof(too_short)), -EINVAL,
		  "parse rejects short body");
	ASSERT_EQ(lichen_frame_parse(&frame, bad_selector, sizeof(bad_selector)),
		  -EINVAL, "parse rejects reserved MIC-length selector");
	for (uint8_t selector = 2U; selector <= 7U; ++selector) {
		bad_selector[1] = (uint8_t)(selector << 2U);
		ASSERT_EQ(lichen_frame_parse(&frame, bad_selector,
					     sizeof(bad_selector)), -EINVAL,
			  "parse rejects every reserved MIC-length selector");
	}

	return 1;
}

static int test_failure_paths_are_atomic(void)
{
	static const uint8_t reserved_selector[] = { 0x04, 0x08, 0x01, 0x12, 0x34 };
	static const uint8_t s_only[] = { 0x04, 0x20, 0x01, 0x12, 0x34 };
	static const uint8_t si_only[] = { 0x04, 0x80, 0x01, 0x12, 0x34 };
	static const uint8_t payload[] = { 0x55 };
	struct lichen_frame frame;
	struct lichen_frame original;
	uint8_t output[16];
	uint8_t original_output[sizeof(output)];

	memset(&frame, 0xa5, sizeof(frame));
	original = frame;
	ASSERT_EQ(lichen_frame_parse(&frame, reserved_selector,
				     sizeof(reserved_selector)), -EINVAL,
		  "failed parse rejects reserved selector");
	ASSERT_EQ(memcmp(&frame, &original, sizeof(frame)), 0,
		  "failed parse leaves destination unchanged");
	ASSERT_EQ(lichen_frame_parse(&frame, s_only, sizeof(s_only)), -EINVAL,
		  "S-only parse is rejected atomically");
	ASSERT_EQ(memcmp(&frame, &original, sizeof(frame)), 0,
		  "S-only rejection leaves destination unchanged");
	ASSERT_EQ(lichen_frame_parse(&frame, si_only, sizeof(si_only)), -EINVAL,
		  "SI-only parse is rejected atomically");
	ASSERT_EQ(memcmp(&frame, &original, sizeof(frame)), 0,
		  "SI-only rejection leaves destination unchanged");

	memset(&frame, 0, sizeof(frame));
	frame.payload_len = 1U;
	frame.mic_len = 0U;
	memset(output, 0x5a, sizeof(output));
	memcpy(original_output, output, sizeof(output));
	ASSERT_EQ(lichen_frame_write(&frame, output, sizeof(output)), -EINVAL,
		  "write rejects NULL non-empty payload before output");
	ASSERT_EQ(memcmp(output, original_output, sizeof(output)), 0,
		  "invalid payload leaves output unchanged");

	frame.payload = payload;
	ASSERT_EQ(lichen_frame_write(&frame, output,
				     LICHEN_FRAME_FIXED_HEADER_LEN - 1U), -ENOMEM,
		  "write rejects short output buffer before output");
	ASSERT_EQ(memcmp(output, original_output, sizeof(output)), 0,
		  "short buffer leaves output unchanged");

	memset(&frame, 0, sizeof(frame));
	frame.signature_present = true;
	frame.mic_len = LICHEN_SIG_LEN;
	ASSERT_EQ(lichen_frame_write(&frame, output, sizeof(output)), -EINVAL,
		  "S-only model is rejected before serialization");
	ASSERT_EQ(memcmp(output, original_output, sizeof(output)), 0,
		  "S-only model leaves output unchanged");

	memset(&frame, 0, sizeof(frame));
	frame.signer_iid_present = true;
	frame.signer_iid_len = LICHEN_ADDR_MAX;
	ASSERT_EQ(lichen_frame_write(&frame, output, sizeof(output)), -EINVAL,
		  "SI-only model is rejected before serialization");
	ASSERT_EQ(memcmp(output, original_output, sizeof(output)), 0,
		  "SI-only model leaves output unchanged");

	return 1;
}

static int test_all_canonical_shared_vectors(void)
{
	uint8_t wire[LICHEN_MAX_FRAME_LEN + 1U];
	uint8_t rebuilt[LICHEN_MAX_FRAME_LEN];
	uint8_t constructed_wire[LICHEN_MAX_FRAME_LEN];
	uint8_t original_wire[LICHEN_MAX_FRAME_LEN];
	uint8_t constructed_payload[LICHEN_FRAME_PAYLOAD_MAX + 1U];
	struct lichen_frame frame;
	struct lichen_frame original;
	struct lichen_frame constructed;
	struct lichen_frame reparsed;

	for (size_t i = 0U; i < CANONICAL_FRAME_VECTOR_COUNT; ++i) {
		const struct canonical_frame_vector *vector =
			&canonical_frame_vectors[i];
		size_t wire_len = hex_decode(vector->encoded_hex, wire, sizeof(wire));
		int ret;

		if (wire_len == 0U) {
			printf("  FAIL: %s: encoded vector is empty or invalid\n",
			       vector->name);
			return 0;
		}
		if (!frame_from_vector(vector, &constructed,
				       constructed_payload)) {
			printf("  FAIL: %s: cannot construct frame from fields\n",
			       vector->name);
			return 0;
		}
		memset(constructed_wire, 0x5a, sizeof(constructed_wire));
		memcpy(original_wire, constructed_wire, sizeof(original_wire));
		ret = lichen_frame_write(&constructed, constructed_wire,
					 sizeof(constructed_wire));
		if (vector->expected_parse < 0) {
			if (ret != vector->expected_parse ||
			    memcmp(constructed_wire, original_wire,
				   sizeof(constructed_wire)) != 0) {
				printf("  FAIL: %s: constructed error returned %d, expected %d, or mutated output\n",
				       vector->name, ret, vector->expected_parse);
				return 0;
			}
		} else if (ret != (int)wire_len ||
			   memcmp(constructed_wire, wire, wire_len) != 0) {
			printf("  FAIL: %s: constructed serialization differs from canonical wire\n",
			       vector->name);
			return 0;
		} else {
			memset(&reparsed, 0, sizeof(reparsed));
			if (lichen_frame_parse(&reparsed, constructed_wire,
					       (size_t)ret) != 0 ||
			    reparsed.epoch != constructed.epoch ||
			    reparsed.seqnum != constructed.seqnum ||
			    reparsed.addr_mode != constructed.addr_mode ||
			    reparsed.mic_length != constructed.mic_length ||
			    reparsed.signature_present !=
				    constructed.signature_present ||
			    reparsed.encrypted != constructed.encrypted ||
			    reparsed.payload_len != constructed.payload_len) {
				printf("  FAIL: %s: constructed frame did not parse round-trip\n",
				       vector->name);
				return 0;
			}
		}
		memset(&frame, 0xa5, sizeof(frame));
		original = frame;
		ret = lichen_frame_parse(&frame, wire, wire_len);
		if (ret != vector->expected_parse) {
			printf("  FAIL: %s: parse returned %d, expected %d\n",
			       vector->name, ret, vector->expected_parse);
			return 0;
		}
		if (ret < 0) {
			if (memcmp(&frame, &original, sizeof(frame)) != 0) {
				printf("  FAIL: %s: failed parse mutated destination\n",
				       vector->name);
				return 0;
			}
			continue;
		}
		for (size_t cut = 0U; cut < wire_len; ++cut) {
			memset(&frame, 0xa5, sizeof(frame));
			original = frame;
			if (lichen_frame_parse(&frame, wire, cut) >= 0 ||
			    memcmp(&frame, &original, sizeof(frame)) != 0) {
				printf("  FAIL: %s: accepted/mutated at truncation %zu\n",
				       vector->name, cut);
				return 0;
			}
		}
		wire[wire_len] = 0U;
		memset(&frame, 0xa5, sizeof(frame));
		original = frame;
		if (lichen_frame_parse(&frame, wire, wire_len + 1U) >= 0 ||
		    memcmp(&frame, &original, sizeof(frame)) != 0) {
			printf("  FAIL: %s: accepted/mutated with trailing byte\n",
			       vector->name);
			return 0;
		}
		ASSERT_EQ(lichen_frame_parse(&frame, wire, wire_len), 0,
			  "reparse canonical vector after malformed-boundary checks");

		if (frame.epoch != vector->epoch || frame.seqnum != vector->seqnum ||
		    frame.addr_mode != (enum lichen_addr_mode)vector->addr_mode ||
		    frame.mic_length != (enum lichen_mic_len)vector->mic_length ||
		    frame.signature_present != vector->signature_present ||
		    frame.encrypted != vector->encrypted ||
		    frame.inner_payload_len != frame.payload_len) {
			printf("  FAIL: %s: parsed scalar fields mismatch\n", vector->name);
			return 0;
		}
		if (!vector_bytes_equal(vector->name, "destination", frame.dst_addr,
					frame.dst_addr_len, vector->dst_hex) ||
		    !vector_bytes_equal(vector->name, "signer", frame.signer_iid,
					frame.signer_iid_len, vector->signer_hex) ||
		    !vector_bytes_equal(vector->name, "payload", frame.payload,
					frame.payload_len, vector->payload_hex) ||
		    !vector_bytes_equal(vector->name, "MIC", frame.mic,
					frame.mic_len, vector->mic_hex)) {
			return 0;
		}

		ret = lichen_frame_write(&frame, rebuilt, sizeof(rebuilt));
		if (ret != (int)wire_len || memcmp(rebuilt, wire, wire_len) != 0) {
			printf("  FAIL: %s: serialization differs from canonical wire\n",
			       vector->name);
			return 0;
		}
	}

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
		  "write rejects SI bit without signature");

	memset(&frame, 0, sizeof(frame));
	frame.signature_present = true;
	frame.mic_len = LICHEN_SIG_LEN;
	ASSERT_EQ(lichen_frame_write(&frame, buf, sizeof(buf)), -EINVAL,
		  "write rejects signature without signer EUI-64");

	memset(&frame, 0, sizeof(frame));
	frame.signature_present = true;
	frame.signer_iid_present = true;
	frame.signer_iid_len = 7U;
	frame.mic_len = LICHEN_SIG_LEN;
	ASSERT_EQ(lichen_frame_write(&frame, buf, sizeof(buf)), -EINVAL,
		  "write rejects non-8-byte signer EUI-64");

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

static int test_write_parse_round_trip_mic64_selector(void)
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
	input.mic_length = LICHEN_MIC_64;

	frame_len = lichen_frame_write(&input, buf, sizeof(buf));
	ASSERT_EQ(frame_len, 8, "write emits unsigned frame with selector 1");
	/* Oracle: spec/02-physical-link.md section 4.2 LLSec bit table —
	 * addr mode bits 1-0 = 00, MIC-length selector bits 4-2 = 001,
	 * S/E/SI clear. Matches mic_length_selector.json
	 * mic_length_1_unsigned llsec_byte 0x04; only defined selectors
	 * (0 and 1) may appear in bits 2-4. */
	ASSERT_EQ(buf[1], 0x04, "64-bit selector encodes as LLSec bits 2-4=001");

	memset(&output, 0, sizeof(output));
	ASSERT_EQ(lichen_frame_parse(&output, buf, (size_t)frame_len), 0,
		  "parse accepts serialized selector-1 frame");
	ASSERT_EQ(output.mic_length, LICHEN_MIC_64, "round-trip preserves selector");
	ASSERT_EQ(output.epoch, input.epoch, "round-trip preserves epoch");
	ASSERT_EQ(output.seqnum, input.seqnum, "round-trip preserves sequence number");
	ASSERT_EQ(output.mic_len, 0, "selector-1 unsigned frame still carries no MIC");
	ASSERT_EQ(output.payload_len, sizeof(payload), "round-trip preserves payload length");
	if (memcmp(output.payload, payload, sizeof(payload)) != 0) {
		printf("  FAIL: round-trip preserves payload\n");
		return 0;
	}

	return 1;
}

static int test_parse_accepts_selector1_vector(void)
{
	/* mic_length_selector.json mic_length_1_unsigned: LLSec=0x04 is a
	 * valid compatibility selector on the wire. */
	static const char hex[] = "0704010002616263";
	uint8_t wire[8];
	struct lichen_frame frame;

	memset(&frame, 0, sizeof(frame));
	ASSERT_EQ(hex_decode(hex, wire, sizeof(wire)), sizeof(wire),
		  "decode selector-1 vector");
	ASSERT_EQ(lichen_frame_parse(&frame, wire, sizeof(wire)), 0,
		  "parse accepts canonical selector-1 vector");
	ASSERT_EQ(frame.mic_length, LICHEN_MIC_64, "vector parses as selector 1");
	ASSERT_EQ(frame.mic_len, 0, "selector-1 vector is unsigned");
	ASSERT_EQ(frame.payload_len, 3, "selector-1 vector payload length");

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
	frame.signer_iid_present = true;
	frame.signer_iid_len = LICHEN_ADDR_MAX;
	frame.encrypted = true;
	frame.mic_len = LICHEN_SIG_LEN;
	frame.payload = &wire[5];
	frame.payload_len = 1U;
	ASSERT_EQ(lichen_frame_write(&frame, wire, sizeof(wire)), -EPROTONOSUPPORT,
		  "write rejects encrypted frame as unsupported");

	return 1;
}

static int test_encryption_beats_other_llsec_policy(void)
{
	/* link_frame.json signed_encrypted: LLSec=0xE0 sets E, S and SI; the
	 * rejection category must be unsupported encryption (spec 4.2). */
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
	/* link_frame.json broadcast_signed (LLSec 0xA0 = S|SI) */
	static const char bcast_hex[] =
		"3fa00100027fd5cfc679ab6342616263"
		"1d8efcec77d664081e6f0bdcfe1e444688aab91502ebe4680d67a4e0d1b158ea4"
		"7cac9c1b0417489a603751692869508";
	/* link_frame.json short_addr_signed (LLSec 0xA1 = S|SI|short) */
	static const char short_hex[] =
		"44a1010002abcd7fd5cfc679ab634268656c6c6f21"
		"c15f23c6e53eebc34ae79d38284a8da8ff0469d6bdcc176e55bfd2585fc450f8"
		"a191804e7d0f184cfc5038f309f2b906";
	/* link_frame.json elided_addr (unsigned, addr_mode=3) */
	static const char elided_hex[] = "0703051234637478";
	uint8_t wire[96];
	uint8_t rebuilt[sizeof(wire)];
	struct lichen_frame frame;
	size_t len;

	memset(&frame, 0, sizeof(frame));
	len = hex_decode(bcast_hex, wire, sizeof(wire));
	ASSERT_EQ(len, 64U, "decode broadcast_signed vector");
	ASSERT_EQ(lichen_frame_parse(&frame, wire, len), 0,
		  "parse accepts canonical signed broadcast");
	ASSERT_EQ(frame.signature_present, true, "broadcast_signed is signed");
	ASSERT_EQ(frame.signer_iid_present, true, "broadcast_signed carries SIID");
	ASSERT_EQ(frame.signer_iid_len, 8U, "broadcast_signed SIID is 8 bytes");
	ASSERT_EQ(frame.mic_length, LICHEN_MIC_32, "broadcast_signed selector");
	ASSERT_EQ(frame.mic_len, LICHEN_SIG_LEN, "signature occupies MIC field");
	ASSERT_EQ(frame.payload_len, 3, "broadcast_signed payload length");
	ASSERT_EQ(frame.dst_addr_len, 0, "broadcast_signed has no destination");
	if (memcmp(frame.signer_iid, "\x7f\xd5\xcf\xc6\x79\xab\x63\x42", 8) != 0) {
		printf("  FAIL: broadcast_signed signer EUI-64 bytes\n");
		return 0;
	}
	ASSERT_EQ(lichen_frame_write(&frame, rebuilt, sizeof(rebuilt)), (int)len,
		  "serialize canonical signed broadcast");
	ASSERT_EQ(memcmp(rebuilt, wire, len), 0,
		  "signed broadcast round-trips byte-for-byte (LLSec 0xA0)");

	memset(&frame, 0, sizeof(frame));
	len = hex_decode(short_hex, wire, sizeof(wire));
	ASSERT_EQ(len, 69U, "decode short_addr_signed vector");
	ASSERT_EQ(lichen_frame_parse(&frame, wire, len), 0,
		  "parse accepts canonical signed short-address frame");
	ASSERT_EQ(frame.signature_present, true, "short_addr_signed is signed");
	ASSERT_EQ(frame.signer_iid_present, true, "short_addr_signed carries SIID");
	ASSERT_EQ(frame.dst_addr_len, 2, "short_addr_signed destination length");
	ASSERT_EQ(frame.dst_addr[0], 0xAB, "short_addr_signed destination high byte");
	ASSERT_EQ(frame.dst_addr[1], 0xCD, "short_addr_signed destination low byte");
	ASSERT_EQ(frame.payload_len, 6, "short_addr_signed payload length");
	ASSERT_EQ(lichen_frame_write(&frame, rebuilt, sizeof(rebuilt)), (int)len,
		  "serialize canonical signed short-address frame");
	ASSERT_EQ(memcmp(rebuilt, wire, len), 0,
		  "signed short-address round-trips byte-for-byte");

	/* link_frame.json signed_max_payload: 194-byte payload + SIID + 48-byte
	 * signature fills the 254-byte body exactly. */
	static const char signed_max_hex[] =
		"fea00000017fd5cfc679ab6342"
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
		"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
		"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
		"c0c1"
		"cf1b6d2f2cab19b9a3498a4ed248bb49d3271af78b8cf1e9b540ddc638b2fe05"
		"d13519891561914c1e7a3e4ea3c9560c";
	uint8_t signed_max[LICHEN_MAX_FRAME_LEN];
	uint8_t signed_max_rebuilt[LICHEN_MAX_FRAME_LEN];

	memset(&frame, 0, sizeof(frame));
	memset(signed_max, 0, sizeof(signed_max));
	len = hex_decode(signed_max_hex, signed_max, sizeof(signed_max));
	ASSERT_EQ(len, sizeof(signed_max), "decode signed_max_payload vector");
	ASSERT_EQ(signed_max[0], LICHEN_MAX_FRAME_BODY_LEN,
		  "signed_max_payload body is 254 bytes");
	ASSERT_EQ(lichen_frame_parse(&frame, signed_max, len), 0,
		  "parse accepts signed maximum-payload frame");
	ASSERT_EQ(frame.payload_len, 194U, "signed maximum payload length");
	ASSERT_EQ(frame.signer_iid_present, true, "signed maximum carries SIID");
	ASSERT_EQ(frame.signer_iid_len, 8U, "signed maximum SIID length");
	ASSERT_EQ(frame.mic_len, LICHEN_SIG_LEN, "signed maximum MIC length");
	ASSERT_EQ(lichen_frame_write(&frame, signed_max_rebuilt,
				     sizeof(signed_max_rebuilt)),
		  (int)sizeof(signed_max_rebuilt),
		  "serialize canonical signed maximum frame");
	ASSERT_EQ(memcmp(signed_max_rebuilt, signed_max, len), 0,
		  "signed maximum frame round-trips byte-for-byte");

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
	RUN_TEST(test_failure_paths_are_atomic);
	RUN_TEST(test_all_canonical_shared_vectors);
	RUN_TEST(test_parse_rejects_oversize_frames);
	RUN_TEST(test_parse_accepts_minimum_and_maximum_bodies);
	RUN_TEST(test_write_rejects_null_frame);
	RUN_TEST(test_write_rejects_null_buf);
	RUN_TEST(test_write_rejects_invalid_policy);
	RUN_TEST(test_write_accepts_mic_selector_without_mic);
	RUN_TEST(test_write_parse_round_trip_unsigned);
	RUN_TEST(test_write_parse_round_trip_mic64_selector);
	RUN_TEST(test_parse_accepts_selector1_vector);
	RUN_TEST(test_write_parse_round_trip_maximum);
	RUN_TEST(test_signed_encrypted_is_rejected);
	RUN_TEST(test_encryption_beats_other_llsec_policy);
	RUN_TEST(test_canonical_signed_vectors_round_trip);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
