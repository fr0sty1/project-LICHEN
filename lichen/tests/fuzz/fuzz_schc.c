/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file fuzz_schc.c
 * @brief libFuzzer harness for SCHC decompression and reassembly.
 *
 * Build with:
 *   clang -fsanitize=fuzzer,address,undefined -g -O1 \
 *     -I../../subsys/schc/include \
 *     fuzz_schc.c ../../subsys/schc/schc.c \
 *     -o fuzz_schc
 *
 * Run:
 *   ./fuzz_schc [-max_len=256] [-jobs=4]
 */

#include <schc/schc.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define FUZZ_OUT_BUF_SIZE 4096
#define FUZZ_REASSEMBLY_BUF_SIZE 2048

/* Mock decompression rule that echoes input after stripping rule ID */
static int mock_decompress(const struct schc_rule *rule,
			   const uint8_t *data, size_t data_len,
			   uint8_t *out, size_t out_len)
{
	(void)rule;

	if (data_len < 1) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t payload_len = data_len - 1;

	if (out_len < payload_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	memcpy(out, &data[1], payload_len);
	return (int)payload_len;
}

/* Mock compression rule (not exercised by this harness, but needed for struct) */
static int mock_compress(const struct schc_rule *rule,
			 const uint8_t *packet, size_t packet_len,
			 uint8_t *out, size_t out_len)
{
	(void)rule;
	(void)packet;
	(void)packet_len;
	(void)out;
	(void)out_len;

	return SCHC_ERR_NO_MATCHING_RULE;
}

static const struct schc_rule fuzz_rules[] = {
	{
		.rule_id = 0x01,
		.compress = mock_compress,
		.decompress = mock_decompress,
		.user_data = NULL,
	},
	{
		.rule_id = 0x02,
		.compress = mock_compress,
		.decompress = mock_decompress,
		.user_data = NULL,
	},
};

static const struct schc_profile fuzz_profile_with_fallback = {
	.rules = fuzz_rules,
	.rule_count = sizeof(fuzz_rules) / sizeof(fuzz_rules[0]),
	.uncompressed_rule_id = 0x00,
	.use_uncompressed_fallback = true,
};

static const struct schc_profile fuzz_profile_no_fallback = {
	.rules = fuzz_rules,
	.rule_count = sizeof(fuzz_rules) / sizeof(fuzz_rules[0]),
	.uncompressed_rule_id = 0x00,
	.use_uncompressed_fallback = false,
};

static const struct schc_profile fuzz_profile_empty = {
	.rules = NULL,
	.rule_count = 0,
	.uncompressed_rule_id = 0xFF,
	.use_uncompressed_fallback = true,
};

static void fuzz_decompress(const uint8_t *data, size_t size)
{
	uint8_t out[FUZZ_OUT_BUF_SIZE];

	/* Test with profile that has rules + fallback */
	(void)schc_decompress(&fuzz_profile_with_fallback, data, size,
			      out, sizeof(out));

	/* Test with profile that has rules but no fallback */
	(void)schc_decompress(&fuzz_profile_no_fallback, data, size,
			      out, sizeof(out));

	/* Test with empty profile + fallback */
	(void)schc_decompress(&fuzz_profile_empty, data, size,
			      out, sizeof(out));

	/* Test with small output buffer to exercise buffer checks */
	if (size > 0) {
		uint8_t tiny_out[1];

		(void)schc_decompress(&fuzz_profile_with_fallback, data, size,
				      tiny_out, sizeof(tiny_out));
	}
}

static void fuzz_reassembler(const uint8_t *data, size_t size)
{
	if (size < 2) {
		return;
	}

	/* Use first byte to select configuration parameters */
	uint8_t config_byte = data[0];
	const uint8_t *fragment = &data[1];
	size_t fragment_len = size - 1;

	uint8_t packet[FUZZ_REASSEMBLY_BUF_SIZE];
	struct schc_reassembler reassembler;
	struct schc_reassembler_config config = {
		.rule_id = (uint8_t)(config_byte & 0x0F),
		.dtag = 0,
		.dtag_bits = 0,
		.window_bits = (uint8_t)(((config_byte >> 4) & 0x03) + 1),
		.fcn_bits = (uint8_t)(((config_byte >> 6) & 0x03) + 1),
		.tile_size = 32,
		.mode = SCHC_FRAGMENT_ACK_ALWAYS,
	};

	/* Validate config to avoid init failures unrelated to fuzzing */
	if (config.window_bits > 7 || config.fcn_bits > 7 ||
	    config.dtag_bits + config.window_bits + config.fcn_bits > 8) {
		config.window_bits = 2;
		config.fcn_bits = 6;
	}

	int ret = schc_reassembler_init(&reassembler, &config,
					packet, sizeof(packet));
	if (ret != SCHC_OK) {
		return;
	}

	/* Feed fragment to reassembler */
	bool complete = false;

	(void)schc_reassembler_input(&reassembler, fragment, fragment_len,
				     &complete);

	/* Exercise ACK generation */
	struct schc_ack ack;

	(void)schc_reassembler_ack(&reassembler, &ack);
}

static void fuzz_ack_decode(const uint8_t *data, size_t size)
{
	if (size < 1) {
		return;
	}

	/* Use first byte for config, rest for data */
	uint8_t config_byte = data[0];
	const uint8_t *ack_data = &data[1];
	size_t ack_len = size - 1;

	uint8_t dtag_bits = (uint8_t)(config_byte & 0x07);
	uint8_t window_bits = (uint8_t)(((config_byte >> 3) & 0x07) + 1);
	uint8_t bitmap_bits = (uint8_t)((config_byte >> 6) & 0x03);

	/* Clamp to valid ranges */
	if (window_bits > 7) {
		window_bits = 7;
	}
	if (dtag_bits + window_bits > 8) {
		dtag_bits = 0;
	}
	if (bitmap_bits > 63) {
		bitmap_bits = 63;
	}

	struct schc_ack ack;

	(void)schc_ack_decode(&ack, dtag_bits, window_bits, bitmap_bits,
			      ack_data, ack_len);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0) {
		return 0;
	}

	/* Use first byte to select which function to fuzz */
	uint8_t selector = data[0] % 3;
	const uint8_t *payload = &data[1];
	size_t payload_len = size > 0 ? size - 1 : 0;

	switch (selector) {
	case 0:
		fuzz_decompress(payload, payload_len);
		break;
	case 1:
		fuzz_reassembler(payload, payload_len);
		break;
	case 2:
		fuzz_ack_decode(payload, payload_len);
		break;
	}

	return 0;
}
