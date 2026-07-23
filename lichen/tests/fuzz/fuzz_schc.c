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
	uint8_t packet[FUZZ_REASSEMBLY_BUF_SIZE];
	struct schc_reassembler reassembler;
	struct schc_reassembler_config config = {
		.rule_id = (uint8_t)(config_byte & 0x0F),
		.dtag = 0,
		.dtag_bits = 0,
		.window_bits = (uint8_t)(((config_byte >> 4) & 0x03) + 1),
		.fcn_bits = (uint8_t)(((config_byte >> 6) & 0x03) + 1),
		.tile_size = 32,
		.mode = SCHC_FRAGMENT_ACK_ON_ERROR,
	};

	if (config.window_bits > 7 || config.fcn_bits > 7 ||
	    config.dtag_bits + config.window_bits + config.fcn_bits > 8) {
		config.dtag_bits = 0;
		config.window_bits = 1;
		config.fcn_bits = 6;
	}

	int ret = schc_reassembler_init(&reassembler, &config,
					packet, sizeof(packet));
	if (ret != SCHC_OK) {
		return;
	}
	uint8_t response[10];
	uint8_t message[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];
	uint8_t rule_id = (data[0] & 1u) != 0u ?
		SCHC_FRAGMENT_RULE_B_TO_A : SCHC_FRAGMENT_RULE_A_TO_B;
	size_t offset = 1;
	while (offset < size) {
		uint8_t selector = data[offset++];
		size_t remaining = size - offset;
		size_t length = remaining < SCHC_FRAGMENT_MAX_MESSAGE_SIZE ? remaining :
				SCHC_FRAGMENT_MAX_MESSAGE_SIZE;
		if (length > 1u + selector % SCHC_FRAGMENT_MAX_MESSAGE_SIZE) {
			length = 1u + selector % SCHC_FRAGMENT_MAX_MESSAGE_SIZE;
		}
		if (length == 0u) {
			break;
		}
		struct schc_reassembly_result result;

		memcpy(message, &data[offset], length);
		message[0] = rule_id;
		(void)schc_reassembler_input(&reassembler, message, length,
					     &result);
		(void)schc_reassembler_next(&reassembler, response, sizeof(response),
					    &result);
		offset += length;
	}

	uint8_t tile[SCHC_FRAGMENT_TILE_SIZE];
	for (size_t i = 0; i < sizeof(tile); i++) {
		tile[i] = data[i % size];
	}
	struct schc_fragment fragment = {
		.tile = tile,
		.tile_len = sizeof(tile),
		.rule_id = rule_id,
		.window = data[1] & 1u,
		.fcn = (uint8_t)(data[1] % 63u),
	};
	if (fragment.window == 1u && fragment.fcn == 0u) {
		fragment.fcn = 1u;
	}
	int length = schc_fragment_encode(&fragment, message, sizeof(message));
	if (length > 0) {
		struct schc_reassembly_result result;

		(void)schc_reassembler_input(&reassembler, message, (size_t)length, &result);
		(void)schc_reassembler_input(&reassembler, message, (size_t)length, &result);
		message[0] = rule_id == SCHC_FRAGMENT_RULE_A_TO_B ?
			SCHC_FRAGMENT_RULE_B_TO_A : SCHC_FRAGMENT_RULE_A_TO_B;
		(void)schc_reassembler_input(&reassembler, message, (size_t)length, &result);
		message[0] = rule_id;
		tile[0] ^= 1u;
		length = schc_fragment_encode(&fragment, message, sizeof(message));
		if (length > 0) {
			(void)schc_reassembler_input(&reassembler, message, (size_t)length,
						     &result);
			(void)schc_reassembler_next(&reassembler, response, sizeof(response),
						    &result);
		}
		fragment.window ^= 1u;
		length = schc_fragment_encode(&fragment, message, sizeof(message));
		if (length > 0) {
			(void)schc_reassembler_input(&reassembler, message, (size_t)length,
						     &result);
			(void)schc_reassembler_input(&reassembler, message, (size_t)length,
						     &result);
		}
	}
	(void)schc_reassembler_expire(&reassembler);
	struct schc_reassembly_result result;
	(void)schc_reassembler_next(&reassembler, response, sizeof(response), &result);
}

static void fuzz_sender_success(const uint8_t *data, size_t size)
{
	if (size == 0u) {
		return;
	}
	uint8_t packet[SCHC_FRAGMENT_TILE_SIZE];
	uint8_t reassembly[SCHC_FRAGMENT_TILE_SIZE];
	uint8_t message[SCHC_FRAGMENT_MAX_MESSAGE_SIZE];
	uint8_t response[10];
	size_t packet_len = 1u + data[0] % SCHC_FRAGMENT_TILE_SIZE;
	for (size_t i = 0; i < packet_len; i++) {
		packet[i] = data[i % size];
	}
	struct schc_fragmenter sender;
	struct schc_reassembler receiver;
	struct schc_reassembly_result result;
	if (schc_fragmenter_init(&sender, SCHC_FRAGMENT_RULE_A_TO_B, packet,
				 packet_len, packet_len) != SCHC_OK ||
	    schc_reassembler_init(&receiver, reassembly, sizeof(reassembly),
				  packet_len) != SCHC_OK) {
		return;
	}
	(void)schc_fragmenter_next(&sender, message, 1);
	int length = schc_fragmenter_next(&sender, message, sizeof(message));
	if (length <= 0) {
		return;
	}
	(void)schc_fragmenter_timeout(&sender);
	(void)schc_fragmenter_next(&sender, response, 1);
	(void)schc_fragmenter_next(&sender, response, sizeof(response));
	(void)schc_reassembler_input(&receiver, message, (size_t)length, &result);
	(void)schc_reassembler_next(&receiver, response, 1, &result);
	int response_len = schc_reassembler_next(&receiver, response,
						 sizeof(response), &result);
	if (response_len > 0) {
		(void)schc_fragmenter_input(&sender, response, (size_t)response_len);
	}
	(void)schc_fragmenter_input(&sender, ((uint8_t[]){ 0x79, 0x40 }), 2);
	(void)schc_fragmenter_next(&sender, message, sizeof(message));
	(void)schc_fragmenter_timeout(&sender);
}

static void fuzz_ack_decode(const uint8_t *data, size_t size)
{
	if (size < 1) {
		return;
	}

	const uint8_t *ack_data = &data[1];
	size_t ack_len = size - 1;
	struct schc_ack ack;
	uint64_t assigned = (uint64_t)data[0] * UINT64_C(0x01010101010101);

	(void)schc_ack_decode(&ack, assigned, (data[0] & 1u) != 0u,
			      ack_data, ack_len);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0) {
		return 0;
	}

	/* Use first byte to select which function to fuzz */
	uint8_t selector = data[0] % 4;
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
	case 3:
		fuzz_sender_success(payload, payload_len);
		break;
	}

	return 0;
}

#ifdef FUZZ_STANDALONE
/*
 * Standalone driver for environments without libFuzzer runtime (e.g., AppleClang).
 * Uses xorshift64 PRNG for reproducible random input generation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* xorshift64 PRNG - fast, simple, good enough for fuzzing */
static uint64_t xorshift64_state;

static uint64_t xorshift64(void)
{
	uint64_t x = xorshift64_state;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	xorshift64_state = x;
	return x;
}

/* Fill buffer with random bytes */
static void fill_random(uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if ((i % 8) == 0) {
			uint64_t r = xorshift64();
			buf[i] = (uint8_t)r;
		} else {
			buf[i] = (uint8_t)(xorshift64_state >> ((i % 8) * 8));
		}
	}
}

int main(int argc, char **argv)
{
	uint64_t iterations = 1000000;  /* 1M default */
	uint64_t seed = (uint64_t)time(NULL);

	/* Parse args: [iterations] [seed] */
	if (argc > 1) {
		iterations = (uint64_t)strtoull(argv[1], NULL, 10);
	}
	if (argc > 2) {
		seed = (uint64_t)strtoull(argv[2], NULL, 10);
	}

	xorshift64_state = seed ? seed : 1;

	fprintf(stderr, "fuzz_schc standalone: %llu iterations, seed=%llu\n",
		(unsigned long long)iterations, (unsigned long long)seed);

	uint8_t buf[512];  /* Max plausible SCHC input size */
	uint64_t progress_interval = iterations / 10;
	if (progress_interval == 0) progress_interval = 1;

	for (uint64_t i = 0; i < iterations; i++) {
		/* Random length: 0-255 bytes, biased toward SCHC-sized inputs */
		size_t len = (size_t)(xorshift64() % 128);
		if (xorshift64() % 10 == 0) {
			len = (size_t)(xorshift64() % 256);  /* Occasionally larger */
		}
		if (xorshift64() % 20 == 0) {
			len = (size_t)(xorshift64() % 512);  /* Rarely much larger */
		}

		fill_random(buf, len);
		LLVMFuzzerTestOneInput(buf, len);

		if ((i + 1) % progress_interval == 0) {
			fprintf(stderr, "Progress: %llu/%llu (%llu%%)\n",
				(unsigned long long)(i + 1),
				(unsigned long long)iterations,
				(unsigned long long)((i + 1) * 100 / iterations));
		}
	}

	fprintf(stderr, "fuzz_schc: %llu iterations completed, no crashes\n",
		(unsigned long long)iterations);
	return 0;
}
#endif /* FUZZ_STANDALONE */
