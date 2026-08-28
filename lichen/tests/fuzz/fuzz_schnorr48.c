/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file fuzz_schnorr48.c
 * @brief libFuzzer harness for schnorr48_verify
 *
 * Fuzzes signature verification with arbitrary inputs.
 * Input format: message || signature (48B) || pubkey (32B)
 *
 * Build with:
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *     -DCONFIG_LICHEN_CRYPTO_MONOCYPHER=1 \
 *     -I../../include \
 *     -I../../subsys/lichen/link/include \
 *     -I../../subsys/lichen/crypto \
 *     fuzz_schnorr48.c \
 *     ../../subsys/lichen/link/schnorr48.c \
 *     ../../subsys/lichen/crypto/monocypher.c \
 *     ../../subsys/lichen/crypto/monocypher-ed25519.c \
 *     -o fuzz_schnorr48
 *
 * When built with libFuzzer (-fsanitize=fuzzer), exposes LLVMFuzzerTestOneInput.
 * When built standalone (FUZZ_STANDALONE), includes main() with PRNG-based input
 * generation for environments without libFuzzer runtime.
 */

#include <stddef.h>
#include <stdint.h>
#include <lichen/schnorr48.h>

/* Minimum input: signature (48B) + pubkey (32B) = 80 bytes */
#define MIN_INPUT_SIZE (SCHNORR48_SIG_LEN + SCHNORR48_PUBKEY_LEN)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < MIN_INPUT_SIZE) {
		return 0;
	}

	/* Parse input: message || signature || pubkey */
	size_t msg_len = size - MIN_INPUT_SIZE;
	const uint8_t *msg = (msg_len > 0) ? data : NULL;
	const uint8_t *sig = data + msg_len;
	const uint8_t *pubkey = sig + SCHNORR48_SIG_LEN;

	/*
	 * Call verify - must not crash regardless of input.
	 * Return value is intentionally ignored; we're testing
	 * that malformed input doesn't cause undefined behavior.
	 */
	(void)schnorr48_verify(pubkey, msg, msg_len, sig, SCHNORR48_SIG_LEN);

	return 0;
}

#ifdef FUZZ_STANDALONE
/*
 * Standalone driver for environments without libFuzzer runtime (e.g., AppleClang).
 * Uses xorshift64 PRNG for reproducible random input generation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

	fprintf(stderr, "fuzz_schnorr48 standalone: %llu iterations, seed=%llu\n",
		(unsigned long long)iterations, (unsigned long long)seed);

	uint8_t buf[512];  /* msg || sig(48) || pubkey(32); 512 covers plausible msgs */
	uint64_t progress_interval = iterations / 10;
	if (progress_interval == 0) progress_interval = 1;

	for (uint64_t i = 0; i < iterations; i++) {
		/* Random length: 0-511 bytes, biased toward signature-sized inputs */
		size_t len = (size_t)(xorshift64() % 200);
		if (xorshift64() % 10 == 0) {
			len = (size_t)(xorshift64() % 512);  /* Occasionally larger */
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

	fprintf(stderr, "fuzz_schnorr48: %llu iterations completed, no crashes\n",
		(unsigned long long)iterations);
	return 0;
}
#endif /* FUZZ_STANDALONE */
