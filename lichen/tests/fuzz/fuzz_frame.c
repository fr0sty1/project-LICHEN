/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file fuzz_frame.c
 * @brief libFuzzer harness for LICHEN frame parser
 *
 * Exercises lichen_frame_parse() with arbitrary byte sequences to find
 * crashes, buffer overflows, and undefined behavior.
 *
 * When built with libFuzzer (-fsanitize=fuzzer), exposes LLVMFuzzerTestOneInput.
 * When built standalone (FUZZ_STANDALONE), includes main() with PRNG-based input
 * generation for environments without libFuzzer runtime.
 */

#include <stdint.h>
#include <stddef.h>
#include <lichen/link.h>

/**
 * @brief libFuzzer entry point.
 *
 * Called repeatedly with mutated inputs. The parser must not crash
 * or exhibit undefined behavior on any input.
 *
 * @param data  Fuzz input bytes
 * @param size  Length of input
 * @return 0 always (fuzzer protocol)
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct lichen_frame frame;

	/* Parser may return error codes, but must never crash */
	(void)lichen_frame_parse(&frame, data, size);

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

	fprintf(stderr, "fuzz_frame standalone: %llu iterations, seed=%llu\n",
		(unsigned long long)iterations, (unsigned long long)seed);

	uint8_t buf[512];  /* Max plausible frame size */
	uint64_t progress_interval = iterations / 10;
	if (progress_interval == 0) progress_interval = 1;

	for (uint64_t i = 0; i < iterations; i++) {
		/* Random length: 0-511 bytes, biased toward frame-sized inputs */
		size_t len = (size_t)(xorshift64() % 300);
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

	fprintf(stderr, "fuzz_frame: %llu iterations completed, no crashes\n",
		(unsigned long long)iterations);
	return 0;
}
#endif /* FUZZ_STANDALONE */
