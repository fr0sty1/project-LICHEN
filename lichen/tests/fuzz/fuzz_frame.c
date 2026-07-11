/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file fuzz_frame.c
 * @brief libFuzzer harness for LICHEN frame parser
 *
 * Exercises lichen_frame_parse() with arbitrary byte sequences to find
 * crashes, buffer overflows, and undefined behavior.
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
