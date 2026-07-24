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
 *     -I../../subsys/lichen/link/include \
 *     -I../../subsys/lichen/crypto \
 *     fuzz_schnorr48.c \
 *     ../../subsys/lichen/link/schnorr48.c \
 *     ../../subsys/lichen/crypto/monocypher.c \
 *     ../../subsys/lichen/crypto/monocypher-ed25519.c \
 *     -o fuzz_schnorr48
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
