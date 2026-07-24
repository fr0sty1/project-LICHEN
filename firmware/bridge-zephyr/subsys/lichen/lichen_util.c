/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_util.c
 * @brief LICHEN shared utility function implementations
 */

#include "lichen_util.h"

/* Compile-time sanity check: SHA-256 always produces 32 bytes */
BUILD_ASSERT(TC_SHA256_DIGEST_SIZE == 32,
             "SHA-256 digest size must be 32 bytes");

int lichen_sha256(const uint8_t *input, size_t inlen,
                  uint8_t *output, size_t outlen)
{
    struct tc_sha256_state_struct state;
    int ret = 0;

    if (input == NULL || output == NULL) {
        return -EINVAL;
    }
    if (outlen < TC_SHA256_DIGEST_SIZE) {
        return -ENOMEM;
    }

    if (inlen == 0) {
        input = (const uint8_t *)"";
    }

    if (tc_sha256_init(&state) != TC_CRYPTO_SUCCESS ||
        tc_sha256_update(&state, input, inlen) != TC_CRYPTO_SUCCESS ||
        tc_sha256_final(output, &state) != TC_CRYPTO_SUCCESS) {
        ret = -EIO;
    }
    secure_zero(&state, sizeof(state));
    return ret;
}
