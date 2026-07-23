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
                  uint8_t output[TC_SHA256_DIGEST_SIZE])
{
    struct tc_sha256_state_struct state;
    int ret = 0;

    if ((input == NULL && inlen > 0) || output == NULL) {
        return -EINVAL;
    }

    /* Conflated error handling is intentional: callers only need pass/fail,
     * and TinyCrypt's SHA-256 functions only fail on NULL (checked above). */
    if (tc_sha256_init(&state) != TC_CRYPTO_SUCCESS ||
        (inlen > 0 &&
         tc_sha256_update(&state, input, inlen) != TC_CRYPTO_SUCCESS) ||
        tc_sha256_final(output, &state) != TC_CRYPTO_SUCCESS) {
        ret = -EIO;
    }
    secure_zero(&state, sizeof(state));
    return ret;
}

uint32_t lichen_hash_32(const uint8_t *data, size_t len)
{
    uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < len; ++i) {
        h ^= (uint32_t)data[i];
        h = h * 0x01000193u;
    }
    return h;
}
