/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_util.c
 * @brief LICHEN shared utility function implementations
 */

#include "lichen_util.h"

int lichen_sha256(const uint8_t *input, size_t inlen,
                  uint8_t output[TC_SHA256_DIGEST_SIZE])
{
    struct tc_sha256_state_struct state;
    int ret = 0;

    if ((input == NULL && inlen > 0) || output == NULL) {
        return -EINVAL;
    }

    if (tc_sha256_init(&state) != TC_CRYPTO_SUCCESS ||
        tc_sha256_update(&state, input, inlen) != TC_CRYPTO_SUCCESS ||
        tc_sha256_final(output, &state) != TC_CRYPTO_SUCCESS) {
        ret = -EIO;
    }
    secure_zero(&state, sizeof(state));
    return ret;
}
