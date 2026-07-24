/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_util.c
 * @brief LICHEN shared utility function implementations
 */

#include "lichen_util.h"
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(lichen_util, CONFIG_LICHEN_UTIL_LOG_LEVEL);

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

    if (tc_sha256_init(&state) != TC_CRYPTO_SUCCESS) {
        LOG_ERR("SHA-256 init failed");
        ret = -EIO;
        goto out;
    }
    if (inlen > 0 &&
        tc_sha256_update(&state, input, inlen) != TC_CRYPTO_SUCCESS) {
        LOG_ERR("SHA-256 update failed");
        ret = -EIO;
        goto out;
    }
    if (tc_sha256_final(output, &state) != TC_CRYPTO_SUCCESS) {
        LOG_ERR("SHA-256 final failed");
        ret = -EIO;
        goto out;
    }

out:
    secure_zero(&state, sizeof(state));
    return ret;
}
