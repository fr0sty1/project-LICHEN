/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_util.h
 * @brief LICHEN shared utility functions
 */

#ifndef LICHEN_UTIL_H
#define LICHEN_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>

/*
 * SECURITY: Secure memset that won't be optimized away.
 * Standard memset() on dead buffers can be removed by the compiler.
 * The volatile pointer forces each store to actually execute.
 * The memory barrier prevents LTO removal and ensures ordering.
 */
static inline void secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = ptr;
    while (len--) {
        *p++ = 0;
    }
    __asm__ __volatile__("" ::: "memory");
}

/**
 * @brief Compute SHA-256 hash with secure cleanup
 *
 * @param input Input data
 * @param inlen Input length
 * @param output Output buffer (must be TC_SHA256_DIGEST_SIZE = 32 bytes)
 * @return 0 on success, negative errno on failure
 */
static inline int lichen_sha256(const uint8_t *input, size_t inlen,
                                uint8_t output[TC_SHA256_DIGEST_SIZE])
{
    struct tc_sha256_state_struct state;
    int ret = 0;

    if (tc_sha256_init(&state) != TC_CRYPTO_SUCCESS ||
        tc_sha256_update(&state, input, inlen) != TC_CRYPTO_SUCCESS ||
        tc_sha256_final(output, &state) != TC_CRYPTO_SUCCESS) {
        ret = -EIO;
    }
    secure_zero(&state, sizeof(state));
    return ret;
}

#endif /* LICHEN_UTIL_H */
