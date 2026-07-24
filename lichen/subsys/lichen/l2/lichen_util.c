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

    if (input == NULL || output == NULL) {
        return -EINVAL;
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

int lichen_iid_to_human_address(const uint8_t *iid, char *buf, size_t buflen)
{
	if (iid == NULL || buf == NULL) {
		return -EINVAL;
	}
	if (buflen < 16) {
		if (buflen > 0) {
			buf[0] = '\0';
		}
		return -EINVAL;
	}
	uint64_t n = 0;
	for (int i = 0; i < 8; i++) {
		n = (n << 8) | iid[i];
	}
	static const char alphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
	char temp[13];
	for (int i = 12; i >= 0; i--) {
		temp[i] = alphabet[n % 32];
		n /= 32;
	}
	buf[0] = temp[0];
	buf[1] = temp[1];
	buf[2] = temp[2];
	buf[3] = temp[3];
	buf[4] = '-';
	buf[5] = temp[4];
	buf[6] = temp[5];
	buf[7] = temp[6];
	buf[8] = temp[7];
	buf[9] = '-';
	buf[10] = temp[8];
	buf[11] = temp[9];
	buf[12] = temp[10];
	buf[13] = temp[11];
	buf[14] = temp[12];
	buf[15] = '\0';
	return 0;
}
