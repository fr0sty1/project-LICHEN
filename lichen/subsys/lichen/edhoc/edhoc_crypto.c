/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file edhoc_crypto.c
 * @brief EDHOC cryptographic primitives
 *
 * SHA-256, HMAC-SHA256, HKDF, AES-CCM, X25519 operations.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/logging/log.h>

#include <monocypher.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/aes.h>
#include <tinycrypt/ccm_mode.h>
#include <tinycrypt/constants.h>

#include "edhoc_internal.h"

LOG_MODULE_DECLARE(edhoc, CONFIG_LICHEN_EDHOC_LOG_LEVEL);

/*
 * SHA-256 hash
 * SECURITY: All crypto return values must be checked - silent failures would
 * produce uninitialized output, potentially usable as predictable keys.
 * Returns 0 on success, -EIO on crypto failure.
 */
int sha256_hash(const uint8_t *data, size_t len, uint8_t out[32])
{
	struct tc_sha256_state_struct state;

	if (tc_sha256_init(&state) != TC_CRYPTO_SUCCESS) {
		LOG_ERR("tc_sha256_init failed");
		return -EIO;
	}

	if (tc_sha256_update(&state, data, len) != TC_CRYPTO_SUCCESS) {
		LOG_ERR("tc_sha256_update failed");
		crypto_wipe(&state, sizeof(state));
		return -EIO;
	}

	if (tc_sha256_final(out, &state) != TC_CRYPTO_SUCCESS) {
		LOG_ERR("tc_sha256_final failed");
		crypto_wipe(&state, sizeof(state));
		return -EIO;
	}

	crypto_wipe(&state, sizeof(state));
	return 0;
}

/*
 * HMAC-SHA256
 * SECURITY: All crypto return values must be checked - silent failures would
 * produce uninitialized output, potentially usable as predictable keys.
 * Returns 0 on success, -EIO on crypto failure.
 */
int hmac_sha256(const uint8_t *key, size_t key_len,
		const uint8_t *data, size_t data_len,
		uint8_t out[32])
{
	struct tc_hmac_state_struct state;

	if (tc_hmac_set_key(&state, key, key_len) != TC_CRYPTO_SUCCESS) {
		LOG_ERR("tc_hmac_set_key failed");
		return -EIO;
	}

	if (tc_hmac_init(&state) != TC_CRYPTO_SUCCESS) {
		LOG_ERR("tc_hmac_init failed");
		crypto_wipe(&state, sizeof(state));
		return -EIO;
	}

	if (tc_hmac_update(&state, data, data_len) != TC_CRYPTO_SUCCESS) {
		LOG_ERR("tc_hmac_update failed");
		crypto_wipe(&state, sizeof(state));
		return -EIO;
	}

	if (tc_hmac_final(out, TC_SHA256_DIGEST_SIZE, &state) != TC_CRYPTO_SUCCESS) {
		LOG_ERR("tc_hmac_final failed");
		crypto_wipe(&state, sizeof(state));
		return -EIO;
	}

	crypto_wipe(&state, sizeof(state));
	return 0;
}

/*
 * HKDF-Extract (RFC 5869)
 * Returns 0 on success, negative on error.
 */
int hkdf_extract(const uint8_t *salt, size_t salt_len,
		 const uint8_t *ikm, size_t ikm_len,
		 uint8_t prk[32])
{
	uint8_t default_salt[32] = {0};
	int ret;

	if (salt == NULL || salt_len == 0) {
		salt = default_salt;
		salt_len = 32;
	}
	ret = hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
	crypto_wipe(default_salt, sizeof(default_salt));
	return ret;
}

/*
 * HKDF-Expand (RFC 5869)
 * SECURITY: All crypto return values must be checked - silent failures would
 * produce uninitialized output, potentially usable as predictable keys.
 * Returns 0 on success, negative on error.
 */
int hkdf_expand(const uint8_t prk[32],
		const uint8_t *info, size_t info_len,
		uint8_t *okm, size_t okm_len)
{
	/* RFC 5869: L <= 255*HashLen (HashLen=32 for SHA-256) */
	if (okm_len > 255 * 32) {
		return -EINVAL;
	}

	uint8_t t[32] = {0};
	uint8_t t_len = 0;
	uint16_t counter = 1;
	size_t offset = 0;

	while (offset < okm_len) {
		struct tc_hmac_state_struct state;

		if (tc_hmac_set_key(&state, prk, 32) != TC_CRYPTO_SUCCESS) {
			LOG_ERR("tc_hmac_set_key failed in HKDF-Expand");
			crypto_wipe(t, sizeof(t));
			return -EIO;
		}

		if (tc_hmac_init(&state) != TC_CRYPTO_SUCCESS) {
			LOG_ERR("tc_hmac_init failed in HKDF-Expand");
			crypto_wipe(&state, sizeof(state));
			crypto_wipe(t, sizeof(t));
			return -EIO;
		}

		if (t_len > 0) {
			if (tc_hmac_update(&state, t, t_len) != TC_CRYPTO_SUCCESS) {
				LOG_ERR("tc_hmac_update (T) failed in HKDF-Expand");
				crypto_wipe(&state, sizeof(state));
				crypto_wipe(t, sizeof(t));
				return -EIO;
			}
		}
		if (tc_hmac_update(&state, info, info_len) != TC_CRYPTO_SUCCESS) {
			LOG_ERR("tc_hmac_update (info) failed in HKDF-Expand");
			crypto_wipe(&state, sizeof(state));
			crypto_wipe(t, sizeof(t));
			return -EIO;
		}

		if (tc_hmac_update(&state, &counter, 1) != TC_CRYPTO_SUCCESS) {
			LOG_ERR("tc_hmac_update (counter) failed in HKDF-Expand");
			crypto_wipe(&state, sizeof(state));
			crypto_wipe(t, sizeof(t));
			return -EIO;
		}

		if (tc_hmac_final(t, TC_SHA256_DIGEST_SIZE, &state) != TC_CRYPTO_SUCCESS) {
			LOG_ERR("tc_hmac_final failed in HKDF-Expand");
			crypto_wipe(&state, sizeof(state));
			crypto_wipe(t, sizeof(t));
			return -EIO;
		}

		crypto_wipe(&state, sizeof(state));
		t_len = 32;

		size_t copy_len = MIN(32, okm_len - offset);
		memcpy(okm + offset, t, copy_len);
		offset += copy_len;
		counter++;
	}
	crypto_wipe(t, sizeof(t));
	return 0;
}

/*
 * AES-CCM-16-64-128 encryption
 */
int aead_encrypt(const uint8_t key[16],
		 const uint8_t nonce[13],
		 const uint8_t *aad, size_t aad_len,
		 const uint8_t *plaintext, size_t pt_len,
		 uint8_t *ciphertext)
{
	struct tc_aes_key_sched_struct sched;
	struct tc_ccm_mode_struct ccm;
	uint8_t nonce_buf[13];
	memcpy(nonce_buf, nonce, 13);

	if (tc_aes128_set_encrypt_key(&sched, key) != TC_CRYPTO_SUCCESS) {
		return -EINVAL;
	}
	if (tc_ccm_config(&ccm, &sched, nonce_buf, 13, 8) != TC_CRYPTO_SUCCESS) {
		return -EINVAL;
	}
	if (tc_ccm_generation_encryption(ciphertext, pt_len + 8,
					 aad, aad_len,
					 plaintext, pt_len,
					 &ccm) != TC_CRYPTO_SUCCESS) {
		return -EINVAL;
	}

	crypto_wipe(&sched, sizeof(sched));
	crypto_wipe(&ccm, sizeof(ccm));
	return 0;
}

/*
 * AES-CCM-16-64-128 decryption
 */
int aead_decrypt(const uint8_t key[16],
		 const uint8_t nonce[13],
		 const uint8_t *aad, size_t aad_len,
		 const uint8_t *ciphertext, size_t ct_len,
		 uint8_t *plaintext)
{
	struct tc_aes_key_sched_struct sched;
	struct tc_ccm_mode_struct ccm;
	uint8_t nonce_buf[13];
	memcpy(nonce_buf, nonce, 13);

	if (ct_len < 8) {
		return -EINVAL;
	}

	if (tc_aes128_set_encrypt_key(&sched, key) != TC_CRYPTO_SUCCESS) {
		return -EINVAL;
	}
	if (tc_ccm_config(&ccm, &sched, nonce_buf, 13, 8) != TC_CRYPTO_SUCCESS) {
		return -EINVAL;
	}
	if (tc_ccm_decryption_verification(plaintext, ct_len - 8,
					   aad, aad_len,
					   ciphertext, ct_len,
					   &ccm) != TC_CRYPTO_SUCCESS) {
		return -EINVAL;
	}

	crypto_wipe(&sched, sizeof(sched));
	crypto_wipe(&ccm, sizeof(ccm));
	return 0;
}

/*
 * Generate X25519 keypair
 * Returns 0 on success, -ENODEV if CSPRNG unavailable
 */
int x25519_keypair(uint8_t sk[32], uint8_t pk[32])
{
	/* SECURITY: Generic error avoids exposing crypto implementation details */
	if (sys_csrand_get(sk, 32) != 0) {
		LOG_WRN("Key generation failed");
		return -ENODEV;
	}
	crypto_x25519_public_key(pk, sk);
	return 0;
}

/*
 * X25519 shared secret
 */
void x25519_shared_secret(uint8_t shared[32],
			  const uint8_t sk[32],
			  const uint8_t pk[32])
{
	crypto_x25519(shared, sk, pk);
}

/*
 * Constant-time check for all-zeros buffer (RFC 7748 Section 6.1)
 * X25519 with a small-order public key produces an all-zeros shared secret,
 * which must be rejected to prevent contributory behavior attacks.
 * Returns true if all bytes are zero.
 */
bool is_all_zeros(const uint8_t *buf, size_t len)
{
	uint8_t acc = 0;
	for (size_t i = 0; i < len; i++) {
		acc |= buf[i];
	}
	return acc == 0;
}
