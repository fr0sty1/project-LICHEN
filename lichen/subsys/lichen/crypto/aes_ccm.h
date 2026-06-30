/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file aes_ccm.h
 * @brief Shared AES-CCM-16-64-128 helper
 *
 * COSE Algorithm ID 10: AES-CCM with 128-bit key, 64-bit tag, 13-byte nonce.
 */

#ifndef LICHEN_CRYPTO_AES_CCM_H_
#define LICHEN_CRYPTO_AES_CCM_H_

#include <stdint.h>
#include <stddef.h>

/** AES-128 key length */
#define AES_CCM_KEY_LEN 16

/** CCM nonce length (13 bytes for L=2) */
#define AES_CCM_NONCE_LEN 13

/** CCM authentication tag length */
#define AES_CCM_TAG_LEN 8

/** Error codes for AES-CCM functions */
#define AES_CCM_OK             0   /**< Success */
#define AES_CCM_ERR_GENERIC   -1   /**< Generic/crypto failure */
#define AES_CCM_ERR_INVALID_PARAM -2  /**< Invalid parameter (e.g., NULL aad with nonzero len) */

/**
 * @brief AES-CCM-16-64-128 encryption
 *
 * @param[in]  key       16-byte encryption key
 * @param[in]  nonce     13-byte nonce
 * @param[in]  aad       Additional authenticated data (may be NULL)
 * @param[in]  aad_len   AAD length
 * @param[in]  plaintext Plaintext to encrypt
 * @param[in]  pt_len    Plaintext length
 * @param[out] ciphertext Output buffer (must hold pt_len + TAG_LEN bytes)
 * @return 0 on success, -1 on failure
 */
int lichen_aes_ccm_encrypt(const uint8_t key[AES_CCM_KEY_LEN],
		    const uint8_t nonce[AES_CCM_NONCE_LEN],
		    const uint8_t *aad, size_t aad_len,
		    const uint8_t *plaintext, size_t pt_len,
		    uint8_t *ciphertext);

/**
 * @brief AES-CCM-16-64-128 decryption
 *
 * @param[in]  key        16-byte encryption key
 * @param[in]  nonce      13-byte nonce
 * @param[in]  aad        Additional authenticated data (may be NULL)
 * @param[in]  aad_len    AAD length
 * @param[in]  ciphertext Ciphertext including tag (ct_len >= TAG_LEN)
 * @param[in]  ct_len     Ciphertext length (including tag)
 * @param[out] plaintext  Output buffer (must hold ct_len - TAG_LEN bytes)
 * @return 0 on success, -1 on authentication failure
 */
int lichen_aes_ccm_decrypt(const uint8_t key[AES_CCM_KEY_LEN],
		    const uint8_t nonce[AES_CCM_NONCE_LEN],
		    const uint8_t *aad, size_t aad_len,
		    const uint8_t *ciphertext, size_t ct_len,
		    uint8_t *plaintext);

#endif /* LICHEN_CRYPTO_AES_CCM_H_ */
