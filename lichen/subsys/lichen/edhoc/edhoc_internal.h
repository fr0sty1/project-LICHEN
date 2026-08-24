/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file edhoc_internal.h
 * @brief Internal declarations for EDHOC implementation
 */

#ifndef LICHEN_EDHOC_INTERNAL_H_
#define LICHEN_EDHOC_INTERNAL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lichen/edhoc.h>

/* CBOR encoding buffer size */
#define CBOR_BUF_SIZE 128

/* Maximum EDHOC message sizes for stack buffers.
 * PLAINTEXT_3 contains ID_CRED_I (33B CBOR) + Signature_3 (65B CBOR) = ~100B.
 * CIPHERTEXT_3 = PLAINTEXT_3 + 8-byte CCM tag. 128+8=136 is safe upper bound.
 */
#define EDHOC_MAX_PLAINTEXT_LEN 128
#define EDHOC_MAX_MSG3_LEN (EDHOC_MAX_PLAINTEXT_LEN + 8)

/*
 * Crypto primitives (edhoc_crypto.c)
 */

/**
 * @brief SHA-256 hash
 * @return 0 on success, -EIO on crypto failure
 */
int sha256_hash(const uint8_t *data, size_t len, uint8_t out[32]);

/**
 * @brief HMAC-SHA256
 * @return 0 on success, -EIO on crypto failure
 */
int hmac_sha256(const uint8_t *key, size_t key_len,
		const uint8_t *data, size_t data_len,
		uint8_t out[32]);

/**
 * @brief HKDF-Extract (RFC 5869)
 * @return 0 on success, negative on error
 */
int hkdf_extract(const uint8_t *salt, size_t salt_len,
		 const uint8_t *ikm, size_t ikm_len,
		 uint8_t prk[32]);

/**
 * @brief HKDF-Expand (RFC 5869)
 * @return 0 on success, negative on error
 */
int hkdf_expand(const uint8_t prk[32],
		const uint8_t *info, size_t info_len,
		uint8_t *okm, size_t okm_len);

/**
 * @brief AES-CCM-16-64-128 encryption
 * @return 0 on success, negative on error
 */
int aead_encrypt(const uint8_t key[16],
		 const uint8_t nonce[13],
		 const uint8_t *aad, size_t aad_len,
		 const uint8_t *plaintext, size_t pt_len,
		 uint8_t *ciphertext);

/**
 * @brief AES-CCM-16-64-128 decryption
 * @return 0 on success, negative on error
 */
int aead_decrypt(const uint8_t key[16],
		 const uint8_t nonce[13],
		 const uint8_t *aad, size_t aad_len,
		 const uint8_t *ciphertext, size_t ct_len,
		 uint8_t *plaintext);

/**
 * @brief Generate X25519 keypair
 * @return 0 on success, -ENODEV if CSPRNG unavailable
 */
int x25519_keypair(uint8_t sk[32], uint8_t pk[32]);

/**
 * @brief Derive X25519 keypair from Ed25519 seed (for static DH)
 *
 * x25519_private = clamp(SHA-512(seed)[0:32]) per RFC 7748 section 5.
 * x25519_public  = X25519(x25519_private, basepoint)
 *
 * This allows deriving both Ed25519 signing keys and X25519 DH keys
 * from the same seed, enabling static authentication in EDHOC.
 *
 * @param[in]  seed  32-byte Ed25519 seed
 * @param[out] sk    32-byte X25519 private key (clamped)
 * @param[out] pk    32-byte X25519 public key
 */
void x25519_keypair_from_seed(const uint8_t seed[32],
			      uint8_t sk[32],
			      uint8_t pk[32]);

/**
 * @brief X25519 shared secret computation
 */
void x25519_shared_secret(uint8_t shared[32],
			  const uint8_t sk[32],
			  const uint8_t pk[32]);

/**
 * @brief Constant-time check for all-zeros buffer (RFC 7748 Section 6.1)
 * @return true if all bytes are zero
 */
bool is_all_zeros(const uint8_t *buf, size_t len);

/*
 * KDF functions (edhoc_kdf.c)
 */

/**
 * @brief Compute transcript hash per RFC 9528 Section 4.1.2
 * TH = H(CBOR(bstr1) || CBOR(bstr2) || CBOR(bstr3))
 * @return 0 on success, negative on error
 */
int compute_th(uint8_t out[32],
	       const uint8_t *b1, size_t b1_len,
	       const uint8_t *b2, size_t b2_len,
	       const uint8_t *b3, size_t b3_len);

/**
 * @brief EDHOC-KDF (RFC 9528 Section 4.1.2) with string label
 * info = CBOR(length) || CBOR(th) || CBOR(label) || CBOR(context)
 * @return 0 on success, negative on error
 */
int edhoc_kdf(const uint8_t prk[32],
	      const uint8_t th[32],
	      const char *label,
	      const uint8_t *context, size_t context_len,
	      uint8_t *out, size_t out_len);

/**
 * @brief EDHOC-KDF with integer label for OSCORE export
 * @return 0 on success, negative on error
 */
int edhoc_kdf_int(const uint8_t prk[32],
		  const uint8_t th[32],
		  int32_t label,
		  const uint8_t *context, size_t context_len,
		  uint8_t *out, size_t out_len);

/**
 * @brief Build COSE Sig_structure per RFC 9052 Section 4.4
 * @return 0 on success, negative on error
 */
int build_sig_structure(const uint8_t *id_cred, size_t id_cred_len,
			const uint8_t *th,
			const uint8_t *cred, size_t cred_len,
			const uint8_t *mac, size_t mac_len,
			uint8_t *out, size_t out_size, size_t *out_len);

/**
 * @brief Build COSE Enc_structure for AEAD operations
 * @return 0 on success, negative on error
 */
int build_enc_structure(uint8_t *out, size_t out_size, size_t *out_len,
			const uint8_t *th, const uint8_t *cred);

/*
 * Signing functions (edhoc_sign.c)
 */

/**
 * @brief Sign message with EDHOC credentials
 * @return 0 on success, negative on error
 */
int edhoc_sign(uint8_t sig[EDHOC_SIG_LEN],
	       const uint8_t *seed,
	       const uint8_t *pubkey,
	       const uint8_t *msg, size_t msg_len);

/**
 * @brief Verify signature with EDHOC credentials
 * @return 0 on success, -1 on verification failure
 */
int edhoc_verify(const uint8_t *pubkey,
		 const uint8_t *sig,
		 const uint8_t *msg, size_t msg_len);

#endif /* LICHEN_EDHOC_INTERNAL_H_ */
