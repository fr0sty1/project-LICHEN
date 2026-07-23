/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file edhoc.c
 * @brief EDHOC (RFC 9528) Suite 0 implementation
 *
 * Uses Monocypher for X25519/Ed25519, tinycrypt for AES-CCM/SHA-256/HKDF.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/logging/log.h>

#include <lichen/edhoc.h>
#include <monocypher.h>
#include <lichen/schnorr48.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/aes.h>
#include <tinycrypt/ccm_mode.h>
#include <tinycrypt/constants.h>
#include <zcbor_common.h>
#include <zcbor_encode.h>
#include <zcbor_decode.h>

LOG_MODULE_REGISTER(edhoc, CONFIG_LICHEN_EDHOC_LOG_LEVEL);

/*
 * SECURITY: Compile-time checks to ensure struct field sizes match the
 * constants used in memcpy operations. Prevents maintenance hazards if
 * constants are changed without updating struct definitions.
 */
BUILD_ASSERT(sizeof(((struct edhoc_initiator *)0)->g_y) >= EDHOC_X25519_KEY_LEN,
	     "g_y too small for EDHOC_X25519_KEY_LEN");
BUILD_ASSERT(sizeof(((struct edhoc_initiator *)0)->ed_seed) >= EDHOC_ED25519_SK_LEN,
	     "ed_seed too small for EDHOC_ED25519_SK_LEN");
BUILD_ASSERT(sizeof(((struct edhoc_initiator *)0)->ed_pubkey) >= EDHOC_ED25519_PK_LEN,
	     "ed_pubkey too small for EDHOC_ED25519_PK_LEN");
BUILD_ASSERT(sizeof(((struct edhoc_responder *)0)->g_x) >= EDHOC_X25519_KEY_LEN,
	     "g_x too small for EDHOC_X25519_KEY_LEN");
BUILD_ASSERT(sizeof(((struct edhoc_responder *)0)->ed_seed) >= EDHOC_ED25519_SK_LEN,
	     "ed_seed too small for EDHOC_ED25519_SK_LEN");
BUILD_ASSERT(sizeof(((struct edhoc_responder *)0)->ed_pubkey) >= EDHOC_ED25519_PK_LEN,
	     "ed_pubkey too small for EDHOC_ED25519_PK_LEN");
BUILD_ASSERT(EDHOC_SIG_LEN == SCHNORR48_SIG_LEN,
	     "EDHOC_SIG_LEN must match SCHNORR48_SIG_LEN");

/* CBOR encoding buffer size */
#define CBOR_BUF_SIZE 128

/* Maximum EDHOC message sizes for stack buffers.
 * PLAINTEXT_3 contains ID_CRED_I (33B CBOR) + Signature_3 (65B CBOR) = ~100B.
 * CIPHERTEXT_3 = PLAINTEXT_3 + 8-byte CCM tag. 128+8=136 is safe upper bound.
 */
#define EDHOC_MAX_PLAINTEXT_LEN 128
#define EDHOC_MAX_MSG3_LEN (EDHOC_MAX_PLAINTEXT_LEN + 8)

/*
 * SHA-256 hash
 * Returns 0 on success, -EIO on crypto failure
 */
static int sha256_hash(const uint8_t *data, size_t len, uint8_t out[32]);

/*
 * Compute transcript hash per RFC 9528 Section 4.1.2
 * TH = H(CBOR(bstr1) || CBOR(bstr2) || CBOR(bstr3))
 * All inputs are CBOR-encoded as byte strings before hashing.
 * Returns 0 on success, negative on error.
 */
static int compute_th(uint8_t out[32],
		      const uint8_t *b1, size_t b1_len,
		      const uint8_t *b2, size_t b2_len,
		      const uint8_t *b3, size_t b3_len)
{
	uint8_t cbor_buf[256];
	ZCBOR_STATE_E(zse, 0, cbor_buf, sizeof(cbor_buf), 0);

	if (!zcbor_bstr_encode_ptr(zse, b1, b1_len) ||
	    !zcbor_bstr_encode_ptr(zse, b2, b2_len)) {
		return -ENOMEM;
	}
	if (b3 != NULL && b3_len > 0 &&
	    !zcbor_bstr_encode_ptr(zse, b3, b3_len)) {
		return -ENOMEM;
	}

	size_t cbor_len = zse->payload - cbor_buf;
	return sha256_hash(cbor_buf, cbor_len, out);
}

/*
 * SHA-256 hash
 * SECURITY: All crypto return values must be checked - silent failures would
 * produce uninitialized output, potentially usable as predictable keys.
 * Returns 0 on success, -EIO on crypto failure.
 */
static int sha256_hash(const uint8_t *data, size_t len, uint8_t out[32])
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
static int hmac_sha256(const uint8_t *key, size_t key_len,
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
static int hkdf_extract(const uint8_t *salt, size_t salt_len,
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
static int hkdf_expand(const uint8_t prk[32],
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
 * EDHOC-KDF (RFC 9528 Section 4.1.2)
 * info = CBOR(length) || CBOR(th) || CBOR(label) || CBOR(context)
 */
static int edhoc_kdf(const uint8_t prk[32],
		     const uint8_t th[32],
		     const char *label,
		     const uint8_t *context, size_t context_len,
		     uint8_t *out, size_t out_len)
{
	uint8_t info[CBOR_BUF_SIZE];
	size_t info_len = 0;
	int ret;

	/* Encode info as CBOR sequence */
	ZCBOR_STATE_E(zse, 0, info, sizeof(info), 0);

	if (!zcbor_uint32_put(zse, (uint32_t)out_len)) {
		return -EINVAL;
	}
	if (!zcbor_bstr_encode_ptr(zse, th, 32)) {
		return -EINVAL;
	}
	size_t label_len = strlen(label);
	if (!zcbor_tstr_encode_ptr(zse, label, label_len)) {
		return -EINVAL;
	}
	if (!zcbor_bstr_encode_ptr(zse, context, context_len)) {
		return -EINVAL;
	}

	info_len = zse->payload - info;

	ret = hkdf_expand(prk, info, info_len, out, out_len);
	crypto_wipe(info, sizeof(info));
	return ret;
}

/*
 * EDHOC-KDF with integer label for OSCORE export (matches Python edhoc.py
 * PRK_out=7, PRK_exporter=10, master_secret=0, master_salt=1 and RFC 9528 §7.2.1).
 * info = CBOR(length) || CBOR(TH) || CBOR(label) || CBOR(context)
 */
static int edhoc_kdf_int(const uint8_t prk[32],
		     const uint8_t th[32],
		     int32_t label,
		     const uint8_t *context, size_t context_len,
		     uint8_t *out, size_t out_len)
{
	uint8_t info[CBOR_BUF_SIZE];
	size_t info_len = 0;
	int ret;

	ZCBOR_STATE_E(zse, 0, info, sizeof(info), 0);

	if (!zcbor_uint32_put(zse, (uint32_t)out_len)) {
		return -EINVAL;
	}
	if (!zcbor_bstr_encode_ptr(zse, th, 32)) {
		return -EINVAL;
	}
	if (!zcbor_int32_put(zse, label)) {
		return -EINVAL;
	}
	if (!zcbor_bstr_encode_ptr(zse, context, context_len)) {
		return -EINVAL;
	}

	info_len = zse->payload - info;

	ret = hkdf_expand(prk, info, info_len, out, out_len);
	crypto_wipe(info, sizeof(info));
	return ret;
}

/*
 * Build COSE Sig_structure per RFC 9052 Section 4.4.
 * Sig_structure = ["Signature1", body_protected, external_aad, payload]
 *
 * For EDHOC Suite 0:
 * - body_protected = << ID_CRED >> (bstr-wrapped)
 * - external_aad = << TH, CRED >> (CBOR sequence as bstr)
 * - payload = MAC (from EDHOC-KDF)
 *
 * SECURITY: All CBOR encoding return values must be checked. If encoding
 * fails (e.g., buffer overflow), operating on corrupted data could cause
 * signature verification to fail or potentially accept invalid signatures.
 */
static int build_sig_structure(const uint8_t *id_cred, size_t id_cred_len,
			       const uint8_t *th,
			       const uint8_t *cred, size_t cred_len,
			       const uint8_t *mac, size_t mac_len,
			       uint8_t *out, size_t out_size, size_t *out_len)
{
	/* external_aad = << TH, CRED >> */
	uint8_t ext_aad[96];
	ZCBOR_STATE_E(zse_ext, 0, ext_aad, sizeof(ext_aad), 0);
	if (!zcbor_bstr_encode_ptr(zse_ext, th, 32)) {
		return -EINVAL;
	}
	if (!zcbor_bstr_encode_ptr(zse_ext, cred, cred_len)) {
		return -EINVAL;
	}
	size_t ext_aad_len = zse_ext->payload - ext_aad;

	/* body_protected = << ID_CRED >> */
	uint8_t body_prot[48];
	ZCBOR_STATE_E(zse_bp, 0, body_prot, sizeof(body_prot), 0);
	if (!zcbor_bstr_encode_ptr(zse_bp, id_cred, id_cred_len)) {
		return -EINVAL;
	}
	size_t body_prot_len = zse_bp->payload - body_prot;

	/* Sig_structure = ["Signature1", body_protected, external_aad, MAC] */
	ZCBOR_STATE_E(zse, 0, out, out_size, 0);
	if (!zcbor_list_start_encode(zse, 4) ||
	    !zcbor_tstr_put_lit(zse, "Signature1") ||
	    !zcbor_bstr_encode_ptr(zse, body_prot, body_prot_len) ||
	    !zcbor_bstr_encode_ptr(zse, ext_aad, ext_aad_len) ||
	    !zcbor_bstr_encode_ptr(zse, mac, mac_len) ||
	    !zcbor_list_end_encode(zse, 4)) {
		return -EINVAL;
	}

	*out_len = zse->payload - out;
	return 0;
}

static int build_enc_structure(uint8_t *out, size_t out_size, size_t *out_len,
			       const uint8_t *th, const uint8_t *cred)
{
	uint8_t ext_aad[64];
	memcpy(ext_aad, th, 32);
	memcpy(ext_aad + 32, cred, 32);
	ZCBOR_STATE_E(zse, 0, out, out_size, 0);
	if (!zcbor_list_start_encode(zse, 3) ||
	    !zcbor_tstr_put_lit(zse, "Encrypt0") ||
	    !zcbor_bstr_encode_ptr(zse, NULL, 0) ||
	    !zcbor_bstr_encode_ptr(zse, ext_aad, 64) ||
	    !zcbor_list_end_encode(zse, 3)) {
		return -ENOMEM;
	}

	*out_len = zse->payload - out;
	return 0;
}

/*
 * AES-CCM-16-64-128 encryption
 */
static int aead_encrypt(const uint8_t key[16],
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
static int aead_decrypt(const uint8_t key[16],
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
static int x25519_keypair(uint8_t sk[32], uint8_t pk[32])
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
static void x25519_shared_secret(uint8_t shared[32],
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
static bool is_all_zeros(const uint8_t *buf, size_t len)
{
	uint8_t acc = 0;
	for (size_t i = 0; i < len; i++) {
		acc |= buf[i];
	}
	return acc == 0;
}

static int edhoc_sign(uint8_t sig[EDHOC_SIG_LEN],
		      const uint8_t *seed,
		      const uint8_t *pubkey,
		      const uint8_t *msg, size_t msg_len)
{
	uint8_t privkey[SCHNORR48_PRIVKEY_LEN];
	uint8_t computed_pub[SCHNORR48_PUBKEY_LEN];
	schnorr48_derive_keypair(seed, privkey, computed_pub);
	if (crypto_verify32(pubkey, computed_pub) != 0) {
		crypto_wipe(privkey, sizeof(privkey));
		crypto_wipe(computed_pub, sizeof(computed_pub));
		return -EINVAL;
	}
	int ret = schnorr48_sign(privkey, pubkey, msg, msg_len, sig);
	crypto_wipe(privkey, sizeof(privkey));
	crypto_wipe(computed_pub, sizeof(computed_pub));
	return ret;
}

static int edhoc_verify(const uint8_t *pubkey,
			const uint8_t *sig,
			const uint8_t *msg, size_t msg_len)
{
	return schnorr48_verify(pubkey, msg, msg_len, sig) ? 0 : -1;
}

int edhoc_initiator_init(struct edhoc_initiator *ctx,
			 const uint8_t *ed_seed,
			 const uint8_t *ed_pubkey,
			 const uint8_t *c_i, size_t c_i_len,
			 uint8_t corr)
{
	if (ctx == NULL || ed_seed == NULL || ed_pubkey == NULL) {
		return -EINVAL;
	}
	if (c_i_len > EDHOC_CID_MAX_LEN || corr > 3) {
		return -EINVAL;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->state = EDHOC_STATE_IDLE;
	ctx->method = EDHOC_METHOD_SIGN_SIGN;
	ctx->corr = corr;
	memcpy(ctx->ed_seed, ed_seed, EDHOC_ED25519_SK_LEN);
	memcpy(ctx->ed_pubkey, ed_pubkey, EDHOC_ED25519_PK_LEN);

	if (c_i != NULL && c_i_len > 0) {
		memcpy(ctx->c_i, c_i, c_i_len);
		ctx->c_i_len = c_i_len;
	} else {
		if (sys_csrand_get(ctx->c_i, 1) != 0) {
			return -ENODEV;
		}
		ctx->c_i_len = 1;
	}

	int ret = x25519_keypair(ctx->eph_sk, ctx->eph_pk);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

int edhoc_initiator_create_msg1(struct edhoc_initiator *ctx,
				uint8_t *msg1, size_t msg1_size,
				size_t *msg1_len)
{
	if (ctx == NULL || msg1 == NULL || msg1_len == NULL) {
		return -EINVAL;
	}
	if (ctx->state != EDHOC_STATE_IDLE) {
		return -EBUSY;
	}

	uint8_t method_corr = ctx->method * 4 + ctx->corr;

	ZCBOR_STATE_E(zse, 0, msg1, msg1_size, 0);

	if (!zcbor_int32_put(zse, method_corr)) {
		return -ENOMEM;
	}
	if (!zcbor_int32_put(zse, EDHOC_SUITE_0)) {
		return -ENOMEM;
	}
	if (!zcbor_bstr_encode_ptr(zse, ctx->eph_pk, EDHOC_X25519_KEY_LEN)) {
		return -ENOMEM;
	}

	/* C_I encoding per RFC 9528 Section 3.3.2 (bstr_identifier):
	 * - Values 0-23: encode as CBOR positive integer
	 * - Values -24 to -1 (stored as 232-255): encode as CBOR negative integer
	 * - Other values: encode as CBOR byte string
	 */
	if (ctx->c_i_len == 1 && ctx->c_i[0] <= 23) {
		if (!zcbor_int32_put(zse, ctx->c_i[0])) {
			return -ENOMEM;
		}
	} else if (ctx->c_i_len == 1 && ctx->c_i[0] >= 232) {
		/* Negative integer: stored as (original + 256), reverse it */
		if (!zcbor_int32_put(zse, (int32_t)ctx->c_i[0] - 256)) {
			return -ENOMEM;
		}
	} else {
		if (!zcbor_bstr_encode_ptr(zse, ctx->c_i, ctx->c_i_len)) {
			return -ENOMEM;
		}
	}

	*msg1_len = zse->payload - msg1;

	/* Save msg1 for TH computation */
	/* SECURITY: Generic error hides internal buffer sizes */
	if (*msg1_len > sizeof(ctx->msg1)) {
		LOG_WRN("Message too large");
		return -ENOMEM;
	}
	memcpy(ctx->msg1, msg1, *msg1_len);
	ctx->msg1_len = *msg1_len;

	ctx->state = EDHOC_STATE_MSG1_SENT;
	return 0;
}

int edhoc_initiator_process_msg2(struct edhoc_initiator *ctx,
				 const uint8_t *msg2, size_t msg2_len,
				 const uint8_t *peer_pubkey,
				 uint8_t *msg3, size_t msg3_size,
				 size_t *msg3_len)
{
	int ret = 0;
	uint8_t g_xy[32] = {0};
	uint8_t k_3[16] = {0};
	uint8_t iv_3[13] = {0};
	uint8_t signature_3[EDHOC_SIG_LEN] = {0};
	uint8_t keystream_2[128] = {0};
	uint8_t plaintext_2[128] = {0};
	uint8_t mac_2[32] = {0};
	uint8_t sig_struct_2[256] = {0};
	uint8_t mac_3[32] = {0};
	uint8_t sig_struct_3[256] = {0};
	uint8_t plaintext_3[EDHOC_MAX_MSG3_LEN - EDHOC_TAG_LEN] = {0};

	if (ctx == NULL || msg2 == NULL || peer_pubkey == NULL ||
	    msg3 == NULL || msg3_len == NULL) {
		return -EINVAL;
	}
	if (ctx->state != EDHOC_STATE_MSG1_SENT) {
		return -EBUSY;
	}

	/* Decode message_2 = (G_Y || CIPHERTEXT_2, C_R) */
	ZCBOR_STATE_D(zsd, 0, msg2, msg2_len, 2, 0);

	struct zcbor_string g_y_ct2;
	if (!zcbor_bstr_decode(zsd, &g_y_ct2)) {
		return -EINVAL;
	}
	if (g_y_ct2.len < EDHOC_X25519_KEY_LEN) {
		return -EINVAL;
	}

	memcpy(ctx->g_y, g_y_ct2.value, EDHOC_X25519_KEY_LEN);
	const uint8_t *ciphertext_2 = g_y_ct2.value + EDHOC_X25519_KEY_LEN;
	size_t ct2_len = g_y_ct2.len - EDHOC_X25519_KEY_LEN;

	/* Decode C_R */
	int32_t c_r_int;
	struct zcbor_string c_r_bstr;
	if (zcbor_int32_decode(zsd, &c_r_int)) {
		if (c_r_int >= 0 && c_r_int <= 255) {
			ctx->c_r[0] = (uint8_t)c_r_int;
			ctx->c_r_len = 1;
		} else if (c_r_int >= -24 && c_r_int < 0) {
			ctx->c_r[0] = (uint8_t)(c_r_int + 256);
			ctx->c_r_len = 1;
		} else {
			return -EINVAL;
		}
	} else if (zcbor_bstr_decode(zsd, &c_r_bstr)) {
		if (c_r_bstr.len > EDHOC_CID_MAX_LEN) {
			return -EINVAL;
		}
		memcpy(ctx->c_r, c_r_bstr.value, c_r_bstr.len);
		ctx->c_r_len = c_r_bstr.len;
	} else {
		return -EINVAL;
	}

	/* Compute shared secret G_XY */
	x25519_shared_secret(g_xy, ctx->eph_sk, ctx->g_y);
	/* SECURITY: Generic error hides small-order point attack detection */
	if (is_all_zeros(g_xy, sizeof(g_xy))) {
		LOG_WRN("Key exchange failed");
		ret = -EACCES;
		goto err_wipe;
	}

	/* TH_2 = H(H(message_1) || G_Y || C_R) per RFC 9528 Section 4.1.2 */
	uint8_t h_msg1[32];
	ret = sha256_hash(ctx->msg1, ctx->msg1_len, h_msg1);
	if (ret != 0) {
		goto err_wipe;
	}

	uint8_t th2_input[72];  /* 32 + 32 + up to 8 for C_R */
	size_t th2_input_len = 0;
	memcpy(th2_input + th2_input_len, h_msg1, 32);
	th2_input_len += 32;
	memcpy(th2_input + th2_input_len, ctx->g_y, 32);
	th2_input_len += 32;
	memcpy(th2_input + th2_input_len, ctx->c_r, ctx->c_r_len);
	th2_input_len += ctx->c_r_len;
	ret = sha256_hash(th2_input, th2_input_len, ctx->th_2);
	if (ret != 0) {
		goto err_wipe;
	}

	/* PRK_2e = HKDF-Extract(TH_2, G_XY) */
	ret = hkdf_extract(ctx->th_2, 32, g_xy, 32, ctx->prk_2e);
	if (ret != 0) {
		goto err_wipe;
	}
	crypto_wipe(g_xy, sizeof(g_xy));

	/*
	 * Decrypt CIPHERTEXT_2 with KEYSTREAM_2 (XOR).
	 * RFC 9528 Section 4.3: message_2 uses XOR-only encryption without MAC.
	 * Authenticity comes from Signature_2 which covers MAC_2 over TH_2.
	 */
	if (ct2_len > sizeof(keystream_2)) {
		ret = -ENOMEM;
		goto err_wipe;
	}
	ret = edhoc_kdf(ctx->prk_2e, ctx->th_2, "KEYSTREAM_2", NULL, 0,
			keystream_2, ct2_len);
	if (ret != 0) {
		goto err_wipe;
	}

	for (size_t i = 0; i < ct2_len; i++) {
		plaintext_2[i] = ciphertext_2[i] ^ keystream_2[i];
	}

	/* Parse PLAINTEXT_2 = (ID_CRED_R, Signature_2) */
	/* ponytail: simplified - just grab ID_CRED_R and signature */
	ZCBOR_STATE_D(zsd_pt2, 0, plaintext_2, ct2_len, 2, 0);

	struct zcbor_string id_cred_r;
	if (!zcbor_bstr_decode(zsd_pt2, &id_cred_r)) {
		ret = -EINVAL;
		goto err_wipe;
	}

	/*
	 * SECURITY: Validate ID_CRED_R against expected peer identity.
	 * RFC 9528 requires that ID_CRED corresponds to the credential used
	 * for verification. Without this check, a malicious party could include
	 * arbitrary ID_CRED data while we verify against a different key.
	 */
	if (id_cred_r.len != EDHOC_ED25519_PK_LEN) {
		LOG_WRN("Peer identity mismatch");
		ret = -EACCES;
		goto err_wipe;
	}
	if (crypto_verify32(id_cred_r.value, peer_pubkey) != 0) {
		LOG_WRN("Peer identity mismatch");
		ret = -EACCES;
		goto err_wipe;
	}

	struct zcbor_string signature_2;
	if (!zcbor_bstr_decode(zsd_pt2, &signature_2)) {
		ret = -EINVAL;
		goto err_wipe;
	}
	if (signature_2.len != EDHOC_SIG_LEN) {
		ret = -EINVAL;
		goto err_wipe;
	}

	/* PRK_3e2m = PRK_2e for SIGN_SIGN Suite 0 */
	memcpy(ctx->prk_3e2m, ctx->prk_2e, 32);

	/* Verify Signature_2 per RFC 9528 */
	/* MAC_2 = EDHOC-KDF(PRK_3e2m, TH_2, "MAC_2", context_2, 32) */
	uint8_t context_2[128];
	ZCBOR_STATE_E(zse_ctx2, 0, context_2, sizeof(context_2), 0);
	if (!zcbor_bstr_encode_ptr(zse_ctx2, ctx->c_r, ctx->c_r_len) ||
	    !zcbor_bstr_encode_ptr(zse_ctx2, peer_pubkey, 32) ||
	    !zcbor_bstr_encode_ptr(zse_ctx2, ctx->th_2, 32) ||
	    !zcbor_bstr_encode_ptr(zse_ctx2, peer_pubkey, 32)) {
		ret = -ENOMEM;
		goto err_wipe;
	}
	size_t context_2_len = zse_ctx2->payload - context_2;

	ret = edhoc_kdf(ctx->prk_3e2m, ctx->th_2, "MAC_2", context_2, context_2_len, mac_2, 32);
	if (ret != 0) {
		goto err_wipe;
	}

	size_t sig_struct_2_len;
	ret = build_sig_structure(peer_pubkey, 32, ctx->th_2, peer_pubkey, 32,
				  mac_2, 32, sig_struct_2, sizeof(sig_struct_2), &sig_struct_2_len);
	if (ret != 0) {
		goto err_wipe;
	}

	/*
	 * SECURITY: Constant-time signature verification.
	 * - schnorr48_verify uses crypto_verify16 + nonzero accumulator (see schnorr48.c:156)
	 * - volatile prevents compiler from optimizing away the check
	 * - No logging here to avoid timing variation from log backends
	 * - Generic error hides which verification step failed
	 */
	volatile int sig2_result = edhoc_verify(peer_pubkey, signature_2.value,
						sig_struct_2, sig_struct_2_len);
	if (sig2_result != 0) {
		ret = -EACCES;
		goto err_wipe;
	}
	/* volatile forces constant-time path even on error (resolves i0bj timing side-channel) */

	ret = compute_th(ctx->th_3, ctx->th_2, 32, ciphertext_2, ct2_len,
			 id_cred_r.value, id_cred_r.len);
	if (ret != 0) {
		goto err_wipe;
	}

	/* PRK_4e3m = PRK_3e2m for SIGN_SIGN */
	memcpy(ctx->prk_4e3m, ctx->prk_3e2m, 32);

	/* Create Message 3 */
	/* PLAINTEXT_3 = (ID_CRED_I, Signature_3) */

	/* MAC_3 = EDHOC-KDF(PRK_4e3m, TH_3, "MAC_3", context_3, 32) */
	/* context_3 = << ID_CRED_I, TH_3, CRED_I >> */
	uint8_t context_3[128];
	ZCBOR_STATE_E(zse_ctx3, 0, context_3, sizeof(context_3), 0);
	if (!zcbor_bstr_encode_ptr(zse_ctx3, ctx->ed_pubkey, 32) ||
	    !zcbor_bstr_encode_ptr(zse_ctx3, ctx->th_3, 32) ||
	    !zcbor_bstr_encode_ptr(zse_ctx3, ctx->ed_pubkey, 32)) {
		ret = -ENOMEM;
		goto err_wipe;
	}
	size_t context_3_len = zse_ctx3->payload - context_3;

	ret = edhoc_kdf(ctx->prk_4e3m, ctx->th_3, "MAC_3", context_3, context_3_len, mac_3, 32);
	if (ret != 0) {
		goto err_wipe;
	}

	/* Sig_structure_3 per RFC 9528/9052 */
	size_t sig_struct_3_len;
	ret = build_sig_structure(ctx->ed_pubkey, 32, ctx->th_3, ctx->ed_pubkey, 32,
				  mac_3, 32, sig_struct_3, sizeof(sig_struct_3), &sig_struct_3_len);
	if (ret != 0) {
		goto err_wipe;
	}

	edhoc_sign(signature_3, ctx->ed_seed, ctx->ed_pubkey, sig_struct_3, sig_struct_3_len);

	/* Encode PLAINTEXT_3 */
	ZCBOR_STATE_E(zse_pt3, 0, plaintext_3, sizeof(plaintext_3), 0);
	if (!zcbor_bstr_encode_ptr(zse_pt3, ctx->ed_pubkey, 32) ||
	    !zcbor_bstr_encode_ptr(zse_pt3, signature_3, EDHOC_SIG_LEN)) {
		ret = -ENOMEM;
		goto err_wipe;
	}
	size_t pt3_len = zse_pt3->payload - plaintext_3;

	/* K_3 and IV_3 for AEAD */
	ret = edhoc_kdf(ctx->prk_3e2m, ctx->th_3, "K_3", NULL, 0, k_3, 16);
	if (ret != 0) {
		goto err_wipe;
	}
	ret = edhoc_kdf(ctx->prk_3e2m, ctx->th_3, "IV_3", NULL, 0, iv_3, 13);
	if (ret != 0) {
		goto err_wipe;
	}

	uint8_t a_3[96];
	size_t a_3_len;
	ret = build_enc_structure(a_3, sizeof(a_3), &a_3_len, ctx->th_3, ctx->ed_pubkey);
	if (ret != 0) {
		goto err_wipe;
	}

	/* Encrypt PLAINTEXT_3 -> CIPHERTEXT_3 (Message 3) */
	if (msg3_size < pt3_len + 8) {
		ret = -ENOMEM;
		goto err_wipe;
	}
	ret = aead_encrypt(k_3, iv_3, a_3, a_3_len, plaintext_3, pt3_len, msg3);
	if (ret != 0) {
		goto err_wipe;
	}
	*msg3_len = pt3_len + 8;

	/* TH_4 = H(TH_3, PLAINTEXT_3, CRED_I) per RFC 9528 Section 4.1.2 */
	ret = compute_th(ctx->th_4, ctx->th_3, 32, plaintext_3, pt3_len, ctx->ed_pubkey, 32);
	if (ret != 0) {
		goto err_wipe;
	}

	crypto_wipe(k_3, sizeof(k_3));
	crypto_wipe(iv_3, sizeof(iv_3));
	crypto_wipe(signature_3, sizeof(signature_3));
	crypto_wipe(keystream_2, sizeof(keystream_2));
	crypto_wipe(plaintext_2, sizeof(plaintext_2));
	crypto_wipe(mac_2, sizeof(mac_2));
	crypto_wipe(sig_struct_2, sizeof(sig_struct_2));
	crypto_wipe(mac_3, sizeof(mac_3));
	crypto_wipe(sig_struct_3, sizeof(sig_struct_3));
	crypto_wipe(plaintext_3, sizeof(plaintext_3));
	crypto_wipe(ctx->eph_sk, sizeof(ctx->eph_sk));

	ctx->state = EDHOC_STATE_COMPLETED;
	return 0;

err_wipe:
	crypto_wipe(g_xy, sizeof(g_xy));
	crypto_wipe(k_3, sizeof(k_3));
	crypto_wipe(iv_3, sizeof(iv_3));
	crypto_wipe(signature_3, sizeof(signature_3));
	crypto_wipe(keystream_2, sizeof(keystream_2));
	crypto_wipe(plaintext_2, sizeof(plaintext_2));
	crypto_wipe(mac_2, sizeof(mac_2));
	crypto_wipe(sig_struct_2, sizeof(sig_struct_2));
	crypto_wipe(mac_3, sizeof(mac_3));
	crypto_wipe(sig_struct_3, sizeof(sig_struct_3));
	crypto_wipe(plaintext_3, sizeof(plaintext_3));
	crypto_wipe(ctx->eph_sk, sizeof(ctx->eph_sk));
	crypto_wipe(ctx->prk_2e, sizeof(ctx->prk_2e));
	crypto_wipe(ctx->prk_3e2m, sizeof(ctx->prk_3e2m));
	crypto_wipe(ctx->prk_4e3m, sizeof(ctx->prk_4e3m));
	return ret;
}

int edhoc_initiator_export_oscore(struct edhoc_initiator *ctx,
				  struct edhoc_oscore_ctx *oscore)
{
	int ret = 0;
	uint8_t prk_out[32] = {0};
	uint8_t prk_exporter[32] = {0};

	if (ctx == NULL || oscore == NULL) {
		return -EINVAL;
	}
	if (ctx->state != EDHOC_STATE_COMPLETED) {
		return -EBUSY;
	}

	/* Exact match to Python EdhocInitiator.export_oscore() derivation
	 * (PRK_out label=7 with context=TH_4, PRK_exporter label=10,
	 * master_secret label=0, master_salt label=1) per uk36.4.1.3.
	 * ID assignment: sender_id=c_i, recipient_id=c_r for initiator.
	 * PRK wipe sequence: only on success path after derivation.
	 */
	ret = edhoc_kdf_int(ctx->prk_4e3m, ctx->th_4, 7,
			    ctx->th_4, 32, prk_out, 32);
	if (ret != 0) {
		goto wipe;
	}

	ret = edhoc_kdf_int(prk_out, ctx->th_4, 10,
			    NULL, 0, prk_exporter, 32);
	if (ret != 0) {
		goto wipe;
	}

	ret = edhoc_kdf_int(prk_exporter, ctx->th_4, 0,
			    NULL, 0, oscore->master_secret, 16);
	if (ret != 0) {
		goto wipe;
	}

	ret = edhoc_kdf_int(prk_exporter, ctx->th_4, 1,
			    NULL, 0, oscore->master_salt, 8);
	if (ret != 0) {
		goto wipe;
	}

	memcpy(oscore->sender_id, ctx->c_i, ctx->c_i_len);
	oscore->sender_id_len = ctx->c_i_len;
	memcpy(oscore->recipient_id, ctx->c_r, ctx->c_r_len);
	oscore->recipient_id_len = ctx->c_r_len;

	crypto_wipe(ctx->prk_2e, sizeof(ctx->prk_2e));
	crypto_wipe(ctx->prk_3e2m, sizeof(ctx->prk_3e2m));
	crypto_wipe(ctx->prk_4e3m, sizeof(ctx->prk_4e3m));
	crypto_wipe(prk_out, sizeof(prk_out));
	crypto_wipe(prk_exporter, sizeof(prk_exporter));

	ctx->state = EDHOC_STATE_EXPORTED;

	return 0;

wipe:
	crypto_wipe(oscore, sizeof(*oscore));
	crypto_wipe(ctx->prk_2e, sizeof(ctx->prk_2e));
	crypto_wipe(ctx->prk_3e2m, sizeof(ctx->prk_3e2m));
	crypto_wipe(ctx->prk_4e3m, sizeof(ctx->prk_4e3m));
	crypto_wipe(prk_out, sizeof(prk_out));
	crypto_wipe(prk_exporter, sizeof(prk_exporter));
	return ret;
}

int edhoc_responder_init(struct edhoc_responder *ctx,
			 const uint8_t *ed_seed,
			 const uint8_t *ed_pubkey,
			 const uint8_t *c_r, size_t c_r_len,
			 uint8_t corr)
{
	if (ctx == NULL || ed_seed == NULL || ed_pubkey == NULL) {
		return -EINVAL;
	}
	if (c_r_len > EDHOC_CID_MAX_LEN || corr > 3) {
		return -EINVAL;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->state = EDHOC_STATE_IDLE;
	ctx->method = EDHOC_METHOD_SIGN_SIGN;
	ctx->corr = corr;
	memcpy(ctx->ed_seed, ed_seed, EDHOC_ED25519_SK_LEN);
	memcpy(ctx->ed_pubkey, ed_pubkey, EDHOC_ED25519_PK_LEN);

	if (c_r != NULL && c_r_len > 0) {
		memcpy(ctx->c_r, c_r, c_r_len);
		ctx->c_r_len = c_r_len;
	} else {
		if (sys_csrand_get(ctx->c_r, 1) != 0) {
			return -ENODEV;
		}
		ctx->c_r_len = 1;
	}

	int ret = x25519_keypair(ctx->eph_sk, ctx->eph_pk);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

int edhoc_responder_process_msg1(struct edhoc_responder *ctx,
				 const uint8_t *msg1, size_t msg1_len,
				 uint8_t *msg2, size_t msg2_size,
				 size_t *msg2_len)
{
	int ret;
	uint8_t g_xy[32] = {0};
	uint8_t signature_2[EDHOC_SIG_LEN] = {0};
	uint8_t mac_2[32] = {0};
	uint8_t sig_struct_2[256] = {0};
	uint8_t plaintext_2[128] = {0};
	uint8_t keystream_2[128] = {0};
	uint8_t ciphertext_2[128] = {0};

	if (ctx == NULL || msg1 == NULL ||
	    msg2 == NULL || msg2_len == NULL) {
		return -EINVAL;
	}
	if (ctx->state != EDHOC_STATE_IDLE) {
		return -EBUSY;
	}

	/* Save msg1 for TH computation */
	if (msg1_len > sizeof(ctx->msg1)) {
		return -ENOMEM;
	}
	memcpy(ctx->msg1, msg1, msg1_len);
	ctx->msg1_len = msg1_len;

	/* Decode message_1 */
	ZCBOR_STATE_D(zsd, 0, msg1, msg1_len, 5, 0);

	int32_t method_corr;
	if (!zcbor_int32_decode(zsd, &method_corr)) {
		return -EINVAL;
	}
	/* METHOD_CORR = method * 4 + corr; extract method */
	/* SECURITY: Generic errors hide negotiation details */
	int method = method_corr / 4;
	if (method != EDHOC_METHOD_SIGN_SIGN) {
		LOG_WRN("Unsupported protocol parameters");
		return -ENOTSUP;
	}

	int32_t suites_i;
	if (!zcbor_int32_decode(zsd, &suites_i)) {
		return -EINVAL;
	}
	if (suites_i != EDHOC_SUITE_0) {
		LOG_WRN("Unsupported protocol parameters");
		return -ENOTSUP;
	}

	struct zcbor_string g_x;
	if (!zcbor_bstr_decode(zsd, &g_x)) {
		return -EINVAL;
	}
	if (g_x.len != EDHOC_X25519_KEY_LEN) {
		return -EINVAL;
	}
	memcpy(ctx->g_x, g_x.value, EDHOC_X25519_KEY_LEN);

	/* Decode C_I */
	int32_t c_i_int;
	struct zcbor_string c_i_bstr;
	if (zcbor_int32_decode(zsd, &c_i_int)) {
		if (c_i_int >= 0 && c_i_int <= 255) {
			ctx->c_i[0] = (uint8_t)c_i_int;
			ctx->c_i_len = 1;
		} else if (c_i_int >= -24 && c_i_int < 0) {
			ctx->c_i[0] = (uint8_t)(c_i_int + 256);
			ctx->c_i_len = 1;
		} else {
			return -EINVAL;
		}
	} else if (zcbor_bstr_decode(zsd, &c_i_bstr)) {
		if (c_i_bstr.len > EDHOC_CID_MAX_LEN) {
			return -EINVAL;
		}
		memcpy(ctx->c_i, c_i_bstr.value, c_i_bstr.len);
		ctx->c_i_len = c_i_bstr.len;
	} else {
		return -EINVAL;
	}
	if (!zcbor_payload_at_end(zsd) || zsd->constant_state->error) {
		return -EINVAL;
	}

	/* Compute shared secret */
	x25519_shared_secret(g_xy, ctx->eph_sk, ctx->g_x);
	/* SECURITY: Generic error hides small-order point attack detection */
	if (is_all_zeros(g_xy, sizeof(g_xy))) {
		LOG_WRN("Key exchange failed");
		ret = -EACCES;
		goto err_wipe;
	}

	/* TH_2 = H(H(message_1) || G_Y || C_R) per RFC 9528 Section 4.1.2 */
	uint8_t h_msg1[32];
	ret = sha256_hash(ctx->msg1, ctx->msg1_len, h_msg1);
	if (ret != 0) {
		goto err_wipe;
	}

	uint8_t th2_input[72];  /* 32 + 32 + up to 8 for C_R */
	size_t th2_input_len = 0;
	memcpy(th2_input + th2_input_len, h_msg1, 32);
	th2_input_len += 32;
	memcpy(th2_input + th2_input_len, ctx->eph_pk, 32);  /* G_Y = our eph_pk */
	th2_input_len += 32;
	memcpy(th2_input + th2_input_len, ctx->c_r, ctx->c_r_len);
	th2_input_len += ctx->c_r_len;
	ret = sha256_hash(th2_input, th2_input_len, ctx->th_2);
	if (ret != 0) {
		goto err_wipe;
	}

	/* PRK_2e */
	ret = hkdf_extract(ctx->th_2, 32, g_xy, 32, ctx->prk_2e);
	if (ret != 0) {
		goto err_wipe;
	}
	crypto_wipe(g_xy, sizeof(g_xy));

	/* PRK_3e2m = PRK_2e for SIGN_SIGN */
	memcpy(ctx->prk_3e2m, ctx->prk_2e, 32);

	/* MAC_2 = EDHOC-KDF(PRK_3e2m, TH_2, "MAC_2", context_2, 32) */
	/* context_2 = << C_R, ID_CRED_R, TH_2, CRED_R >> */
	uint8_t context_2[128];
	ZCBOR_STATE_E(zse_ctx2, 0, context_2, sizeof(context_2), 0);
	if (!zcbor_bstr_encode_ptr(zse_ctx2, ctx->c_r, ctx->c_r_len) ||
	    !zcbor_bstr_encode_ptr(zse_ctx2, ctx->ed_pubkey, 32) ||
	    !zcbor_bstr_encode_ptr(zse_ctx2, ctx->th_2, 32) ||
	    !zcbor_bstr_encode_ptr(zse_ctx2, ctx->ed_pubkey, 32)) {
		ret = -ENOMEM;
		goto err_wipe;
	}
	size_t context_2_len = zse_ctx2->payload - context_2;

	ret = edhoc_kdf(ctx->prk_3e2m, ctx->th_2, "MAC_2", context_2, context_2_len, mac_2, 32);
	if (ret != 0) {
		goto err_wipe;
	}

	/* Sig_structure_2 per RFC 9528/9052 */
	size_t sig_struct_2_len;
	ret = build_sig_structure(ctx->ed_pubkey, 32, ctx->th_2, ctx->ed_pubkey, 32,
				  mac_2, 32, sig_struct_2, sizeof(sig_struct_2), &sig_struct_2_len);
	if (ret != 0) {
		goto err_wipe;
	}

	edhoc_sign(signature_2, ctx->ed_seed, ctx->ed_pubkey, sig_struct_2, sig_struct_2_len);

	ZCBOR_STATE_E(zse_pt2, 0, plaintext_2, sizeof(plaintext_2), 0);
	if (!zcbor_bstr_encode_ptr(zse_pt2, ctx->ed_pubkey, 32) ||
	    !zcbor_bstr_encode_ptr(zse_pt2, signature_2, EDHOC_SIG_LEN)) {
		ret = -ENOMEM;
		goto err_wipe;
	}
	size_t pt2_len = zse_pt2->payload - plaintext_2;

	/*
	 * KEYSTREAM_2 for XOR encryption.
	 * RFC 9528 Section 4.3: message_2 uses XOR-only encryption without MAC.
	 * Authenticity comes from Signature_2 which covers MAC_2 over TH_2.
	 */
	ret = edhoc_kdf(ctx->prk_2e, ctx->th_2, "KEYSTREAM_2", NULL, 0,
			keystream_2, pt2_len);
	if (ret != 0) {
		goto err_wipe;
	}

	for (size_t i = 0; i < pt2_len; i++) {
		ciphertext_2[i] = plaintext_2[i] ^ keystream_2[i];
	}

	ret = compute_th(ctx->th_3, ctx->th_2, 32, ciphertext_2, pt2_len,
			 ctx->ed_pubkey, 32);
	if (ret != 0) {
		goto err_wipe;
	}

	/* Build message_2 = (G_Y || CIPHERTEXT_2, C_R) */
	ZCBOR_STATE_E(zse, 0, msg2, msg2_size, 0);

	/* G_Y || CIPHERTEXT_2 as single bstr */
	uint8_t g_y_ct2[160];
	memcpy(g_y_ct2, ctx->eph_pk, 32);
	memcpy(g_y_ct2 + 32, ciphertext_2, pt2_len);

	if (!zcbor_bstr_encode_ptr(zse, g_y_ct2, 32 + pt2_len)) {
		ret = -ENOMEM;
		goto err_wipe;
	}

	/* C_R encoding per RFC 9528 Section 3.3.2 (bstr_identifier):
	 * - Values 0-23: encode as CBOR positive integer
	 * - Values -24 to -1 (stored as 232-255): encode as CBOR negative integer
	 * - Other values: encode as CBOR byte string
	 */
	if (ctx->c_r_len == 1 && ctx->c_r[0] <= 23) {
		if (!zcbor_int32_put(zse, ctx->c_r[0])) {
			ret = -ENOMEM;
			goto err_wipe;
		}
	} else if (ctx->c_r_len == 1 && ctx->c_r[0] >= 232) {
		/* Negative integer: stored as (original + 256), reverse it */
		if (!zcbor_int32_put(zse, (int32_t)ctx->c_r[0] - 256)) {
			ret = -ENOMEM;
			goto err_wipe;
		}
	} else {
		if (!zcbor_bstr_encode_ptr(zse, ctx->c_r, ctx->c_r_len)) {
			ret = -ENOMEM;
			goto err_wipe;
		}
	}

	*msg2_len = zse->payload - msg2;

	crypto_wipe(signature_2, sizeof(signature_2));
	crypto_wipe(plaintext_2, sizeof(plaintext_2));
	crypto_wipe(keystream_2, sizeof(keystream_2));
	crypto_wipe(mac_2, sizeof(mac_2));
	crypto_wipe(sig_struct_2, sizeof(sig_struct_2));
	crypto_wipe(ciphertext_2, sizeof(ciphertext_2));
	crypto_wipe(ctx->eph_sk, sizeof(ctx->eph_sk));

	ctx->state = EDHOC_STATE_MSG2_SENT;
	return 0;

err_wipe:
	crypto_wipe(g_xy, sizeof(g_xy));
	crypto_wipe(signature_2, sizeof(signature_2));
	crypto_wipe(plaintext_2, sizeof(plaintext_2));
	crypto_wipe(keystream_2, sizeof(keystream_2));
	crypto_wipe(mac_2, sizeof(mac_2));
	crypto_wipe(sig_struct_2, sizeof(sig_struct_2));
	crypto_wipe(ciphertext_2, sizeof(ciphertext_2));
	crypto_wipe(ctx->eph_sk, sizeof(ctx->eph_sk));
	crypto_wipe(ctx->prk_2e, sizeof(ctx->prk_2e));
	crypto_wipe(ctx->prk_3e2m, sizeof(ctx->prk_3e2m));
	return ret;
}

int edhoc_responder_process_msg3(struct edhoc_responder *ctx,
				 const uint8_t *msg3, size_t msg3_len,
				 const uint8_t *peer_pubkey)
{
	int ret;
	uint8_t k_3[16] = {0};
	uint8_t iv_3[13] = {0};
	uint8_t plaintext_3[EDHOC_MAX_MSG3_LEN - EDHOC_TAG_LEN] = {0};
	uint8_t mac_3[32] = {0};
	uint8_t sig_struct_3[256] = {0};

	if (ctx == NULL || msg3 == NULL || peer_pubkey == NULL) {
		return -EINVAL;
	}
	if (ctx->state != EDHOC_STATE_MSG2_SENT) {
		return -EBUSY;
	}
	/* Validate msg3_len to prevent stack buffer overflow */
	if (msg3_len > EDHOC_MAX_MSG3_LEN) {
		return -ENOMEM;
	}

	/* K_3 and IV_3 for AEAD decryption */
	ret = edhoc_kdf(ctx->prk_3e2m, ctx->th_3, "K_3", NULL, 0, k_3, 16);
	if (ret != 0) {
		goto err_wipe;
	}
	ret = edhoc_kdf(ctx->prk_3e2m, ctx->th_3, "IV_3", NULL, 0, iv_3, 13);
	if (ret != 0) {
		goto err_wipe;
	}

	uint8_t a_3[96];
	size_t a_3_len;
	ret = build_enc_structure(a_3, sizeof(a_3), &a_3_len, ctx->th_3, peer_pubkey);
	if (ret != 0) {
		goto err_wipe;
	}

	/* Decrypt CIPHERTEXT_3 */
	ret = aead_decrypt(k_3, iv_3, a_3, a_3_len, msg3, msg3_len, plaintext_3);
	/* SECURITY: Generic error hides decryption vs verification failure */
	if (ret != 0) {
		LOG_WRN("Authentication failed");
		goto err_wipe;
	}
	size_t pt3_len = msg3_len - 8;

	/* Parse PLAINTEXT_3 = (ID_CRED_I, Signature_3) */
	ZCBOR_STATE_D(zsd, 0, plaintext_3, pt3_len, 2, 0);

	struct zcbor_string id_cred_i;
	if (!zcbor_bstr_decode(zsd, &id_cred_i)) {
		ret = -EINVAL;
		goto err_wipe;
	}

	/*
	 * SECURITY: Validate ID_CRED_I against expected peer identity.
	 * RFC 9528 requires that ID_CRED corresponds to the credential used
	 * for verification. Without this check, a malicious party could include
	 * arbitrary ID_CRED data while we verify against a different key.
	 */
	if (id_cred_i.len != EDHOC_ED25519_PK_LEN) {
		LOG_WRN("Peer identity mismatch");
		ret = -EACCES;
		goto err_wipe;
	}
	if (crypto_verify32(id_cred_i.value, peer_pubkey) != 0) {
		LOG_WRN("Peer identity mismatch");
		ret = -EACCES;
		goto err_wipe;
	}

	struct zcbor_string signature_3;
	if (!zcbor_bstr_decode(zsd, &signature_3)) {
		ret = -EINVAL;
		goto err_wipe;
	}
	if (signature_3.len != EDHOC_SIG_LEN) {
		ret = -EINVAL;
		goto err_wipe;
	}
	if (!zcbor_payload_at_end(zsd) || zsd->constant_state->error) {
		ret = -EINVAL;
		goto err_wipe;
	}

	/* PRK_4e3m = PRK_3e2m for SIGN_SIGN */
	memcpy(ctx->prk_4e3m, ctx->prk_3e2m, 32);

	/* Verify Signature_3 per RFC 9528 */
	/* MAC_3 = EDHOC-KDF(PRK_4e3m, TH_3, "MAC_3", context_3, 32) */
	uint8_t context_3[128];
	ZCBOR_STATE_E(zse_ctx3, 0, context_3, sizeof(context_3), 0);
	if (!zcbor_bstr_encode_ptr(zse_ctx3, peer_pubkey, 32) ||
	    !zcbor_bstr_encode_ptr(zse_ctx3, ctx->th_3, 32) ||
	    !zcbor_bstr_encode_ptr(zse_ctx3, peer_pubkey, 32)) {
		ret = -ENOMEM;
		goto err_wipe;
	}
	size_t context_3_len = zse_ctx3->payload - context_3;

	ret = edhoc_kdf(ctx->prk_4e3m, ctx->th_3, "MAC_3", context_3, context_3_len, mac_3, 32);
	if (ret != 0) {
		goto err_wipe;
	}

	size_t sig_struct_3_len;
	ret = build_sig_structure(peer_pubkey, 32, ctx->th_3, peer_pubkey, 32,
				  mac_3, 32, sig_struct_3, sizeof(sig_struct_3), &sig_struct_3_len);
	if (ret != 0) {
		goto err_wipe;
	}

	/*
	 * SECURITY: Constant-time signature verification.
	 * - schnorr48_verify uses crypto_verify16 + nonzero accumulator (see schnorr48.c:156)
	 * - volatile prevents compiler from optimizing away the check
	 * - No logging here to avoid timing variation from log backends
	 * - Generic error hides which verification step failed
	 */
	volatile int sig3_result = edhoc_verify(peer_pubkey, signature_3.value,
						sig_struct_3, sig_struct_3_len);
	if (sig3_result != 0) {
		ret = -EACCES;
		goto err_wipe;
	}

	/* TH_4 = H(TH_3, PLAINTEXT_3, CRED_I) per RFC 9528 Section 4.2.2 */
	ret = compute_th(ctx->th_4, ctx->th_3, 32, plaintext_3, pt3_len, peer_pubkey, 32);
	if (ret != 0) {
		goto err_wipe;
	}

	crypto_wipe(k_3, sizeof(k_3));
	crypto_wipe(iv_3, sizeof(iv_3));
	crypto_wipe(plaintext_3, sizeof(plaintext_3));
	crypto_wipe(mac_3, sizeof(mac_3));
	crypto_wipe(sig_struct_3, sizeof(sig_struct_3));
	crypto_wipe(ctx->eph_sk, sizeof(ctx->eph_sk));

	ctx->state = EDHOC_STATE_COMPLETED;
	return 0;

err_wipe:
	crypto_wipe(k_3, sizeof(k_3));
	crypto_wipe(iv_3, sizeof(iv_3));
	crypto_wipe(plaintext_3, sizeof(plaintext_3));
	crypto_wipe(mac_3, sizeof(mac_3));
	crypto_wipe(sig_struct_3, sizeof(sig_struct_3));
	crypto_wipe(ctx->eph_sk, sizeof(ctx->eph_sk));
	crypto_wipe(ctx->prk_2e, sizeof(ctx->prk_2e));
	crypto_wipe(ctx->prk_3e2m, sizeof(ctx->prk_3e2m));
	crypto_wipe(ctx->prk_4e3m, sizeof(ctx->prk_4e3m));
	return ret;
}

int edhoc_responder_export_oscore(struct edhoc_responder *ctx,
				  struct edhoc_oscore_ctx *oscore)
{
	int ret = 0;
	uint8_t prk_out[32] = {0};
	uint8_t prk_exporter[32] = {0};

	if (ctx == NULL || oscore == NULL) {
		return -EINVAL;
	}
	if (ctx->state != EDHOC_STATE_COMPLETED) {
		return -EBUSY;
	}

	/* Exact match to Python EdhocResponder.export_oscore() derivation
	 * (same PRK_out=7/PRK_exporter=10/master=0/salt=1 chain) and
	 * ID assignment (sender_id=c_r, recipient_id=c_i for responder).
	 * PRK wipe sequence matches Python exactly; oscore wiped on error.
	 */
	ret = edhoc_kdf_int(ctx->prk_4e3m, ctx->th_4, 7,
			    ctx->th_4, 32, prk_out, 32);
	if (ret != 0) {
		goto wipe;
	}

	ret = edhoc_kdf_int(prk_out, ctx->th_4, 10,
			    NULL, 0, prk_exporter, 32);
	if (ret != 0) {
		goto wipe;
	}

	ret = edhoc_kdf_int(prk_exporter, ctx->th_4, 0,
			    NULL, 0, oscore->master_secret, 16);
	if (ret != 0) {
		goto wipe;
	}

	ret = edhoc_kdf_int(prk_exporter, ctx->th_4, 1,
			    NULL, 0, oscore->master_salt, 8);
	if (ret != 0) {
		goto wipe;
	}

	memcpy(oscore->sender_id, ctx->c_r, ctx->c_r_len);
	oscore->sender_id_len = ctx->c_r_len;
	memcpy(oscore->recipient_id, ctx->c_i, ctx->c_i_len);
	oscore->recipient_id_len = ctx->c_i_len;

	crypto_wipe(ctx->prk_2e, sizeof(ctx->prk_2e));
	crypto_wipe(ctx->prk_3e2m, sizeof(ctx->prk_3e2m));
	crypto_wipe(ctx->prk_4e3m, sizeof(ctx->prk_4e3m));
	crypto_wipe(prk_out, sizeof(prk_out));
	crypto_wipe(prk_exporter, sizeof(prk_exporter));

	ctx->state = EDHOC_STATE_EXPORTED;

	return 0;

wipe:
	crypto_wipe(oscore, sizeof(*oscore));
	crypto_wipe(ctx->prk_2e, sizeof(ctx->prk_2e));
	crypto_wipe(ctx->prk_3e2m, sizeof(ctx->prk_3e2m));
	crypto_wipe(ctx->prk_4e3m, sizeof(ctx->prk_4e3m));
	crypto_wipe(prk_out, sizeof(prk_out));
	crypto_wipe(prk_exporter, sizeof(prk_exporter));
	return ret;
}

void edhoc_initiator_wipe(struct edhoc_initiator *ctx)
{
	if (ctx == NULL) {
		return;
	}
	crypto_wipe(ctx, sizeof(*ctx));
}

void edhoc_responder_wipe(struct edhoc_responder *ctx)
{
	if (ctx == NULL) {
		return;
	}
	crypto_wipe(ctx, sizeof(*ctx));
}
