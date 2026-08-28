/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file edhoc_initiator.c
 * @brief EDHOC initiator protocol implementation
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/logging/log.h>

#include <lichen/edhoc.h>
#include <lichen/schnorr48.h>
#include <monocypher.h>
#include <zcbor_common.h>
#include <zcbor_encode.h>
#include <zcbor_decode.h>

#include "edhoc_internal.h"

LOG_MODULE_DECLARE(edhoc, CONFIG_LICHEN_EDHOC_LOG_LEVEL);

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
BUILD_ASSERT(EDHOC_SIG_LEN == SCHNORR48_SIG_LEN,
	     "EDHOC_SIG_LEN must match SCHNORR48_SIG_LEN");

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
	if (ctx->state == EDHOC_STATE_ERROR) {
		return -EBUSY;
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

	uint8_t encoded[EDHOC_MSG1_MAX_LEN];
	ZCBOR_STATE_E(zse, 0, encoded, sizeof(encoded), 0);

	/* RFC 9528 encodes METHOD directly.  The METHOD_CORR draft field was
	 * removed before publication and must never appear on the wire. */
	if (!zcbor_int32_put(zse, ctx->method)) {
		return -ENOMEM;
	}
	if (!zcbor_int32_put(zse, EDHOC_SUITE_0)) {
		return -ENOMEM;
	}
	if (!zcbor_bstr_encode_ptr(zse, ctx->eph_pk, EDHOC_X25519_KEY_LEN)) {
		return -ENOMEM;
	}

	/* Emit the profile's canonical byte-string form.  Decoders also accept
	 * compact integers, but deterministic senders do not alternate forms. */
	if (!zcbor_bstr_encode_ptr(zse, ctx->c_i, ctx->c_i_len)) {
		return -ENOMEM;
	}

	size_t encoded_len = (size_t)(zse->payload - encoded);
	if (msg1_size < encoded_len) {
		return -ENOMEM;
	}
	memcpy(msg1, encoded, encoded_len);
	*msg1_len = encoded_len;

	/* Save msg1 for TH computation */
	/* SECURITY: Generic error hides internal buffer sizes */
	if (*msg1_len > sizeof(ctx->msg1)) {
		LOG_WRN("Message too large");
		return -ENOMEM;
	}
	memcpy(ctx->msg1, encoded, *msg1_len);
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
	int ret = -EINVAL;
	uint8_t g_xy[32] = {0}, keystream[128] = {0}, plaintext_2[128] = {0};
	uint8_t id_cred_r[11], cred_r[40], id_cred_i[11], cred_i[40];
	uint8_t mac_2[32] = {0}, mac_3[32] = {0};
	uint8_t sig_input[256] = {0}, signature_3[EDHOC_SIG_LEN] = {0};
	uint8_t context[128] = {0}, plaintext_3[80] = {0};
	uint8_t k_3[16] = {0}, iv_3[13] = {0}, aad[64] = {0};
	uint8_t ciphertext_3[80] = {0}, encoded_msg3[96] = {0};
	size_t context_len, sig_input_len, pt3_len, aad_len, encoded_len;

	if (ctx == NULL || msg2 == NULL || peer_pubkey == NULL || msg3 == NULL ||
	    msg3_len == NULL) {
		return -EINVAL;
	}
	if (ctx->state != EDHOC_STATE_MSG1_SENT) {
		return -EBUSY;
	}
	ZCBOR_STATE_D(zsd, 0, msg2, msg2_len, 2, 0);
	struct zcbor_string combined;
	if (!zcbor_bstr_decode(zsd, &combined) || !zcbor_payload_at_end(zsd) ||
	    zsd->constant_state->error || combined.len <= 32 || combined.len > 160) {
		goto fail;
	}
	memcpy(ctx->g_y, combined.value, 32);
	const uint8_t *ciphertext_2 = combined.value + 32;
	size_t ciphertext_2_len = combined.len - 32;
	x25519_shared_secret(g_xy, ctx->eph_sk, ctx->g_y);
	if (is_all_zeros(g_xy, sizeof(g_xy))) {
		ret = -EACCES;
		goto fail;
	}
	if ((ret = edhoc_compute_th2(ctx->g_y, ctx->msg1, ctx->msg1_len, ctx->th_2)) != 0 ||
	    (ret = hkdf_extract(ctx->th_2, 32, g_xy, 32, ctx->prk_2e)) != 0 ||
	    (ret = edhoc_kdf_int(ctx->prk_2e, 0, ctx->th_2, 32,
				 keystream, ciphertext_2_len)) != 0) {
		goto fail;
	}
	for (size_t i = 0; i < ciphertext_2_len; i++) {
		plaintext_2[i] = ciphertext_2[i] ^ keystream[i];
	}
	size_t cid_len;
	if ((ret = edhoc_decode_identifier(plaintext_2, ciphertext_2_len, ctx->c_r,
					   &ctx->c_r_len, &cid_len)) != 0 ||
	    (ctx->c_i_len == ctx->c_r_len &&
	     memcmp(ctx->c_i, ctx->c_r, ctx->c_i_len) == 0)) {
		ret = -EACCES;
		goto fail;
	}
	if ((ret = edhoc_encode_id_cred(peer_pubkey, id_cred_r)) != 0 ||
	    ciphertext_2_len < cid_len + sizeof(id_cred_r) ||
	    memcmp(plaintext_2 + cid_len, id_cred_r, sizeof(id_cred_r)) != 0) {
		ret = -EACCES;
		goto fail;
	}
	ZCBOR_STATE_D(zsd_sig, 0, plaintext_2 + cid_len + sizeof(id_cred_r),
			ciphertext_2_len - cid_len - sizeof(id_cred_r), 2, 0);
	struct zcbor_string signature_2;
	if (!zcbor_bstr_decode(zsd_sig, &signature_2) || signature_2.len != EDHOC_SIG_LEN ||
	    !zcbor_payload_at_end(zsd_sig) || zsd_sig->constant_state->error) {
		ret = -EINVAL;
		goto fail;
	}
	memcpy(ctx->prk_3e2m, ctx->prk_2e, 32);
	edhoc_encode_credential(peer_pubkey, cred_r);
	if ((ret = edhoc_encode_identifier(ctx->c_r, ctx->c_r_len, context,
					   sizeof(context), &context_len)) != 0 ||
	    context_len + 11 + 34 + 40 > sizeof(context)) {
		goto fail;
	}
	memcpy(context + context_len, id_cred_r, 11); context_len += 11;
	context[context_len++] = 0x58; context[context_len++] = 0x20;
	memcpy(context + context_len, ctx->th_2, 32); context_len += 32;
	memcpy(context + context_len, cred_r, 40); context_len += 40;
	if ((ret = edhoc_kdf_int(ctx->prk_3e2m, 2, context, context_len, mac_2, 32)) != 0 ||
	    (ret = build_sig_structure(id_cred_r, 11, ctx->th_2, cred_r, 40,
				       mac_2, 32, sig_input, sizeof(sig_input), &sig_input_len)) != 0 ||
	    edhoc_verify(peer_pubkey, signature_2.value, sig_input, sig_input_len) != 0) {
		ret = -EACCES;
		goto fail;
	}
	if ((ret = edhoc_compute_transcript(ctx->th_2, plaintext_2, ciphertext_2_len,
					    cred_r, 40, ctx->th_3)) != 0) {
		goto fail;
	}
	memcpy(ctx->prk_4e3m, ctx->prk_3e2m, 32);
	edhoc_encode_id_cred(ctx->ed_pubkey, id_cred_i);
	edhoc_encode_credential(ctx->ed_pubkey, cred_i);
	memcpy(context, id_cred_i, 11); context_len = 11;
	context[context_len++] = 0x58; context[context_len++] = 0x20;
	memcpy(context + context_len, ctx->th_3, 32); context_len += 32;
	memcpy(context + context_len, cred_i, 40); context_len += 40;
	if ((ret = edhoc_kdf_int(ctx->prk_4e3m, 6, context, context_len, mac_3, 32)) != 0 ||
	    (ret = build_sig_structure(id_cred_i, 11, ctx->th_3, cred_i, 40,
				       mac_3, 32, sig_input, sizeof(sig_input), &sig_input_len)) != 0 ||
	    (ret = edhoc_sign(signature_3, ctx->ed_seed, ctx->ed_pubkey,
			      sig_input, sig_input_len)) != 0) {
		goto fail;
	}
	memcpy(plaintext_3, id_cred_i, 11);
	plaintext_3[11] = 0x58; plaintext_3[12] = EDHOC_SIG_LEN;
	memcpy(plaintext_3 + 13, signature_3, EDHOC_SIG_LEN);
	pt3_len = 13 + EDHOC_SIG_LEN;
	if ((ret = edhoc_kdf_int(ctx->prk_3e2m, 3, ctx->th_3, 32, k_3, 16)) != 0 ||
	    (ret = edhoc_kdf_int(ctx->prk_3e2m, 4, ctx->th_3, 32, iv_3, 13)) != 0 ||
	    (ret = build_enc_structure(aad, sizeof(aad), &aad_len, ctx->th_3)) != 0 ||
	    (ret = aead_encrypt(k_3, iv_3, aad, aad_len, plaintext_3, pt3_len,
			       ciphertext_3)) != 0 ||
	    (ret = edhoc_compute_transcript(ctx->th_3, plaintext_3, pt3_len,
					    cred_i, 40, ctx->th_4)) != 0) {
		goto fail;
	}
	ZCBOR_STATE_E(zse_out, 0, encoded_msg3, sizeof(encoded_msg3), 0);
	if (!zcbor_bstr_encode_ptr(zse_out, ciphertext_3, pt3_len + EDHOC_TAG_LEN)) {
		ret = -ENOMEM;
		goto fail;
	}
	encoded_len = zse_out->payload - encoded_msg3;
	if (msg3_size < encoded_len) {
		ret = -ENOMEM;
		goto fail;
	}
	memcpy(msg3, encoded_msg3, encoded_len);
	*msg3_len = encoded_len;
	ctx->state = EDHOC_STATE_COMPLETED;
	ret = 0;
	goto wipe;

fail:
	ctx->state = EDHOC_STATE_ERROR;
	crypto_wipe(ctx->prk_2e, sizeof(ctx->prk_2e));
	crypto_wipe(ctx->prk_3e2m, sizeof(ctx->prk_3e2m));
	crypto_wipe(ctx->prk_4e3m, sizeof(ctx->prk_4e3m));
wipe:
	crypto_wipe(g_xy, sizeof(g_xy)); crypto_wipe(keystream, sizeof(keystream));
	crypto_wipe(plaintext_2, sizeof(plaintext_2)); crypto_wipe(mac_2, sizeof(mac_2));
	crypto_wipe(mac_3, sizeof(mac_3)); crypto_wipe(sig_input, sizeof(sig_input));
	crypto_wipe(signature_3, sizeof(signature_3)); crypto_wipe(plaintext_3, sizeof(plaintext_3));
	crypto_wipe(k_3, sizeof(k_3)); crypto_wipe(iv_3, sizeof(iv_3));
	crypto_wipe(ciphertext_3, sizeof(ciphertext_3));
	crypto_wipe(ctx->eph_sk, sizeof(ctx->eph_sk));
	crypto_wipe(ctx->ed_seed, sizeof(ctx->ed_seed));
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

	/* RFC 9528 Sections 4.2.1 and Appendix A.1: PRK_out label 7,
	 * PRK_exporter label 10, master_secret label 0, master_salt label 1.
	 * Table 14 assigns sender_id=C_R and recipient_id=C_I to the initiator.
	 * PRK wipe sequence: only on success path after derivation.
	 */
	ret = edhoc_kdf_int(ctx->prk_4e3m, 7,
			    ctx->th_4, 32, prk_out, 32);
	if (ret != 0) {
		goto wipe;
	}

	ret = edhoc_kdf_int(prk_out, 10,
			    NULL, 0, prk_exporter, 32);
	if (ret != 0) {
		goto wipe;
	}

	ret = edhoc_kdf_int(prk_exporter, 0,
			    NULL, 0, oscore->master_secret, 16);
	if (ret != 0) {
		goto wipe;
	}

	ret = edhoc_kdf_int(prk_exporter, 1,
			    NULL, 0, oscore->master_salt, 8);
	if (ret != 0) {
		goto wipe;
	}

	memcpy(oscore->sender_id, ctx->c_r, ctx->c_r_len);
	oscore->sender_id_len = ctx->c_r_len;
	memcpy(oscore->recipient_id, ctx->c_i, ctx->c_i_len);
	oscore->recipient_id_len = ctx->c_i_len;

	ctx->state = EDHOC_STATE_EXPORTED;

	crypto_wipe(ctx->prk_2e, sizeof(ctx->prk_2e));
	crypto_wipe(ctx->prk_3e2m, sizeof(ctx->prk_3e2m));
	crypto_wipe(ctx->prk_4e3m, sizeof(ctx->prk_4e3m));
	crypto_wipe(prk_out, sizeof(prk_out));
	crypto_wipe(prk_exporter, sizeof(prk_exporter));

	return 0;

wipe:
	ctx->state = EDHOC_STATE_ERROR;
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
