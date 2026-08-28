/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file edhoc_responder.c
 * @brief EDHOC responder protocol implementation
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

LOG_MODULE_REGISTER(edhoc, CONFIG_LICHEN_EDHOC_LOG_LEVEL);

/*
 * SECURITY: Compile-time checks to ensure struct field sizes match the
 * constants used in memcpy operations. Prevents maintenance hazards if
 * constants are changed without updating struct definitions.
 */
BUILD_ASSERT(sizeof(((struct edhoc_responder *)0)->g_x) >= EDHOC_X25519_KEY_LEN,
	     "g_x too small for EDHOC_X25519_KEY_LEN");
BUILD_ASSERT(sizeof(((struct edhoc_responder *)0)->ed_seed) >= EDHOC_ED25519_SK_LEN,
	     "ed_seed too small for EDHOC_ED25519_SK_LEN");
BUILD_ASSERT(sizeof(((struct edhoc_responder *)0)->ed_pubkey) >= EDHOC_ED25519_PK_LEN,
	     "ed_pubkey too small for EDHOC_ED25519_PK_LEN");

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
	if (ctx->state == EDHOC_STATE_ERROR) {
		return -EBUSY;
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
	int ret = -EINVAL;
	uint8_t g_xy[32] = {0}, signature_2[EDHOC_SIG_LEN] = {0};
	uint8_t id_cred_r[11], cred_r[40], mac_2[32] = {0};
	uint8_t sig_input[256] = {0}, context[128] = {0};
	uint8_t plaintext_2[128] = {0}, keystream[128] = {0};
	uint8_t combined[160] = {0}, encoded_msg2[164] = {0};
	size_t context_len, sig_input_len, cid_len, pt_len, encoded_len;

	if (ctx == NULL || msg1 == NULL ||
	    msg2 == NULL || msg2_len == NULL) {
		return -EINVAL;
	}
	if (ctx->state != EDHOC_STATE_IDLE) {
		return -EBUSY;
	}

	if (msg1_len > sizeof(ctx->msg1)) {
		return -ENOMEM;
	}
	ZCBOR_STATE_D(zsd, 0, msg1, msg1_len, 5, 0);
	int32_t method, suite;
	if (!zcbor_int32_decode(zsd, &method) || method != EDHOC_METHOD_SIGN_SIGN ||
	    !zcbor_int32_decode(zsd, &suite) || suite != EDHOC_SUITE_0) {
		ret = -ENOTSUP;
		goto fail;
	}
	struct zcbor_string g_x;
	if (!zcbor_bstr_decode(zsd, &g_x) || g_x.len != EDHOC_X25519_KEY_LEN) {
		goto fail;
	}
	memcpy(ctx->g_x, g_x.value, EDHOC_X25519_KEY_LEN);
	size_t remaining = msg1_len - (size_t)(zsd->payload - msg1), consumed;
	if ((ret = edhoc_decode_identifier(zsd->payload, remaining, ctx->c_i,
					   &ctx->c_i_len, &consumed)) != 0) {
		goto fail;
	}
	zsd->payload += consumed;
	if (!zcbor_payload_at_end(zsd) || zsd->constant_state->error) {
		goto fail;
	}
	if (ctx->c_i_len == ctx->c_r_len &&
	    memcmp(ctx->c_i, ctx->c_r, ctx->c_i_len) == 0) {
		ctx->c_r[0] = ctx->c_i_len == 1 && ctx->c_i[0] == 0 ? 1 : 0;
		ctx->c_r_len = 1;
	}
	memcpy(ctx->msg1, msg1, msg1_len); ctx->msg1_len = msg1_len;
	x25519_shared_secret(g_xy, ctx->eph_sk, ctx->g_x);
	if (is_all_zeros(g_xy, sizeof(g_xy))) {
		ret = -EACCES;
		goto fail;
	}
	if ((ret = edhoc_compute_th2(ctx->eph_pk, msg1, msg1_len, ctx->th_2)) != 0 ||
	    (ret = hkdf_extract(ctx->th_2, 32, g_xy, 32, ctx->prk_2e)) != 0 ||
	    (ret = edhoc_encode_id_cred(ctx->ed_pubkey, id_cred_r)) != 0) {
		goto fail;
	}
	memcpy(ctx->prk_3e2m, ctx->prk_2e, 32);
	edhoc_encode_credential(ctx->ed_pubkey, cred_r);
	if ((ret = edhoc_encode_identifier(ctx->c_r, ctx->c_r_len, context,
					   sizeof(context), &context_len)) != 0 ||
	    context_len + 85 > sizeof(context)) {
		goto fail;
	}
	memcpy(context + context_len, id_cred_r, 11); context_len += 11;
	context[context_len++] = 0x58; context[context_len++] = 0x20;
	memcpy(context + context_len, ctx->th_2, 32); context_len += 32;
	memcpy(context + context_len, cred_r, 40); context_len += 40;
	if ((ret = edhoc_kdf_int(ctx->prk_3e2m, 2, context, context_len, mac_2, 32)) != 0 ||
	    (ret = build_sig_structure(id_cred_r, 11, ctx->th_2, cred_r, 40,
				       mac_2, 32, sig_input, sizeof(sig_input), &sig_input_len)) != 0 ||
	    (ret = edhoc_sign(signature_2, ctx->ed_seed, ctx->ed_pubkey,
			      sig_input, sig_input_len)) != 0 ||
	    (ret = edhoc_encode_identifier(ctx->c_r, ctx->c_r_len, plaintext_2,
					   sizeof(plaintext_2), &cid_len)) != 0) {
		goto fail;
	}
	memcpy(plaintext_2 + cid_len, id_cred_r, 11);
	plaintext_2[cid_len + 11] = 0x58;
	plaintext_2[cid_len + 12] = EDHOC_SIG_LEN;
	memcpy(plaintext_2 + cid_len + 13, signature_2, EDHOC_SIG_LEN);
	pt_len = cid_len + 13 + EDHOC_SIG_LEN;
	if ((ret = edhoc_kdf_int(ctx->prk_2e, 0, ctx->th_2, 32,
				 keystream, pt_len)) != 0 ||
	    (ret = edhoc_compute_transcript(ctx->th_2, plaintext_2, pt_len,
					    cred_r, 40, ctx->th_3)) != 0) {
		goto fail;
	}
	memcpy(combined, ctx->eph_pk, 32);
	for (size_t i = 0; i < pt_len; i++) {
		combined[32 + i] = plaintext_2[i] ^ keystream[i];
	}
	ZCBOR_STATE_E(zse_out, 0, encoded_msg2, sizeof(encoded_msg2), 0);
	if (!zcbor_bstr_encode_ptr(zse_out, combined, 32 + pt_len)) {
		ret = -ENOMEM;
		goto fail;
	}
	encoded_len = zse_out->payload - encoded_msg2;
	if (msg2_size < encoded_len) {
		ret = -ENOMEM;
		goto fail;
	}
	memcpy(msg2, encoded_msg2, encoded_len); *msg2_len = encoded_len;
	ctx->state = EDHOC_STATE_MSG2_SENT;
	ret = 0;
	goto wipe;

fail:
	ctx->state = EDHOC_STATE_ERROR;
	crypto_wipe(ctx->prk_2e, sizeof(ctx->prk_2e));
	crypto_wipe(ctx->prk_3e2m, sizeof(ctx->prk_3e2m));
	wipe:
	crypto_wipe(g_xy, sizeof(g_xy)); crypto_wipe(signature_2, sizeof(signature_2));
	crypto_wipe(plaintext_2, sizeof(plaintext_2)); crypto_wipe(keystream, sizeof(keystream));
	crypto_wipe(mac_2, sizeof(mac_2)); crypto_wipe(sig_input, sizeof(sig_input));
	crypto_wipe(ctx->eph_sk, sizeof(ctx->eph_sk));
	crypto_wipe(ctx->ed_seed, sizeof(ctx->ed_seed));
	return ret;
}

int edhoc_responder_process_msg3(struct edhoc_responder *ctx,
				 const uint8_t *msg3, size_t msg3_len,
				 const uint8_t *peer_pubkey)
{
	int ret = -EINVAL;
	uint8_t k_3[16] = {0}, iv_3[13] = {0}, aad[64] = {0};
	uint8_t plaintext_3[128] = {0}, expected_id_cred[11], credential[40];
	uint8_t mac_3[32] = {0}, context[128] = {0}, sig_input[256] = {0};
	size_t aad_len, context_len = 0, sig_input_len;

	if (ctx == NULL || msg3 == NULL || peer_pubkey == NULL) {
		return -EINVAL;
	}
	if (ctx->state != EDHOC_STATE_MSG2_SENT) {
		return -EBUSY;
	}
	ZCBOR_STATE_D(zsd_msg3, 0, msg3, msg3_len, 2, 0);
	struct zcbor_string ciphertext_3;
	if (!zcbor_bstr_decode(zsd_msg3, &ciphertext_3) ||
	    !zcbor_payload_at_end(zsd_msg3) || zsd_msg3->constant_state->error ||
	    ciphertext_3.len <= EDHOC_TAG_LEN || ciphertext_3.len > sizeof(plaintext_3)) {
		goto fail;
	}
	if ((ret = edhoc_kdf_int(ctx->prk_3e2m, 3, ctx->th_3, 32, k_3, 16)) != 0 ||
	    (ret = edhoc_kdf_int(ctx->prk_3e2m, 4, ctx->th_3, 32, iv_3, 13)) != 0 ||
	    (ret = build_enc_structure(aad, sizeof(aad), &aad_len, ctx->th_3)) != 0 ||
	    (ret = aead_decrypt(k_3, iv_3, aad, aad_len, ciphertext_3.value,
			       ciphertext_3.len, plaintext_3)) != 0) {
		ret = -EACCES;
		goto fail;
	}
	size_t pt3_len = ciphertext_3.len - EDHOC_TAG_LEN;
	if ((ret = edhoc_encode_id_cred(peer_pubkey, expected_id_cred)) != 0 ||
	    pt3_len < 13 + EDHOC_SIG_LEN ||
	    memcmp(plaintext_3, expected_id_cred, 11) != 0) {
		ret = -EACCES;
		goto fail;
	}
	ZCBOR_STATE_D(zsd_sig, 0, plaintext_3 + 11, pt3_len - 11, 2, 0);
	struct zcbor_string signature_3;
	if (!zcbor_bstr_decode(zsd_sig, &signature_3) || signature_3.len != EDHOC_SIG_LEN ||
	    !zcbor_payload_at_end(zsd_sig) || zsd_sig->constant_state->error) {
		goto fail;
	}
	memcpy(ctx->prk_4e3m, ctx->prk_3e2m, 32);
	edhoc_encode_credential(peer_pubkey, credential);
	memcpy(context, expected_id_cred, 11); context_len = 11;
	context[context_len++] = 0x58; context[context_len++] = 0x20;
	memcpy(context + context_len, ctx->th_3, 32); context_len += 32;
	memcpy(context + context_len, credential, 40); context_len += 40;
	if ((ret = edhoc_kdf_int(ctx->prk_4e3m, 6, context, context_len, mac_3, 32)) != 0 ||
	    (ret = build_sig_structure(expected_id_cred, 11, ctx->th_3, credential, 40,
				       mac_3, 32, sig_input, sizeof(sig_input), &sig_input_len)) != 0 ||
	    edhoc_verify(peer_pubkey, signature_3.value, sig_input, sig_input_len) != 0) {
		ret = -EACCES;
		goto fail;
	}
	if ((ret = edhoc_compute_transcript(ctx->th_3, plaintext_3, pt3_len,
					    credential, 40, ctx->th_4)) != 0) {
		goto fail;
	}
	ctx->state = EDHOC_STATE_COMPLETED;
	ret = 0;
	goto wipe;
fail:
	ctx->state = EDHOC_STATE_ERROR;
	crypto_wipe(ctx->prk_2e, sizeof(ctx->prk_2e));
	crypto_wipe(ctx->prk_3e2m, sizeof(ctx->prk_3e2m));
	crypto_wipe(ctx->prk_4e3m, sizeof(ctx->prk_4e3m));
	wipe:
	crypto_wipe(k_3, sizeof(k_3)); crypto_wipe(iv_3, sizeof(iv_3));
	crypto_wipe(plaintext_3, sizeof(plaintext_3)); crypto_wipe(mac_3, sizeof(mac_3));
	crypto_wipe(sig_input, sizeof(sig_input)); crypto_wipe(ctx->eph_sk, sizeof(ctx->eph_sk));
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

	/* RFC 9528 Sections 4.2.1 and Appendix A.1 use the same exporter chain
	 * on both roles. Table 14 assigns sender_id=C_I and recipient_id=C_R
	 * to the responder.
	 * PRK wipe sequence matches Python exactly; oscore wiped on error.
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

	memcpy(oscore->sender_id, ctx->c_i, ctx->c_i_len);
	oscore->sender_id_len = ctx->c_i_len;
	memcpy(oscore->recipient_id, ctx->c_r, ctx->c_r_len);
	oscore->recipient_id_len = ctx->c_r_len;

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

void edhoc_responder_wipe(struct edhoc_responder *ctx)
{
	if (ctx == NULL) {
		return;
	}
	crypto_wipe(ctx, sizeof(*ctx));
}
