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

	/*
	 * RFC 9528 Section 3.3.2: SUITES_I is either an integer (single suite)
	 * or an array where the first element is the selected suite.
	 * LICHEN only supports Suite 0.
	 */
	int32_t suites_i;
	if (zcbor_int32_decode(zsd, &suites_i)) {
		/* Single suite as integer */
		if (suites_i != EDHOC_SUITE_0) {
			LOG_WRN("Unsupported protocol parameters");
			return -ENOTSUP;
		}
	} else if (zcbor_list_start_decode(zsd)) {
		/* Array of suites - first element is the selected suite */
		if (!zcbor_int32_decode(zsd, &suites_i)) {
			return -EINVAL;
		}
		if (suites_i != EDHOC_SUITE_0) {
			LOG_WRN("Unsupported protocol parameters");
			return -ENOTSUP;
		}
		/* Skip remaining suite entries */
		int32_t dummy;
		while (zcbor_int32_decode(zsd, &dummy)) {
			/* Consume additional suites */
		}
		if (!zcbor_list_end_decode(zsd)) {
			return -EINVAL;
		}
	} else {
		return -EINVAL;
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
	/* SECURITY: wipe signing key immediately after last use */
	crypto_wipe(ctx->ed_seed, sizeof(ctx->ed_seed));

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
	ctx->state = EDHOC_STATE_ERROR;
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
	ctx->state = EDHOC_STATE_ERROR;
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
