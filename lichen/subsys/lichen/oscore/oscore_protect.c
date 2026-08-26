/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file oscore_protect.c
 * @brief OSCORE message protection and unprotection
 *
 * Implements request/response encryption and decryption per RFC 8613.
 */

#include <limits.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <lichen/oscore.h>
#include "oscore_internal.h"
#include "aes_ccm.h"
#include <monocypher.h>

LOG_MODULE_DECLARE(oscore, CONFIG_LICHEN_OSCORE_LOG_LEVEL);

/*
 * Find the payload marker (0xFF) in CoAP options, parsing option headers.
 * Returns offset of marker (or end of data if no marker), or (size_t)-1 on error.
 */
size_t find_coap_payload_marker(const uint8_t *data, size_t len)
{
	size_t pos = 0;
	while (pos < len) {
		uint8_t byte = data[pos];
		if (byte == 0xFF) {
			if (pos > (size_t)INT_MAX) {
				return (size_t)-1;
			}
			return pos;
		}
		uint8_t delta_nibble = (byte >> 4) & 0x0F;
		uint8_t len_nibble = byte & 0x0F;
		pos++;
		if (delta_nibble == 13) {
			if (pos >= len) return (size_t)-1;
			pos++;
		} else if (delta_nibble == 14) {
			if (pos + 1 >= len) return (size_t)-1;
			pos += 2;
		} else if (delta_nibble == 15) {
			return (size_t)-1;
		}
		size_t opt_len;
		if (len_nibble == 13) {
			if (pos >= len) return (size_t)-1;
			opt_len = data[pos] + 13;
			pos++;
		} else if (len_nibble == 14) {
			if (pos + 1 >= len) return (size_t)-1;
			opt_len = ((size_t)data[pos] << 8) + data[pos + 1] + 269;
			pos += 2;
		} else if (len_nibble == 15) {
			return (size_t)-1;
		} else {
			opt_len = len_nibble;
		}
		if (pos + opt_len > len) return (size_t)-1;
		pos += opt_len;
	}
	if (len > (size_t)INT_MAX) {
		return (size_t)-1;
	}
	return len;
}

int oscore_protect_request(struct oscore_ctx *ctx,
			   uint8_t code,
			   const uint8_t *options, size_t options_len,
			   const uint8_t *payload, size_t payload_len,
			   uint8_t *ciphertext, size_t *ciphertext_len,
			   uint8_t *oscore_opt, size_t *oscore_opt_len)
{
	uint8_t nonce[OSCORE_NONCE_LEN];
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len;
	uint8_t plaintext[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX];
	size_t pt_len;
	uint8_t aad[64];
	int aad_ret;
	size_t aad_len;
	size_t required_ct_len;
	struct oscore_option opt;
	int opt_len;
	int ret;
	int ctx_idx;
	uint64_t seq;

	if (ctx == NULL || ciphertext == NULL || ciphertext_len == NULL ||
	    oscore_opt == NULL || oscore_opt_len == NULL) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_protect_request;
	}

	if ((options_len > 0 && options == NULL) ||
	    (payload_len > 0 && payload == NULL)) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_protect_request;
	}

	/*
	 * Atomically check initialization, sequence exhaustion, and increment.
	 * Fixes python-ano.2 (race on sender_seq++) and python-ano.41 (nonce
	 * reuse on NVM failure+reboot). See full analysis in
	 * project-LICHEN-ow3c.1.3.2.1 and nvm_failed label.
	 */
	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	ctx_idx = ctx_get_index(ctx);
	if (ctx_idx < 0) {
		k_mutex_unlock(&s_ctx_mutex);
		LOG_ERR("OSCORE context not in storage array");
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_protect_request;
	}

	/* Require sender_seq to be explicitly initialized before first use */
	if (!s_seq_initialized[ctx_idx]) {
		k_mutex_unlock(&s_ctx_mutex);
		LOG_ERR("OSCORE sender_seq not initialized - call oscore_ctx_set_sender_seq()");
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_protect_request;
	}

	/* Check for sender sequence number exhaustion before use (40-bit limit per RFC 8613) */
	if (ctx->sender_seq >= OSCORE_SSN_MAX) {
		k_mutex_unlock(&s_ctx_mutex);
		LOG_ERR("OSCORE sender sequence exhausted - key rotation required");
		ret = OSCORE_ERR_SEQ_EXHAUSTED;
		goto cleanup_protect_request;
	}

	/* Get and increment sender sequence number atomically */
	seq = ctx->sender_seq++;

	k_mutex_unlock(&s_ctx_mutex);

	piv_len = encode_piv(seq, piv);

	/* Compute nonce */
	compute_nonce(ctx->sender_id, ctx->sender_id_len,
		      piv, piv_len, ctx->common_iv, nonce);

	/*
	 * SECURITY: Error handling below follows a two-class model.
	 *
	 * Class 1 - pre-transmission errors (options/payload/AAD/ciphertext
	 * buffer too small, AEAD encrypt failure, OSCORE option build
	 * failure): each sets ret to the specific error code and goes to
	 * common_wipe. The sender_seq increment above is consumed but the
	 * packet is never transmitted, which is safe: sequence gaps are
	 * harmless in RFC 8613, only nonce REUSE is catastrophic (Section 7.2).
	 * common_wipe destroys nonce, PIV, plaintext and seq so no key
	 * material or plaintext lingers on the stack.
	 *
	 * Class 2 - post-transmittable NVM failure (persist_ssn failing
	 * after ciphertext and OSCORE option are fully built and returned
	 * to the caller): goes to the distinct nvm_failed path, which takes
	 * extra measures (safety-margin SSN bump inside persist_ssn,
	 * s_seq_initialized sync) because the packet may still be sent.
	 */

	/*
	 * Build plaintext: code || options || payload
	 * Code is first byte, options follow, then 0xFF marker and payload.
	 */
	pt_len = 0;
	plaintext[pt_len++] = code;

	if (options_len > 0) {
		if (options_len > sizeof(plaintext) - pt_len) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto common_wipe;
		}
		memcpy(plaintext + pt_len, options, options_len);
		pt_len += options_len;
	}

	if (payload_len > 0) {
		if (payload_len > sizeof(plaintext) - pt_len - 1) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto common_wipe;
		}
		plaintext[pt_len++] = 0xFF; /* Payload marker */
		memcpy(plaintext + pt_len, payload, payload_len);
		pt_len += payload_len;
	}

	/* Build AAD per RFC 8613 Section 5.4 */
	aad_ret = build_oscore_aad(ctx->sender_id, ctx->sender_id_len,
				   piv, piv_len, aad, sizeof(aad));
	if (aad_ret < 0) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto common_wipe;
	}
	aad_len = (size_t)aad_ret;

	/* Check output buffer size */
	required_ct_len = pt_len + OSCORE_TAG_LEN;
	if (*ciphertext_len < required_ct_len) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto common_wipe;
	}

	/* Encrypt */
	if (lichen_aes_ccm_encrypt(ctx->sender_key, nonce,
			    aad, aad_len,
			    plaintext, pt_len,
			    ciphertext) != 0) {
		ret = OSCORE_ERR_ENCRYPT_FAILED;
		goto common_wipe;
	}
	*ciphertext_len = required_ct_len;

	/* Build OSCORE option */
	opt.has_piv = true;
	opt.piv_len = (uint8_t)(piv_len & 0x07);
	opt.has_kid = true;
	opt.kid_len = ctx->sender_id_len;
	memcpy(opt.piv, piv, piv_len);
	memcpy(opt.kid, ctx->sender_id, ctx->sender_id_len);
	opt.has_kid_context = false;
	opt.kid_context_len = 0;

	opt_len = oscore_option_build(&opt, oscore_opt, *oscore_opt_len);
	if (opt_len < 0) {
		ret = opt_len;
		goto common_wipe;
	}
	*oscore_opt_len = (size_t)opt_len;
	ret = oscore_ctx_persist_ssn(ctx);
	if (ret == OSCORE_ERR_NVM_FAILED) {
		ret = OSCORE_ERR_NVM_FAILED;
		goto nvm_failed;
	} else {
		ret = OSCORE_OK;
	}

common_wipe:
	/*
	 * SECURITY: Single convergence point for the success path and all
	 * Class 1 pre-transmission error paths (see two-class model above);
	 * nvm_failed also joins here after its extra SSN handling. ret was
	 * set by the originating path (specific error code, OSCORE_OK, or
	 * OSCORE_ERR_NVM_FAILED). Wipe nonce, PIV, plaintext and seq from
	 * the stack unconditionally so key material and unencrypted content
	 * cannot leak via stack reuse, regardless of which path got here.
	 */
	crypto_wipe(nonce, sizeof(nonce));
	crypto_wipe(piv, sizeof(piv));
	crypto_wipe(plaintext, sizeof(plaintext));
	crypto_wipe(&seq, sizeof(seq));
	return ret;

nvm_failed:
	/* Before common wipe in cleanup_protect_request, this dedicated
	 * nvm_failed path locks mutex to safely handle sender_seq.
	 * SECURITY: SSN MUST NOT be left incremented on NVM failure -
	 * would allow AES-CCM nonce reuse attack vector on reboot
	 * (RFC 8613 7.2, oscore.c:1524). Rollback to pre-increment value
	 * (conditional on no concurrent update) prevents reuse while
	 * preserving monotonicity. See project-LICHEN-ow3c.1.3.3.1,
	 * persist_ssn, and oscore.h for full rationale.
	 */
	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	ctx_idx = ctx_get_index(ctx);
	if (ctx_idx >= 0) {
		if (ctx->sender_seq == seq + 1) {
			ctx->sender_seq = seq;
		}
		s_seq_initialized[ctx_idx] = true;
	}
	k_mutex_unlock(&s_ctx_mutex);
	ret = OSCORE_ERR_NVM_FAILED;
	goto common_wipe;

cleanup_protect_request:
	return ret;
}

int oscore_unprotect_request(struct oscore_ctx *ctx,
			     const uint8_t *oscore_opt, size_t oscore_opt_len,
			     const uint8_t *ciphertext, size_t ciphertext_len,
			     uint8_t *code,
			     uint8_t *options, size_t *options_len,
			     uint8_t *payload, size_t *payload_len)
{
	struct oscore_option opt;
	uint8_t nonce[OSCORE_NONCE_LEN];
	uint8_t plaintext[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX];
	int ret;
	uint32_t seq;
	int ctx_idx;
	bool replay_reserved = false;

	if (ctx == NULL || ciphertext == NULL || code == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	if (ciphertext_len < OSCORE_TAG_LEN + 1) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Parse OSCORE option */
	ret = oscore_option_parse(oscore_opt, oscore_opt_len, &opt);
	if (ret != OSCORE_OK) {
		return ret;
	}

	/* Need PIV for request */
	if (!opt.has_piv) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	seq = decode_piv(opt.piv, opt.piv_len);

	/*
	 * Reserve the sequence while decrypting without advancing the committed
	 * replay window. This keeps failed authentication from poisoning replay
	 * state while ensuring a concurrent copy of the same sequence is rejected.
	 */
	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	ctx_idx = ctx_get_index(ctx);
	if (ctx_idx < 0) {
		k_mutex_unlock(&s_ctx_mutex);
		LOG_ERR("OSCORE context not in storage array");
		return OSCORE_ERR_INVALID_PARAM;
	}

	ret = replay_reserve_pending_locked(ctx, ctx_idx, seq);
	if (ret != OSCORE_OK) {
		k_mutex_unlock(&s_ctx_mutex);
		if (ret == OSCORE_ERR_REPLAY) {
			LOG_WRN("OSCORE replay detected: seq=%u", seq);
		} else {
			LOG_ERR("OSCORE replay reservation unavailable: seq=%u", seq);
		}
		return ret;
	}
	replay_reserved = true;

	k_mutex_unlock(&s_ctx_mutex);

	/* Compute nonce using sender's ID from option (which is our recipient) */
	compute_nonce(ctx->recipient_id, ctx->recipient_id_len,
		      opt.piv, opt.piv_len, ctx->common_iv, nonce);

	/* Build AAD per RFC 8613 Section 5.4 */
	uint8_t aad[64];
	int aad_ret = build_oscore_aad(ctx->recipient_id, ctx->recipient_id_len,
				       opt.piv, opt.piv_len, aad, sizeof(aad));
	if (aad_ret < 0) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_unprotect_request;
	}
	size_t aad_len = (size_t)aad_ret;

	/* Decrypt */
	size_t pt_len = ciphertext_len - OSCORE_TAG_LEN;
	if (pt_len > sizeof(plaintext)) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_unprotect_request;
	}

	if (lichen_aes_ccm_decrypt(ctx->recipient_key, nonce,
			    aad, aad_len,
			    ciphertext, ciphertext_len,
			    plaintext) != 0) {
		ret = OSCORE_ERR_DECRYPT_FAILED;
		goto cleanup_unprotect_request;
	}

	/*
	 * Decryption succeeded - now update replay window on the real context.
	 * This fixes python-ano.4 (window updated before decrypt) and
	 * python-ano.56 (updates lost because operating on copy).
	 */
	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	replay_clear_pending_locked(ctx_idx, seq);
	replay_reserved = false;
	if (!replay_update_window(ctx, seq)) {
		k_mutex_unlock(&s_ctx_mutex);
		LOG_WRN("OSCORE replay detected after decrypt: seq=%u", seq);
		ret = OSCORE_ERR_REPLAY;
		goto cleanup_unprotect_request;
	}
	k_mutex_unlock(&s_ctx_mutex);

	if (pt_len < 1) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_request;
	}
	*code = plaintext[0];
	size_t marker_result = find_coap_payload_marker(plaintext + 1, pt_len - 1);
	if (marker_result == (size_t)-1) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_request;
	}
	size_t marker_pos = 1 + marker_result;

	/* Copy options */
	size_t opt_out_len = marker_pos - 1;
	if (options == NULL) {
		if (options_len != NULL) {
			*options_len = 0;
		}
	} else if (options_len != NULL) {
		if (*options_len < opt_out_len) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup_unprotect_request;
		}
		memcpy(options, plaintext + 1, opt_out_len);
		*options_len = opt_out_len;
	}

	/* Copy payload */
	if (marker_pos < pt_len && plaintext[marker_pos] == 0xFF) {
		size_t pay_len = pt_len - marker_pos - 1;
		if (payload != NULL && payload_len != NULL) {
			if (*payload_len < pay_len) {
				ret = OSCORE_ERR_BUFFER_TOO_SMALL;
				goto cleanup_unprotect_request;
			}
			memcpy(payload, plaintext + marker_pos + 1, pay_len);
			*payload_len = pay_len;
		}
	} else if (payload_len != NULL) {
		*payload_len = 0;
	}

	ret = OSCORE_OK;

cleanup_unprotect_request:
	if (replay_reserved) {
		k_mutex_lock(&s_ctx_mutex, K_FOREVER);
		replay_clear_pending_locked(ctx_idx, seq);
		k_mutex_unlock(&s_ctx_mutex);
	}
	crypto_wipe(nonce, sizeof(nonce));
	crypto_wipe(plaintext, sizeof(plaintext));
	return ret;
}

int oscore_protect_response(struct oscore_ctx *ctx,
			    const uint8_t *request_piv, size_t request_piv_len,
			    uint8_t code,
			    const uint8_t *options, size_t options_len,
			    const uint8_t *payload, size_t payload_len,
			    uint8_t *ciphertext, size_t *ciphertext_len,
			    uint8_t *oscore_opt, size_t *oscore_opt_len)
{
	uint8_t nonce[OSCORE_NONCE_LEN];
	uint8_t plaintext[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX];
	size_t pt_len;
	int ret;

	if (ctx == NULL || ciphertext == NULL || ciphertext_len == NULL ||
	    oscore_opt == NULL || oscore_opt_len == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	if ((request_piv_len > 0 && request_piv == NULL) ||
	    request_piv_len > OSCORE_PIV_MAX_LEN ||
	    (options_len > 0 && options == NULL) ||
	    (payload_len > 0 && payload == NULL)) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Response nonce: use sender_id (response sender) + request_piv for RFC 8613
	 * Section 5.2 nonce + 5.4 AAD request_kid binding (checkpoint fix).
	 */
	compute_nonce(ctx->sender_id, ctx->sender_id_len,
		      request_piv, request_piv_len, ctx->common_iv, nonce);

	/* Build plaintext: code || options || payload */
	pt_len = 0;
	plaintext[pt_len++] = code;

	if (options_len > 0) {
		if (options_len > sizeof(plaintext) - pt_len) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup_protect_response;
		}
		memcpy(plaintext + pt_len, options, options_len);
		pt_len += options_len;
	}

	if (payload_len > 0) {
		if (payload_len > sizeof(plaintext) - pt_len - 1) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup_protect_response;
		}
		plaintext[pt_len++] = 0xFF;
		memcpy(plaintext + pt_len, payload, payload_len);
		pt_len += payload_len;
	}

	/* Build AAD per RFC 8613 Section 5.4 - use request KID/PIV for response */
	uint8_t aad[64];
	int aad_ret = build_oscore_aad(ctx->recipient_id, ctx->recipient_id_len,
				       request_piv, request_piv_len,
				       aad, sizeof(aad));
	if (aad_ret < 0) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_protect_response;
	}
	size_t aad_len = (size_t)aad_ret;

	/* Check output buffer size */
	size_t required_ct_len = pt_len + OSCORE_TAG_LEN;
	if (*ciphertext_len < required_ct_len) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_protect_response;
	}

	/* Encrypt with sender key */
	if (lichen_aes_ccm_encrypt(ctx->sender_key, nonce,
			    aad, aad_len,
			    plaintext, pt_len,
			    ciphertext) != 0) {
		ret = OSCORE_ERR_ENCRYPT_FAILED;
		goto cleanup_protect_response;
	}
	*ciphertext_len = required_ct_len;

	/* Response OSCORE option: no PIV, no KID (echo) */
	struct oscore_option opt = {0};
	int opt_out_len = oscore_option_build(&opt, oscore_opt, *oscore_opt_len);
	if (opt_out_len < 0) {
		ret = opt_out_len;
		goto cleanup_protect_response;
	}
	*oscore_opt_len = (size_t)opt_out_len;

	ret = OSCORE_OK;

cleanup_protect_response:
	crypto_wipe(nonce, sizeof(nonce));
	crypto_wipe(plaintext, sizeof(plaintext));
	return ret;
}

int oscore_unprotect_response(struct oscore_ctx *ctx,
			      const uint8_t *request_piv, size_t request_piv_len,
			      const uint8_t *oscore_opt, size_t oscore_opt_len,
			      const uint8_t *ciphertext, size_t ciphertext_len,
			      uint8_t *code,
			      uint8_t *options, size_t *options_len,
			      uint8_t *payload, size_t *payload_len)
{
	struct oscore_option resp_opt;
	uint8_t nonce[OSCORE_NONCE_LEN];
	uint8_t plaintext[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX];
	int ret;
	const uint8_t *nonce_piv;
	size_t nonce_piv_len;

	if (ctx == NULL || ciphertext == NULL || code == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	if (ciphertext_len < OSCORE_TAG_LEN + 1) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* SECURITY: Validate request_piv pointer when len > 0 to prevent NULL dereference */
	if (request_piv_len > OSCORE_PIV_MAX_LEN ||
	    (request_piv_len > 0 && request_piv == NULL)) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/*
	 * RFC 8613 Section 8.4: OSCORE responses MAY include a Partial IV
	 * in the OSCORE option. When present, use response PIV for nonce.
	 */
	nonce_piv = request_piv;
	nonce_piv_len = request_piv_len;

	if (oscore_opt_len > 0) {
		ret = oscore_option_parse(oscore_opt, oscore_opt_len, &resp_opt);
		if (ret != OSCORE_OK) {
			return ret;
		}
		if (resp_opt.has_piv && resp_opt.piv_len > 0) {
			nonce_piv = resp_opt.piv;
			nonce_piv_len = resp_opt.piv_len;
		}
	}

	/* Response nonce: use recipient_id (response sender's ID) + PIV (response or
	 * request) per RFC 8613 5.2/8.4 for correct binding (checkpoint fix).
	 */
	compute_nonce(ctx->recipient_id, ctx->recipient_id_len,
		      nonce_piv, nonce_piv_len, ctx->common_iv, nonce);

	/* Build AAD per RFC 8613 Section 5.4 - use request KID/PIV */
	uint8_t aad[64];
	int aad_ret = build_oscore_aad(ctx->sender_id, ctx->sender_id_len,
				       request_piv, request_piv_len,
				       aad, sizeof(aad));
	if (aad_ret < 0) {
		crypto_wipe(nonce, sizeof(nonce));
		return OSCORE_ERR_BUFFER_TOO_SMALL;
	}
	size_t aad_len = (size_t)aad_ret;

	/* Decrypt with recipient key */
	size_t pt_len = ciphertext_len - OSCORE_TAG_LEN;
	if (pt_len > sizeof(plaintext)) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_unprotect_response;
	}

	if (lichen_aes_ccm_decrypt(ctx->recipient_key, nonce,
			    aad, aad_len,
			    ciphertext, ciphertext_len,
			    plaintext) != 0) {
		ret = OSCORE_ERR_DECRYPT_FAILED;
		goto cleanup_unprotect_response;
	}

	if (pt_len < 1) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_response;
	}
	*code = plaintext[0];
	size_t marker_result = find_coap_payload_marker(plaintext + 1, pt_len - 1);
	if (marker_result == (size_t)-1) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_response;
	}
	size_t marker_pos = 1 + marker_result;

	/* Copy options */
	size_t opt_out_len = marker_pos - 1;
	if (options == NULL) {
		if (options_len != NULL) {
			*options_len = 0;
		}
	} else if (options_len != NULL) {
		if (*options_len < opt_out_len) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup_unprotect_response;
		}
		memcpy(options, plaintext + 1, opt_out_len);
		*options_len = opt_out_len;
	}

	/* Copy payload */
	if (marker_pos < pt_len && plaintext[marker_pos] == 0xFF) {
		size_t pay_len = pt_len - marker_pos - 1;
		if (payload != NULL && payload_len != NULL) {
			if (*payload_len < pay_len) {
				ret = OSCORE_ERR_BUFFER_TOO_SMALL;
				goto cleanup_unprotect_response;
			}
			memcpy(payload, plaintext + marker_pos + 1, pay_len);
			*payload_len = pay_len;
		}
	} else if (payload_len != NULL) {
		*payload_len = 0;
	}

	ret = OSCORE_OK;

cleanup_unprotect_response:
	crypto_wipe(nonce, sizeof(nonce));
	crypto_wipe(plaintext, sizeof(plaintext));
	return ret;
}
