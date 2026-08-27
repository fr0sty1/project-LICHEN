/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file oscore_protect.c
 * @brief OSCORE message protection and unprotection
 *
 * Implements request/response encryption and decryption per RFC 8613.
 */

#include <limits.h>
#include <inttypes.h>
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

static bool response_replay_acceptable(bool initialized, uint64_t latest,
				       uint32_t window, uint64_t seq)
{
	if (!initialized || seq > latest) {
		return true;
	}

	uint64_t diff = latest - seq;
	return diff < CONFIG_LICHEN_OSCORE_REPLAY_WINDOW &&
	       (window & (1U << diff)) == 0;
}

static void response_replay_update(bool *initialized, uint64_t *latest,
				   uint32_t *window, uint64_t seq)
{
	if (!*initialized) {
		*latest = seq;
		*window = 1;
		*initialized = true;
	} else if (seq > *latest) {
		uint64_t shift = seq - *latest;
		/*
		 * The shift is computed in uint64_t because the promotion of
		 * a uint32_t lvalue is ABI-dependent: on ILP32 targets
		 * (uint32_t == unsigned int, as on every Zephyr target here)
		 * (*window << shift) was already defined wrapping arithmetic,
		 * while on an ABI whose int is wider than 32 bits the
		 * promoted type is signed int and a shift count >= 32 would
		 * be UB. The uint64_t intermediate is defined wrapping on
		 * every ABI and produces identical bit patterns.
		 */
		*window = shift >= 32 ?
			  1U : (uint32_t)(((uint64_t)*window << shift) | 1U);
		*latest = seq;
	} else {
		uint64_t diff = *latest - seq;
		*window |= diff >= 32 ? 0U : (uint32_t)((uint64_t)1 << diff);
	}
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
	uint8_t plaintext[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX];
	uint8_t aad[64];
	uint8_t option_tmp[1 + OSCORE_PIV_MAX_LEN + 1 +
			   OSCORE_ID_CONTEXT_MAX_LEN + OSCORE_ID_MAX_LEN];
	uint8_t sender_key[OSCORE_KEY_LEN];
	uint8_t common_iv[OSCORE_NONCE_LEN];
	uint8_t sender_id[OSCORE_ID_MAX_LEN];
	uint8_t id_context[OSCORE_ID_CONTEXT_MAX_LEN];
	uint8_t eui64_copy[OSCORE_EUI64_LEN];
	struct oscore_option opt = {0};
	size_t sender_id_len = 0;
	size_t id_context_len = 0;
	size_t piv_len = 0;
	size_t pt_len = 0;
	size_t aad_len = 0;
	size_t required_ct_len;
	size_t ciphertext_capacity;
	size_t option_capacity;
	size_t option_len = 0;
	int ctx_idx = -1;
	int ret = OSCORE_ERR_INVALID_PARAM;
	uint64_t seq = 0;
	bool mutex_locked = false;
	bool reservation_rollback_allowed = false;
	bool had_peer_eui64 = false;

	if (ctx == NULL || ciphertext == NULL || ciphertext_len == NULL ||
	    oscore_opt == NULL || oscore_opt_len == NULL) {
		goto cleanup;
	}
	ciphertext_capacity = *ciphertext_len;
	option_capacity = *oscore_opt_len;

	if ((options_len > 0 && options == NULL) ||
	    (payload_len > 0 && payload == NULL)) {
		goto cleanup;
	}
	if (options_len > sizeof(plaintext) - 1) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup;
	}
	pt_len = 1 + options_len;
	if (payload_len > 0) {
		if (pt_len == sizeof(plaintext) ||
		    payload_len > sizeof(plaintext) - pt_len - 1) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		pt_len += 1 + payload_len;
	}
	required_ct_len = pt_len + OSCORE_TAG_LEN;
	if (ciphertext_capacity < required_ct_len) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup;
	}

	/*
	 * Reserve exactly one sequence and snapshot all cryptographic/context
	 * material under the same lock. The reservation is rolled back on every
	 * failure before durable persistence, provided no concurrent reservation
	 * has advanced the context in the meantime.
	 */
	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	mutex_locked = true;

	ctx_idx = ctx_get_index(ctx);
	if (ctx_idx < 0 || !ctx->active) {
		LOG_ERR("OSCORE context not in storage array");
		ret = OSCORE_ERR_NO_CONTEXT;
		goto cleanup;
	}

	if (!s_seq_initialized[ctx_idx]) {
		LOG_ERR("OSCORE sender_seq not initialized - call oscore_ctx_set_sender_seq()");
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup;
	}
	/* OSCORE_SSN_MAX is the terminal usable five-byte Partial IV. */
	if (ctx->sender_seq > OSCORE_SSN_MAX) {
		LOG_ERR("OSCORE sender sequence exhausted - key rotation required");
		ret = OSCORE_ERR_SEQ_EXHAUSTED;
		goto cleanup;
	}
	if (ctx->sender_id_len > 7 || ctx->id_context_len > OSCORE_ID_CONTEXT_MAX_LEN) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup;
	}

	sender_id_len = ctx->sender_id_len;
	id_context_len = ctx->id_context_len;
	memcpy(sender_id, ctx->sender_id, sender_id_len);
	memcpy(id_context, ctx->id_context, id_context_len);
	memcpy(sender_key, ctx->sender_key, sizeof(sender_key));
	memcpy(common_iv, ctx->common_iv, sizeof(common_iv));
	if (ctx->has_peer_eui64) {
		memcpy(eui64_copy, ctx->peer_eui64, sizeof(eui64_copy));
		had_peer_eui64 = true;
	}

	seq = ctx->sender_seq++;
	reservation_rollback_allowed = true;
	k_mutex_unlock(&s_ctx_mutex);
	mutex_locked = false;

	piv_len = encode_piv(seq, piv);
	plaintext[0] = code;
	if (options_len > 0) {
		memcpy(plaintext + 1, options, options_len);
	}
	if (payload_len > 0) {
		size_t marker_pos = 1 + options_len;
		plaintext[marker_pos] = 0xFF;
		memcpy(plaintext + marker_pos + 1, payload, payload_len);
	}

	compute_nonce(sender_id, sender_id_len, piv, piv_len, common_iv, nonce);
	int aad_ret = build_oscore_aad(sender_id, sender_id_len,
				   piv, piv_len, aad, sizeof(aad));
	if (aad_ret < 0) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup;
	}
	aad_len = (size_t)aad_ret;

	opt.has_piv = true;
	opt.piv_len = (uint8_t)piv_len;
	opt.has_kid = true;
	opt.kid_len = (uint8_t)sender_id_len;
	memcpy(opt.piv, piv, piv_len);
	memcpy(opt.kid, sender_id, sender_id_len);
	opt.has_kid_context = id_context_len > 0;
	opt.kid_context_len = (uint8_t)id_context_len;
	memcpy(opt.kid_context, id_context, id_context_len);

	int option_ret = oscore_option_build(&opt, option_tmp, sizeof(option_tmp));
	if (option_ret < 0) {
		ret = option_ret;
		goto cleanup;
	}
	option_len = (size_t)option_ret;
	if (option_capacity < option_len) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup;
	}

	/*
	 * Persist a margin-skipped durable SSN before creating publishable
	 * bytes: oscore_ctx_persist_ssn() stores sender_seq plus
	 * OSCORE_SSN_SAFETY_MARGIN and, only after a successful write,
	 * advances the in-RAM sender_seq by the same skip. A reboot that
	 * reloads from NVM therefore resumes strictly above every sequence
	 * this boot could have transmitted (RFC 8613 Section 7.2 / Appendix
	 * D.4), and the skipped range is never used as a nonce.
	 */
	ret = oscore_ctx_persist_ssn(ctx);
	if (ret != OSCORE_OK) {
		goto cleanup;
	}
	reservation_rollback_allowed = false;

	/*
	 * The persistence callback runs unlocked. Revalidate the exact context
	 * slot before encryption, then keep it locked through publication so a
	 * concurrent free/recreate cannot swap keys or identities underneath us.
	 */
	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	mutex_locked = true;
	ctx_idx = ctx_get_index(ctx);
	if (ctx_idx < 0 || !ctx->active ||
	    ctx->sender_id_len != sender_id_len ||
	    ctx->id_context_len != id_context_len ||
	    memcmp(ctx->sender_id, sender_id, sender_id_len) != 0 ||
	    memcmp(ctx->id_context, id_context, id_context_len) != 0 ||
	    memcmp(ctx->sender_key, sender_key, sizeof(sender_key)) != 0 ||
	    memcmp(ctx->common_iv, common_iv, sizeof(common_iv)) != 0 ||
	    ctx->has_peer_eui64 != had_peer_eui64 ||
	    (had_peer_eui64 &&
	     memcmp(ctx->peer_eui64, eui64_copy, sizeof(eui64_copy)) != 0)) {
		ret = OSCORE_ERR_NO_CONTEXT;
		goto cleanup;
	}

	/* All deterministic failures have completed; only now touch outputs. */
	if (lichen_aes_ccm_encrypt(sender_key, nonce, aad, aad_len,
				   plaintext, pt_len, ciphertext) != 0) {
		ret = OSCORE_ERR_ENCRYPT_FAILED;
		goto cleanup;
	}
	memcpy(oscore_opt, option_tmp, option_len);
	*ciphertext_len = required_ct_len;
	*oscore_opt_len = option_len;
	ret = OSCORE_OK;

cleanup:
	if (mutex_locked) {
		k_mutex_unlock(&s_ctx_mutex);
	}
	if (reservation_rollback_allowed) {
		k_mutex_lock(&s_ctx_mutex, K_FOREVER);
		ctx_idx = ctx_get_index(ctx);
		if (ctx_idx >= 0 && ctx->active && ctx->sender_seq == seq + 1 &&
		    ctx->sender_id_len == sender_id_len &&
		    ctx->id_context_len == id_context_len &&
		    memcmp(ctx->sender_id, sender_id, sender_id_len) == 0 &&
		    memcmp(ctx->id_context, id_context, id_context_len) == 0 &&
		    memcmp(ctx->sender_key, sender_key, sizeof(sender_key)) == 0 &&
		    ctx->has_peer_eui64 == had_peer_eui64 &&
		    (!had_peer_eui64 ||
		     memcmp(ctx->peer_eui64, eui64_copy, sizeof(eui64_copy)) == 0)) {
			ctx->sender_seq = seq;
		}
		k_mutex_unlock(&s_ctx_mutex);
	}
	crypto_wipe(nonce, sizeof(nonce));
	crypto_wipe(piv, sizeof(piv));
	crypto_wipe(plaintext, sizeof(plaintext));
	crypto_wipe(aad, sizeof(aad));
	crypto_wipe(option_tmp, sizeof(option_tmp));
	crypto_wipe(sender_key, sizeof(sender_key));
	crypto_wipe(common_iv, sizeof(common_iv));
	crypto_wipe(sender_id, sizeof(sender_id));
	crypto_wipe(id_context, sizeof(id_context));
	crypto_wipe(eui64_copy, sizeof(eui64_copy));
	crypto_wipe(&opt, sizeof(opt));
	crypto_wipe(&seq, sizeof(seq));
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
	uint8_t aad[64];
	uint8_t plaintext[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX];
	int ret = OSCORE_ERR_INVALID_PARAM;
	uint64_t seq;
	int ctx_idx = -1;
	bool replay_reserved = false;
	bool mutex_locked = false;
	size_t pt_len;
	size_t marker_result;
	size_t marker_pos;
	size_t opt_out_len;
	size_t pay_len = 0;
	size_t options_capacity;
	size_t payload_capacity;
	uint8_t decoded_code;

	if (ctx == NULL || oscore_opt == NULL || ciphertext == NULL || code == NULL ||
	    options_len == NULL || payload_len == NULL) {
		goto cleanup_unprotect_request;
	}
	options_capacity = *options_len;
	payload_capacity = *payload_len;

	if (ciphertext_len < OSCORE_TAG_LEN + 1) {
		goto cleanup_unprotect_request;
	}

	/* Parse OSCORE option */
	ret = oscore_option_parse(oscore_opt, oscore_opt_len, &opt);
	if (ret != OSCORE_OK) {
		goto cleanup_unprotect_request;
	}

	/* Requests carry a canonical one-to-five-byte Partial IV. */
	if (!opt.has_piv || opt.piv_len == 0 ||
	    (opt.piv_len > 1 && opt.piv[0] == 0)) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_request;
	}

	seq = decode_piv(opt.piv, opt.piv_len);
	if (seq > OSCORE_SSN_MAX) {
		ret = OSCORE_ERR_SEQ_EXHAUSTED;
		goto cleanup_unprotect_request;
	}

	/*
	 * Keep the context locked from identity binding through authentication,
	 * plaintext validation, and replay commit.  This prevents a free/recreate
	 * of the same slot from changing keys or replay state underneath the
	 * operation.  The pending reservation is still explicit so every failure
	 * path can roll back without advancing the committed window.
	 */
	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	mutex_locked = true;

	ctx_idx = ctx_get_index(ctx);
	if (ctx_idx < 0 || !ctx->active) {
		LOG_ERR("OSCORE context not in storage array");
		ret = OSCORE_ERR_NO_CONTEXT;
		goto cleanup_unprotect_request;
	}

	/* Any identifiers carried by the request must select this exact context. */
	if (!opt.has_kid || opt.kid_len != ctx->recipient_id_len ||
	    memcmp(opt.kid, ctx->recipient_id, opt.kid_len) != 0 ||
	    (opt.has_kid_context &&
	     (opt.kid_context_len != ctx->id_context_len ||
	      memcmp(opt.kid_context, ctx->id_context,
		     opt.kid_context_len) != 0))) {
		ret = OSCORE_ERR_NO_CONTEXT;
		goto cleanup_unprotect_request;
	}

	ret = replay_reserve_pending_locked(ctx, ctx_idx, seq);
	if (ret != OSCORE_OK) {
		if (ret == OSCORE_ERR_REPLAY) {
			LOG_WRN("OSCORE replay detected: seq=%" PRIu64, seq);
		} else {
			LOG_ERR("OSCORE replay reservation unavailable: seq=%" PRIu64,
				seq);
		}
		goto cleanup_unprotect_request;
	}
	replay_reserved = true;

	/* Compute nonce using sender's ID from option (which is our recipient) */
	compute_nonce(ctx->recipient_id, ctx->recipient_id_len,
		      opt.piv, opt.piv_len, ctx->common_iv, nonce);

	/* Build AAD per RFC 8613 Section 5.4 */
	int aad_ret = build_oscore_aad(ctx->recipient_id, ctx->recipient_id_len,
				       opt.piv, opt.piv_len, aad, sizeof(aad));
	if (aad_ret < 0) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_unprotect_request;
	}
	size_t aad_len = (size_t)aad_ret;

	/* Decrypt */
	pt_len = ciphertext_len - OSCORE_TAG_LEN;
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

	decoded_code = plaintext[0];
	/* A protected request contains a real CoAP method code (class 0). */
	if (decoded_code == 0 || (decoded_code & 0xE0) != 0) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_request;
	}

	marker_result = find_coap_payload_marker(plaintext + 1, pt_len - 1);
	if (marker_result == (size_t)-1) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_request;
	}
	marker_pos = 1 + marker_result;
	opt_out_len = marker_pos - 1;
	if (marker_pos < pt_len) {
		/* A payload marker without at least one payload byte is malformed. */
		if (plaintext[marker_pos] != 0xFF || marker_pos + 1 >= pt_len) {
			ret = OSCORE_ERR_INVALID_PARAM;
			goto cleanup_unprotect_request;
		}
		pay_len = pt_len - marker_pos - 1;
	}

	/*
	 * Validate all caller-visible outputs before replay commit or any copy.
	 * A NULL buffer where content exists is a caller-contract violation
	 * (OSCORE_ERR_INVALID_PARAM, matching the response siblings); an
	 * insufficient capacity is OSCORE_ERR_BUFFER_TOO_SMALL.
	 */
	if ((opt_out_len > 0 && options == NULL) ||
	    (pay_len > 0 && payload == NULL)) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_request;
	}
	if (options_capacity < opt_out_len || payload_capacity < pay_len) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_unprotect_request;
	}

	/* Commit exactly once, only after authentication and full validation. */
	replay_clear_pending_locked(ctx_idx, seq);
	replay_reserved = false;
	if (!replay_update_window(ctx, seq)) {
		LOG_WRN("OSCORE replay detected after decrypt: seq=%" PRIu64, seq);
		ret = OSCORE_ERR_REPLAY;
		goto cleanup_unprotect_request;
	}

	*code = decoded_code;
	if (opt_out_len > 0) {
		memcpy(options, plaintext + 1, opt_out_len);
	}
	if (pay_len > 0) {
		memcpy(payload, plaintext + marker_pos + 1, pay_len);
	}
	*options_len = opt_out_len;
	*payload_len = pay_len;
	ret = OSCORE_OK;

cleanup_unprotect_request:
	if (replay_reserved) {
		replay_clear_pending_locked(ctx_idx, seq);
	}
	if (mutex_locked) {
		k_mutex_unlock(&s_ctx_mutex);
	}
	crypto_wipe(nonce, sizeof(nonce));
	crypto_wipe(aad, sizeof(aad));
	crypto_wipe(plaintext, sizeof(plaintext));
	crypto_wipe(&opt, sizeof(opt));
	return ret;
}

static int protect_response(struct oscore_ctx *ctx,
			    const uint8_t *request_piv, size_t request_piv_len,
			    uint8_t code,
			    const uint8_t *options, size_t options_len,
			    const uint8_t *payload, size_t payload_len,
			    bool include_piv,
			    uint8_t *ciphertext, size_t *ciphertext_len,
			    uint8_t *oscore_opt, size_t *oscore_opt_len)
{
	uint8_t nonce[OSCORE_NONCE_LEN];
	uint8_t plaintext[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX];
	uint8_t option_tmp[1 + OSCORE_PIV_MAX_LEN];
	uint8_t sender_key[OSCORE_KEY_LEN];
	uint8_t common_iv[OSCORE_NONCE_LEN];
	uint8_t sender_id[OSCORE_ID_MAX_LEN];
	uint8_t recipient_id[OSCORE_ID_MAX_LEN];
	uint8_t eui64_copy[OSCORE_EUI64_LEN];
	uint8_t piv[OSCORE_PIV_MAX_LEN] = {0};
	size_t sender_id_len;
	size_t recipient_id_len;
	size_t piv_len = 0;
	size_t option_len = 0;
	size_t pt_len = 0;
	size_t required_ct_len;
	size_t ciphertext_capacity;
	size_t option_capacity;
	uint64_t request_seq;
	uint64_t seq = 0;
	int ctx_idx;
	int ret = OSCORE_ERR_INVALID_PARAM;
	bool mutex_locked = false;
	bool fresh_reserved = false;
	bool had_peer_eui64 = false;

	if (ctx == NULL || ciphertext == NULL || ciphertext_len == NULL ||
	    oscore_opt == NULL || oscore_opt_len == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	if (request_piv_len == 0 || request_piv == NULL ||
	    request_piv_len > OSCORE_PIV_MAX_LEN ||
	    (options_len > 0 && options == NULL) ||
	    (payload_len > 0 && payload == NULL) ||
	    (code >> 5) < 2 || (code >> 5) > 5) {
		return OSCORE_ERR_INVALID_PARAM;
	}
	ciphertext_capacity = *ciphertext_len;
	option_capacity = *oscore_opt_len;

	/* Build plaintext: code || options || payload */
	plaintext[pt_len++] = code;

	if (options_len > 0) {
		if (options_len > sizeof(plaintext) - pt_len) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		memcpy(plaintext + pt_len, options, options_len);
		pt_len += options_len;
	}

	if (payload_len > 0) {
		if (payload_len > sizeof(plaintext) - pt_len - 1) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		plaintext[pt_len++] = 0xFF;
		memcpy(plaintext + pt_len, payload, payload_len);
		pt_len += payload_len;
	}
	required_ct_len = pt_len + OSCORE_TAG_LEN;
	option_len = include_piv ? 2 : 0; /* Sequence zero is the minimum fresh option. */
	if (ciphertext_capacity < required_ct_len || option_capacity < option_len) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup;
	}

	request_seq = decode_piv(request_piv, request_piv_len);
	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	mutex_locked = true;
	ctx_idx = ctx_get_index(ctx);
	if (ctx_idx < 0 || !ctx->active) {
		ret = OSCORE_ERR_NO_CONTEXT;
		goto cleanup;
	}

	/* Snapshot all key/context material before releasing the context lock. */
	sender_id_len = ctx->sender_id_len;
	recipient_id_len = ctx->recipient_id_len;
	memcpy(sender_id, ctx->sender_id, sender_id_len);
	memcpy(recipient_id, ctx->recipient_id, recipient_id_len);
	memcpy(sender_key, ctx->sender_key, sizeof(sender_key));
	memcpy(common_iv, ctx->common_iv, sizeof(common_iv));
	if (ctx->has_peer_eui64) {
		memcpy(eui64_copy, ctx->peer_eui64, sizeof(eui64_copy));
		had_peer_eui64 = true;
	}

	if (include_piv) {
		if (!s_seq_initialized[ctx_idx]) {
			ret = OSCORE_ERR_INVALID_PARAM;
			goto cleanup;
		}
		if (ctx->sender_seq > OSCORE_SSN_MAX) {
			ret = OSCORE_ERR_SEQ_EXHAUSTED;
			goto cleanup;
		}
		seq = ctx->sender_seq++;
		fresh_reserved = true;
		piv_len = encode_piv(seq, piv);
		option_len = 1 + piv_len;
		if (option_capacity < option_len) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		k_mutex_unlock(&s_ctx_mutex);
		mutex_locked = false;
	} else {
		if (!response_replay_acceptable(ctx->sent_response_window_initialized,
						ctx->sent_response_seq,
						ctx->sent_response_window,
						request_seq)) {
			ret = OSCORE_ERR_REPLAY;
			goto cleanup;
		}
	}

	/* RFC 8613 Sections 5.2, 8.3, and 8.4 nonce selection. */
	if (include_piv) {
		compute_nonce(sender_id, sender_id_len, piv, piv_len, common_iv, nonce);
	} else {
		compute_nonce(recipient_id, recipient_id_len,
			      request_piv, request_piv_len, common_iv, nonce);
	}

	/* Build AAD per RFC 8613 Section 5.4 - use request KID/PIV for response */
	uint8_t aad[64];
	int aad_ret = build_oscore_aad(recipient_id, recipient_id_len,
				       request_piv, request_piv_len,
				       aad, sizeof(aad));
	if (aad_ret < 0) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup;
	}
	size_t aad_len = (size_t)aad_ret;

	if (include_piv) {
		option_tmp[0] = (uint8_t)piv_len;
		memcpy(option_tmp + 1, piv, piv_len);

		/* Fresh response PIVs consume/persist the shared sender sequence. */
		ret = oscore_ctx_persist_ssn(ctx);
		if (ret != OSCORE_OK) {
			goto cleanup;
		}

		/* Reject a freed or recycled slot before publishing ciphertext. */
		k_mutex_lock(&s_ctx_mutex, K_FOREVER);
		mutex_locked = true;
		ctx_idx = ctx_get_index(ctx);
		if (ctx_idx < 0 || !ctx->active ||
		    ctx->sender_id_len != sender_id_len ||
		    ctx->recipient_id_len != recipient_id_len ||
		    memcmp(ctx->sender_id, sender_id, sender_id_len) != 0 ||
		    memcmp(ctx->recipient_id, recipient_id, recipient_id_len) != 0 ||
		    memcmp(ctx->sender_key, sender_key, sizeof(sender_key)) != 0 ||
		    ctx->has_peer_eui64 != had_peer_eui64 ||
		    (had_peer_eui64 &&
		     memcmp(ctx->peer_eui64, eui64_copy, sizeof(eui64_copy)) != 0)) {
			ret = OSCORE_ERR_NO_CONTEXT;
			goto cleanup;
		}
	}

	/*
	 * SECURITY: Encryption is the final fallible step and writes directly
	 * into the caller's buffer (mirroring oscore_protect_request), which
	 * removes ciphertext_tmp from this frame (-PT_MAX-TAG stack bytes).
	 * Every failure-prone step above (buffer checks, context validation,
	 * NVM persistence, slot recycle rejection, AAD build) completes first,
	 * so policy and validation failures never write any caller-visible
	 * byte; the no-PIV correlation commit follows only after encryption
	 * succeeds. Residual exposure: if the AEAD primitive itself faults
	 * (hardware-error territory given pre-validated sizes), partial bytes
	 * may land in the caller buffer. With a fresh PIV the NVM SSN then
	 * stays persisted at the margin-skipped value and the in-RAM advance
	 * keeps it (the rollback equality check below no longer matches), so
	 * the skipped sequences are never reused; without a PIV the window is
	 * left uncommitted, so an identical retry of this correlation remains
	 * possible.
	 */
	if (lichen_aes_ccm_encrypt(sender_key, nonce,
			    aad, aad_len,
			    plaintext, pt_len,
			    ciphertext) != 0) {
		ret = OSCORE_ERR_ENCRYPT_FAILED;
		goto cleanup;
	}
	fresh_reserved = false;

	/*
	 * Commit the no-PIV correlation only after the encryption that could
	 * still fail. This is an infallible RAM write under the mutex this
	 * path has held since identity binding, and the acceptability gate
	 * above ran under that same hold, so no concurrent commit can slip
	 * between the two. On an encrypt fault the window stays unchanged and
	 * a genuine retry of the same correlation can still succeed.
	 */
	if (!include_piv) {
		response_replay_update(&ctx->sent_response_window_initialized,
				       &ctx->sent_response_seq,
				       &ctx->sent_response_window, request_seq);
	}

	if (option_len > 0) {
		memcpy(oscore_opt, option_tmp, option_len);
	}
	*ciphertext_len = required_ct_len;
	*oscore_opt_len = option_len;
	ret = OSCORE_OK;

cleanup:
	if (mutex_locked) {
		k_mutex_unlock(&s_ctx_mutex);
	}
	if (fresh_reserved) {
		/* Roll back only our own still-current reservation on failure. */
		k_mutex_lock(&s_ctx_mutex, K_FOREVER);
		ctx_idx = ctx_get_index(ctx);
		if (ctx_idx >= 0 && ctx->active && ctx->sender_seq == seq + 1 &&
		    ctx->sender_id_len == sender_id_len &&
		    ctx->recipient_id_len == recipient_id_len &&
		    memcmp(ctx->sender_id, sender_id, sender_id_len) == 0 &&
		    memcmp(ctx->recipient_id, recipient_id, recipient_id_len) == 0 &&
		    memcmp(ctx->sender_key, sender_key, sizeof(sender_key)) == 0 &&
		    ctx->has_peer_eui64 == had_peer_eui64 &&
		    (!had_peer_eui64 ||
		     memcmp(ctx->peer_eui64, eui64_copy, sizeof(eui64_copy)) == 0)) {
			ctx->sender_seq = seq;
		}
		k_mutex_unlock(&s_ctx_mutex);
	}
	crypto_wipe(nonce, sizeof(nonce));
	crypto_wipe(plaintext, sizeof(plaintext));
	crypto_wipe(option_tmp, sizeof(option_tmp));
	crypto_wipe(sender_key, sizeof(sender_key));
	crypto_wipe(common_iv, sizeof(common_iv));
	crypto_wipe(sender_id, sizeof(sender_id));
	crypto_wipe(recipient_id, sizeof(recipient_id));
	crypto_wipe(eui64_copy, sizeof(eui64_copy));
	crypto_wipe(piv, sizeof(piv));
	crypto_wipe(&seq, sizeof(seq));
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
	return protect_response(ctx, request_piv, request_piv_len, code,
				options, options_len, payload, payload_len, false,
				ciphertext, ciphertext_len, oscore_opt, oscore_opt_len);
}

int oscore_protect_response_with_piv(struct oscore_ctx *ctx,
				     const uint8_t *request_piv, size_t request_piv_len,
				     uint8_t code,
				     const uint8_t *options, size_t options_len,
				     const uint8_t *payload, size_t payload_len,
				     uint8_t *ciphertext, size_t *ciphertext_len,
				     uint8_t *oscore_opt, size_t *oscore_opt_len)
{
	return protect_response(ctx, request_piv, request_piv_len, code,
				options, options_len, payload, payload_len, true,
				ciphertext, ciphertext_len, oscore_opt, oscore_opt_len);
}

int oscore_unprotect_response(struct oscore_ctx *ctx,
			      const uint8_t *request_piv, size_t request_piv_len,
			      const uint8_t *oscore_opt, size_t oscore_opt_len,
			      const uint8_t *ciphertext, size_t ciphertext_len,
			      uint8_t *code,
			      uint8_t *options, size_t *options_len,
			      uint8_t *payload, size_t *payload_len)
{
	struct oscore_option resp_opt = {0};
	uint8_t nonce[OSCORE_NONCE_LEN];
	uint8_t plaintext[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX];
	int ret;
	const uint8_t *nonce_piv;
	size_t nonce_piv_len;
	uint64_t request_seq;
	uint64_t response_seq = 0;
	bool response_has_piv = false;
	bool mutex_locked = false;
	size_t marker_pos;
	size_t opt_out_len;
	size_t pay_len = 0;

	if (ctx == NULL || ciphertext == NULL || code == NULL ||
	    options_len == NULL || payload_len == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	if (ciphertext_len < OSCORE_TAG_LEN + 1) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* SECURITY: Validate request_piv pointer when len > 0 to prevent NULL dereference */
	if (request_piv_len == 0 || request_piv_len > OSCORE_PIV_MAX_LEN ||
	    request_piv == NULL || (oscore_opt_len > 0 && oscore_opt == NULL)) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/*
	 * RFC 8613 Section 8.4: OSCORE responses MAY include a Partial IV
	 * in the OSCORE option. When present, use response PIV for nonce.
	 */
	nonce_piv = request_piv;
	nonce_piv_len = request_piv_len;
	request_seq = decode_piv(request_piv, request_piv_len);

	if (oscore_opt_len > 0) {
		ret = oscore_option_parse(oscore_opt, oscore_opt_len, &resp_opt);
		if (ret != OSCORE_OK) {
			return ret;
		}
		if (resp_opt.has_piv && resp_opt.piv_len > 0) {
			nonce_piv = resp_opt.piv;
			nonce_piv_len = resp_opt.piv_len;
			response_seq = decode_piv(resp_opt.piv, resp_opt.piv_len);
			response_has_piv = true;
		}
	}

	/*
	 * Keep the context locked through authentication, validation, and replay
	 * commit. This prevents a context slot from being freed/recycled and makes
	 * duplicate concurrent responses deterministic without advancing any
	 * replay window on failure.
	 */
	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	mutex_locked = true;
	if (ctx_get_index(ctx) < 0 || !ctx->active) {
		ret = OSCORE_ERR_NO_CONTEXT;
		goto cleanup_unprotect_response;
	}

	if (resp_opt.has_kid &&
	    (resp_opt.kid_len != ctx->recipient_id_len ||
	     memcmp(resp_opt.kid, ctx->recipient_id, resp_opt.kid_len) != 0)) {
		ret = OSCORE_ERR_NO_CONTEXT;
		goto cleanup_unprotect_response;
	}
	if (resp_opt.has_kid_context &&
	    (resp_opt.kid_context_len != ctx->id_context_len ||
	     memcmp(resp_opt.kid_context, ctx->id_context,
		    resp_opt.kid_context_len) != 0)) {
		ret = OSCORE_ERR_NO_CONTEXT;
		goto cleanup_unprotect_response;
	}

	if (response_has_piv) {
		if (!response_replay_acceptable(ctx->response_piv_window_initialized,
						ctx->response_piv_seq,
						ctx->response_piv_window,
						response_seq)) {
			LOG_WRN("OSCORE response replay detected: seq=%" PRIu64,
				response_seq);
			ret = OSCORE_ERR_REPLAY;
			goto cleanup_unprotect_response;
		}
	} else if (!response_replay_acceptable(
			   ctx->received_response_window_initialized,
			   ctx->received_response_seq,
			   ctx->received_response_window, request_seq)) {
		LOG_WRN("OSCORE response correlation replay detected: request seq=%" PRIu64,
			request_seq);
		ret = OSCORE_ERR_REPLAY;
		goto cleanup_unprotect_response;
	}

	/*
	 * A response without a fresh PIV reuses the request nonce, whose KID is
	 * this client context's sender_id. A response with a fresh PIV uses the
	 * responder's KID (recipient_id) with that PIV (RFC 8613 Sections 8.3/8.4).
	 */
	if (response_has_piv) {
		compute_nonce(ctx->recipient_id, ctx->recipient_id_len,
			      nonce_piv, nonce_piv_len, ctx->common_iv, nonce);
	} else {
		compute_nonce(ctx->sender_id, ctx->sender_id_len,
			      nonce_piv, nonce_piv_len, ctx->common_iv, nonce);
	}

	/* Build AAD per RFC 8613 Section 5.4 - use request KID/PIV */
	uint8_t aad[64];
	int aad_ret = build_oscore_aad(ctx->sender_id, ctx->sender_id_len,
				       request_piv, request_piv_len,
				       aad, sizeof(aad));
	if (aad_ret < 0) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_unprotect_response;
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
	if ((plaintext[0] >> 5) < 2 || (plaintext[0] >> 5) > 5) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_response;
	}
	size_t marker_result = find_coap_payload_marker(plaintext + 1, pt_len - 1);
	if (marker_result == (size_t)-1) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_response;
	}
	marker_pos = 1 + marker_result;
	opt_out_len = marker_pos - 1;

	/* Validate every caller-visible output before mutating outputs or replay state. */
	if (opt_out_len > 0 && options == NULL) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_response;
	}
	if (*options_len < opt_out_len) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_unprotect_response;
	}

	if (marker_pos < pt_len && plaintext[marker_pos] == 0xFF) {
		pay_len = pt_len - marker_pos - 1;
		/* RFC 7252 Section 3: a payload marker without payload is malformed. */
		if (pay_len == 0) {
			ret = OSCORE_ERR_INVALID_PARAM;
			goto cleanup_unprotect_response;
		}
	}
	if (pay_len > 0 && payload == NULL) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_response;
	}
	if (*payload_len < pay_len) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_unprotect_response;
	}

	/* Commit response replay state only after authentication and validation. */
	if (response_has_piv) {
		response_replay_update(&ctx->response_piv_window_initialized,
				       &ctx->response_piv_seq,
				       &ctx->response_piv_window, response_seq);
	} else {
		response_replay_update(&ctx->received_response_window_initialized,
				       &ctx->received_response_seq,
				       &ctx->received_response_window, request_seq);
	}

	/* Publish decrypted data only after all failure paths above are exhausted. */
	*code = plaintext[0];
	if (opt_out_len > 0) {
		memcpy(options, plaintext + 1, opt_out_len);
	}
	*options_len = opt_out_len;
	if (pay_len > 0) {
		memcpy(payload, plaintext + marker_pos + 1, pay_len);
	}
	*payload_len = pay_len;

	ret = OSCORE_OK;

cleanup_unprotect_response:
	if (mutex_locked) {
		k_mutex_unlock(&s_ctx_mutex);
	}
	crypto_wipe(nonce, sizeof(nonce));
	crypto_wipe(plaintext, sizeof(plaintext));
	return ret;
}
