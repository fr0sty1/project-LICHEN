/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file oscore_ctx.c
 * @brief OSCORE context lifecycle management
 *
 * Implements context creation, destruction, lookup, and key derivation.
 */

#include <string.h>
#include <inttypes.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <lichen/oscore.h>
#include "oscore_internal.h"
#include "hkdf.h"
#include <monocypher.h>

LOG_MODULE_DECLARE(oscore, CONFIG_LICHEN_OSCORE_LOG_LEVEL);

/* Context storage */
struct oscore_ctx s_contexts[CONFIG_LICHEN_OSCORE_MAX_CONTEXTS];
bool s_seq_initialized[CONFIG_LICHEN_OSCORE_MAX_CONTEXTS];
bool s_initialized;
K_MUTEX_DEFINE(s_ctx_mutex);

/* NVM persistence callbacks */
oscore_nvm_write_cb s_nvm_write_cb;
oscore_nvm_read_cb s_nvm_read_cb;

/*
 * Derive sender/recipient key or common IV using HKDF.
 */
static int derive_key(const uint8_t *master_secret, size_t ms_len,
		      const uint8_t *master_salt, size_t salt_len,
		      const uint8_t *id, size_t id_len,
		      const uint8_t *id_context, size_t id_context_len,
		      const char *type, size_t out_len,
		      uint8_t *out)
{
	uint8_t info[64];
	int info_len;

	info_len = build_info_cbor(id, id_len, id_context, id_context_len,
				   type, out_len, info, sizeof(info));
	if (info_len < 0) {
		return OSCORE_ERR_KEY_DERIVATION;
	}

	if (lichen_hkdf_sha256(master_salt, salt_len,
			       master_secret, ms_len,
			       info, (size_t)info_len,
			       out, out_len) != 0) {
		return OSCORE_ERR_KEY_DERIVATION;
	}

	return OSCORE_OK;
}

/*
 * Find context pointer by recipient ID (internal, caller holds mutex).
 * Returns NULL if not found.
 *
 * Security note: Uses Monocypher's crypto_verify16() for constant-time
 * comparison to prevent timing leaks about configured recipient ID lengths.
 * The length match is combined with the byte comparison result to determine
 * the final match. (python-ano.81)
 */
struct oscore_ctx *ctx_find_by_recipient_locked(const uint8_t *recipient_id,
						size_t recipient_id_len)
{
	/*
	 * SECURITY: Reject oversized recipient_id_len early to prevent:
	 * 1. The padded_input staying all zeros (no memcpy executed)
	 * 2. Truncation when casting to uint8_t for length comparison
	 * These could cause false matches (e.g., len=256 matching len=0).
	 */
	if (recipient_id_len > OSCORE_ID_MAX_LEN) {
		return NULL;
	}
	if (recipient_id_len > 0 && recipient_id == NULL) {
		return NULL;
	}

	/* Pad input to 16 bytes for crypto_verify16 */
	uint8_t padded_input[16] = {0};
	memcpy(padded_input, recipient_id, recipient_id_len);

	for (int i = 0; i < CONFIG_LICHEN_OSCORE_MAX_CONTEXTS; i++) {
		if (s_contexts[i].active) {
			/*
			 * Pad stored recipient_id to 16 bytes for constant-time
			 * comparison via crypto_verify16. The stored recipient_id
			 * is already zero-padded (struct is zeroed at creation).
			 */
			uint8_t padded_stored[16] = {0};
			memcpy(padded_stored, s_contexts[i].recipient_id,
			       OSCORE_ID_MAX_LEN);
			/*
			 * Match requires both:
			 * 1. All bytes match (crypto_verify16 returns 0)
			 * 2. Lengths match (constant-time via XOR + OR)
			 */
			int bytes_differ = crypto_verify16(padded_stored, padded_input);
			uint8_t len_diff = (uint8_t)(s_contexts[i].recipient_id_len ^
						     (uint8_t)recipient_id_len);
			if ((bytes_differ | len_diff) == 0) {
				return &s_contexts[i];
			}
		}
	}
	return NULL;
}

/*
 * Find context pointer by peer EUI-64 (internal, caller holds mutex).
 * Returns NULL if not found.
 *
 * Security note: Uses Monocypher's crypto_verify16() for constant-time
 * comparison to prevent timing side-channels.
 */
struct oscore_ctx *ctx_find_by_eui64_locked(const uint8_t eui64[OSCORE_EUI64_LEN])
{
	/* Pad input EUI-64 to 16 bytes for crypto_verify16 */
	uint8_t padded_input[16] = {0};
	memcpy(padded_input, eui64, OSCORE_EUI64_LEN);

	for (int i = 0; i < CONFIG_LICHEN_OSCORE_MAX_CONTEXTS; i++) {
		if (s_contexts[i].active && s_contexts[i].has_peer_eui64) {
			/* Pad stored EUI-64 to 16 bytes for constant-time compare */
			uint8_t padded_stored[16] = {0};
			memcpy(padded_stored, s_contexts[i].peer_eui64,
			       OSCORE_EUI64_LEN);
			if (crypto_verify16(padded_stored, padded_input) == 0) {
				return &s_contexts[i];
			}
		}
	}
	return NULL;
}

/*
 * Get context index for a given context pointer.
 * Returns -1 if not in the array.
 */
int ctx_get_index(const struct oscore_ctx *ctx)
{
	if (ctx >= &s_contexts[0] && ctx < &s_contexts[CONFIG_LICHEN_OSCORE_MAX_CONTEXTS]) {
		return (int)(ctx - s_contexts);
	}
	return -1;
}

int oscore_init(void)
{
	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	if (s_initialized) {
		k_mutex_unlock(&s_ctx_mutex);
		return 0;
	}
	memset(s_contexts, 0, sizeof(s_contexts));
	memset(s_seq_initialized, 0, sizeof(s_seq_initialized));
	s_nvm_write_cb = NULL;
	s_nvm_read_cb = NULL;
	s_initialized = true;
	k_mutex_unlock(&s_ctx_mutex);

	LOG_INF("OSCORE initialized (%d contexts max)",
		CONFIG_LICHEN_OSCORE_MAX_CONTEXTS);
	return 0;
}

void oscore_nvm_register_callbacks(oscore_nvm_write_cb _Nullable write_cb,
				   oscore_nvm_read_cb _Nullable read_cb)
{
	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	if (s_nvm_write_cb != write_cb || s_nvm_read_cb != read_cb) {
		s_nvm_write_cb = write_cb;
		s_nvm_read_cb = read_cb;
		LOG_DBG("NVM callbacks registered (write=%p, read=%p)",
			(void *)write_cb, (void *)read_cb);
	}
	k_mutex_unlock(&s_ctx_mutex);
}

int oscore_ctx_create(const uint8_t *_Nonnull master_secret,
		      const uint8_t *_Nullable master_salt, size_t master_salt_len,
		      const uint8_t *_Nonnull sender_id, size_t sender_id_len,
		      const uint8_t *_Nonnull recipient_id, size_t recipient_id_len,
		      struct oscore_ctx *_Nullable *_Nonnull ctx_out)
{
	struct oscore_ctx *ctx = NULL;
	int ret;
	int ctx_idx;

	/* Validate required output and master_secret are provided. */
	if (ctx_out == NULL) {
		LOG_ERR("ctx_out must not be NULL");
		return OSCORE_ERR_INVALID_PARAM;
	}
	*ctx_out = NULL;

	if (master_secret == NULL) {
		LOG_ERR("master_secret must not be NULL");
		return OSCORE_ERR_INVALID_PARAM;
	}

	/*
	 * Nonce layout per RFC 8613 Section 5.2 / Figure 8: S flag at byte 0,
	 * Sender/Recipient ID right-aligned into byte 7, PIV in bytes 8..12;
	 * implemented by compute_nonce() and verified against Python/Rust
	 * cross-implementation test vectors.
	 */
	if (sender_id_len > 7 || recipient_id_len > 7) {
		LOG_ERR("sender/recipient ID exceeds RFC 8613 max (7 bytes)");
		return OSCORE_ERR_INVALID_PARAM;
	}

	if ((sender_id == NULL && sender_id_len > 0) ||
	    (recipient_id == NULL && recipient_id_len > 0)) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	if (sender_id_len > OSCORE_ID_MAX_LEN ||
	    recipient_id_len > OSCORE_ID_MAX_LEN ||
	    master_salt_len > 8) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/*
	 * SECURITY: Reject sender_id == recipient_id for unicast OSCORE because
	 * both peers would derive identical keys. This includes the case where
	 * both IDs are empty (zero-length). Group OSCORE (RFC 9203) may allow
	 * this, but we don't support it yet.
	 */
	if ((sender_id_len == 0 && recipient_id_len == 0) ||
	    (sender_id_len > 0 && sender_id_len == recipient_id_len &&
	     memcmp(sender_id, recipient_id, sender_id_len) == 0)) {
		LOG_ERR("sender_id and recipient_id must differ for unicast OSCORE");
		return OSCORE_ERR_INVALID_PARAM;
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	if (!s_initialized) {
		k_mutex_unlock(&s_ctx_mutex);
		LOG_ERR("oscore_init() must be called before oscore_ctx_create()");
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Find free slot */
	ctx_idx = -1;
	for (int i = 0; i < CONFIG_LICHEN_OSCORE_MAX_CONTEXTS; i++) {
		if (!s_contexts[i].active) {
			ctx = &s_contexts[i];
			ctx_idx = i;
			break;
		}
	}

	if (ctx == NULL) {
		k_mutex_unlock(&s_ctx_mutex);
		return OSCORE_ERR_NO_MEMORY;
	}

	/* Initialize context */
	replay_clear_pending_context_locked(ctx_idx);
	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->master_secret, master_secret, OSCORE_KEY_LEN);

	if (master_salt != NULL && master_salt_len > 0) {
		memcpy(ctx->master_salt, master_salt, master_salt_len);
		ctx->master_salt_len = (uint8_t)master_salt_len;
	}

	if (sender_id_len > 0) {
		memcpy(ctx->sender_id, sender_id, sender_id_len);
	}
	ctx->sender_id_len = (uint8_t)sender_id_len;

	if (recipient_id_len > 0) {
		memcpy(ctx->recipient_id, recipient_id, recipient_id_len);
	}
	ctx->recipient_id_len = (uint8_t)recipient_id_len;

	/* Derive Sender Key */
	ret = derive_key(ctx->master_secret, OSCORE_KEY_LEN,
			 ctx->master_salt, ctx->master_salt_len,
			 ctx->sender_id, ctx->sender_id_len,
			 ctx->id_context, ctx->id_context_len,
			 "Key", OSCORE_KEY_LEN, ctx->sender_key);
	if (ret != OSCORE_OK) {
		goto cleanup_on_failure;
	}

	/* Derive Recipient Key */
	ret = derive_key(ctx->master_secret, OSCORE_KEY_LEN,
			 ctx->master_salt, ctx->master_salt_len,
			 ctx->recipient_id, ctx->recipient_id_len,
			 ctx->id_context, ctx->id_context_len,
			 "Key", OSCORE_KEY_LEN, ctx->recipient_key);
	if (ret != OSCORE_OK) {
		goto cleanup_on_failure;
	}

	/* Derive Common IV (id = empty for common context) */
	ret = derive_key(ctx->master_secret, OSCORE_KEY_LEN,
			 ctx->master_salt, ctx->master_salt_len,
			 NULL, 0,
			 ctx->id_context, ctx->id_context_len,
			 "IV", OSCORE_NONCE_LEN, ctx->common_iv);
	if (ret != OSCORE_OK) {
		goto cleanup_on_failure;
	}

	/* Wipe master secret now that keys are derived (issue python-bdd.4) */
	crypto_wipe(ctx->master_secret, sizeof(ctx->master_secret));

	ctx->sender_seq = 0;
	ctx->recipient_seq = 0;
	ctx->replay_window = 0;
	ctx->active = true;

	/*
	 * Mark sender_seq as NOT initialized - caller MUST call
	 * oscore_ctx_set_sender_seq() before using oscore_protect_request().
	 * This prevents nonce reuse after reboot (python-ano.41).
	 */
	s_seq_initialized[ctx_idx] = false;

	k_mutex_unlock(&s_ctx_mutex);

	*ctx_out = ctx;
	LOG_DBG("Created OSCORE context (sender=%u, recipient=%u)",
		sender_id_len, recipient_id_len);
	return OSCORE_OK;

cleanup_on_failure:
	/* Wipe partial context to avoid leaking key material */
	crypto_wipe(ctx, sizeof(*ctx));
	k_mutex_unlock(&s_ctx_mutex);
	return ret;
}

void oscore_ctx_free(struct oscore_ctx *ctx)
{
	int ctx_idx;

	if (ctx == NULL) {
		return;
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	ctx_idx = ctx_get_index(ctx);
	if (ctx_idx >= 0) {
		replay_clear_pending_context_locked(ctx_idx);
		/*
		 * SECURITY: Sender_seq is no longer valid once the context
		 * is freed. Prevents a stale/recycled slot from passing the
		 * initialization check in oscore_protect_request().
		 */
		s_seq_initialized[ctx_idx] = false;
	}

	crypto_wipe(ctx, sizeof(*ctx));

	k_mutex_unlock(&s_ctx_mutex);
}

int oscore_ctx_create_with_eui64(const uint8_t *_Nonnull master_secret,
				 const uint8_t *_Nullable master_salt, size_t master_salt_len,
				 const uint8_t *_Nonnull sender_id, size_t sender_id_len,
				 const uint8_t *_Nonnull recipient_id, size_t recipient_id_len,
				 const uint8_t peer_eui64[_Nonnull OSCORE_EUI64_LEN],
				 struct oscore_ctx *_Nullable *_Nonnull ctx_out)
{
	int ret;
	struct oscore_ctx *ctx;
	int ctx_idx;

	if (peer_eui64 == NULL) {
		LOG_ERR("peer_eui64 must not be NULL");
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* First, create the context using the base function */
	ret = oscore_ctx_create(master_secret, master_salt, master_salt_len,
				sender_id, sender_id_len,
				recipient_id, recipient_id_len, ctx_out);
	if (ret != OSCORE_OK) {
		return ret;
	}

	ctx = *ctx_out;

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	/*
	 * SECURITY: Verify context identity hasn't changed while mutex was
	 * released between oscore_ctx_create() and here. Protects against
	 * another thread freeing and recreating a context in the same slot.
	 */
	ctx_idx = ctx_get_index(ctx);
	if (ctx_idx < 0 || !ctx->active ||
	    ctx->sender_id_len != (uint8_t)sender_id_len ||
	    ctx->recipient_id_len != (uint8_t)recipient_id_len ||
	    (sender_id_len > 0 && memcmp(ctx->sender_id, sender_id, sender_id_len) != 0) ||
	    (recipient_id_len > 0 && memcmp(ctx->recipient_id, recipient_id, recipient_id_len) != 0)) {
		k_mutex_unlock(&s_ctx_mutex);
		LOG_ERR("Context slot recycled during creation");
		*ctx_out = NULL;
		return OSCORE_ERR_NO_CONTEXT;
	}

	/* Set the EUI-64 */
	memcpy(ctx->peer_eui64, peer_eui64, OSCORE_EUI64_LEN);
	ctx->has_peer_eui64 = true;

	/* Try to restore SSN from NVM if callback is registered */
	if (s_nvm_read_cb != NULL) {
		uint64_t stored_ssn;
		ret = s_nvm_read_cb(peer_eui64, &stored_ssn);
		if (ret == 0) {
			ctx->sender_seq = stored_ssn;
			s_seq_initialized[ctx_idx] = true;
			LOG_DBG("Restored SSN %" PRIu64 " from NVM for peer", stored_ssn);

			/* SECURITY: Warn if restored SSN is near exhaustion.
			 * Per RFC 8613 Section 7.5, implementations must
			 * persist SSN with a safety margin. If we're this
			 * close to exhaustion, key rotation is urgent.
			 */
			if (stored_ssn >= OSCORE_SSN_MAX - OSCORE_SSN_ROTATION_CRITICAL) {
				LOG_WRN("Restored SSN %" PRIu64 " near exhaustion, "
					"key rotation required", stored_ssn);
			} else if (stored_ssn >= OSCORE_SSN_MAX - OSCORE_SSN_ROTATION_WARNING) {
				LOG_WRN("Restored SSN %" PRIu64 " approaching exhaustion, "
					"key rotation recommended", stored_ssn);
			}
		} else {
			LOG_DBG("No SSN in NVM for peer, starting fresh");
		}
	}

	k_mutex_unlock(&s_ctx_mutex);

	LOG_DBG("Created OSCORE context with peer EUI-64");
	return OSCORE_OK;
}

int oscore_ctx_set_peer_eui64(struct oscore_ctx *ctx,
			      const uint8_t peer_eui64[OSCORE_EUI64_LEN])
{
	if (ctx == NULL || peer_eui64 == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	memcpy(ctx->peer_eui64, peer_eui64, OSCORE_EUI64_LEN);
	ctx->has_peer_eui64 = true;

	k_mutex_unlock(&s_ctx_mutex);

	LOG_DBG("Set peer EUI-64 for OSCORE context");
	return OSCORE_OK;
}

int oscore_ctx_get_by_eui64(const uint8_t peer_eui64[OSCORE_EUI64_LEN],
			    struct oscore_ctx **ctx_out)
{
	struct oscore_ctx *ctx;
	int ret = OSCORE_ERR_NO_CONTEXT;

	if (peer_eui64 == NULL || ctx_out == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}
	*ctx_out = NULL;

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	ctx = ctx_find_by_eui64_locked(peer_eui64);
	if (ctx != NULL) {
		*ctx_out = ctx;
		ret = OSCORE_OK;
	}

	k_mutex_unlock(&s_ctx_mutex);
	return ret;
}

int oscore_ctx_set_sender_seq(struct oscore_ctx *ctx, uint64_t sender_seq)
{
	if (ctx == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	oscore_nvm_write_cb write_cb;
	uint8_t eui64_copy[OSCORE_EUI64_LEN];
	bool had_peer_eui64 = false;
	int idx;

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	idx = ctx_get_index(ctx);
	if (idx < 0) {
		k_mutex_unlock(&s_ctx_mutex);
		return OSCORE_ERR_INVALID_PARAM;
	}

	write_cb = s_nvm_write_cb;
	if (ctx->has_peer_eui64) {
		memcpy(eui64_copy, ctx->peer_eui64, OSCORE_EUI64_LEN);
		had_peer_eui64 = true;
	}

	k_mutex_unlock(&s_ctx_mutex);

	if (write_cb != NULL) {
		int ret = write_cb(had_peer_eui64 ? eui64_copy : NULL, sender_seq);
		if (ret != 0) {
			LOG_ERR("Failed to persist SSN to NVM: %d", ret);
			return OSCORE_ERR_NVM_FAILED;
		}
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	idx = ctx_get_index(ctx);
	if (idx < 0 || !ctx->active) {
		k_mutex_unlock(&s_ctx_mutex);
		LOG_ERR("Context released before sender_seq commit");
		return OSCORE_ERR_NO_CONTEXT;
	}

	/*
	 * SECURITY: Verify context identity hasn't changed while mutex
	 * was released. Protects against slot reuse by another peer.
	 * Caller MUST see the failure instead of a silent OSCORE_OK.
	 */
	bool identity_matches = false;
	if (had_peer_eui64) {
		identity_matches = ctx->has_peer_eui64 &&
			memcmp(ctx->peer_eui64, eui64_copy, OSCORE_EUI64_LEN) == 0;
	} else {
		identity_matches = !ctx->has_peer_eui64;
	}
	if (!identity_matches) {
		k_mutex_unlock(&s_ctx_mutex);
		LOG_ERR("Context slot recycled during sender_seq update");
		return OSCORE_ERR_NO_CONTEXT;
	}

	ctx->sender_seq = sender_seq;
	s_seq_initialized[idx] = true;

	k_mutex_unlock(&s_ctx_mutex);

	LOG_DBG("Set sender_seq to %llu for nonce persistence", (unsigned long long)sender_seq);
	return OSCORE_OK;
}

/**
 * @note Unlike oscore_ctx_set_sender_seq(), this function works on any
 *       oscore_ctx pointer including copies from oscore_ctx_lookup().
 *       The mutex protects only the read operation, not pointer validity.
 */
int oscore_ctx_get_sender_seq(const struct oscore_ctx *ctx, uint64_t *sender_seq)
{
	if (ctx == NULL || sender_seq == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	*sender_seq = ctx->sender_seq;
	k_mutex_unlock(&s_ctx_mutex);

	return OSCORE_OK;
}

int oscore_ctx_get_seq_remaining(const struct oscore_ctx *ctx, uint64_t *remaining)
{
	if (ctx == NULL || remaining == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	*remaining = ctx->sender_seq > OSCORE_SSN_MAX ?
		     0 : OSCORE_SSN_MAX - ctx->sender_seq + 1;
	k_mutex_unlock(&s_ctx_mutex);

	return OSCORE_OK;
}

int oscore_ctx_check_freshness(const struct oscore_ctx *ctx,
			       enum oscore_freshness *status)
{
	uint64_t remaining;

	if (ctx == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	remaining = ctx->sender_seq > OSCORE_SSN_MAX ?
		    0 : OSCORE_SSN_MAX - ctx->sender_seq + 1;
	k_mutex_unlock(&s_ctx_mutex);

	enum oscore_freshness result;
	if (remaining == 0) {
		result = OSCORE_FRESHNESS_EXHAUSTED;
	} else if (remaining <= OSCORE_SSN_ROTATION_CRITICAL) {
		result = OSCORE_FRESHNESS_CRITICAL;
	} else if (remaining <= OSCORE_SSN_ROTATION_WARNING) {
		result = OSCORE_FRESHNESS_WARNING;
	} else {
		result = OSCORE_FRESHNESS_OK;
	}

	if (status != NULL) {
		*status = result;
	}

	/* Return error if context is exhausted per RFC 8613 Section 7.2.1 */
	if (result == OSCORE_FRESHNESS_EXHAUSTED) {
		LOG_WRN("OSCORE context exhausted - key rotation required");
		return OSCORE_ERR_CONTEXT_STALE;
	}

	if (result == OSCORE_FRESHNESS_CRITICAL) {
		LOG_WRN("OSCORE context critical (%llu remaining) - immediate key rotation needed",
			(unsigned long long)remaining);
	} else if (result == OSCORE_FRESHNESS_WARNING) {
		LOG_INF("OSCORE context warning (%llu remaining) - proactive key rotation recommended",
			(unsigned long long)remaining);
	}

	return OSCORE_OK;
}

int oscore_ctx_persist_ssn(struct oscore_ctx *ctx)
{
	int ret;
	int idx;
	oscore_nvm_write_cb write_cb;
	uint64_t ssn;
	uint64_t durable;
	uint8_t eui64_copy[OSCORE_EUI64_LEN];
	const uint8_t *eui64 = NULL;
	bool had_peer_eui64;

	if (ctx == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	/*
	 * The in-RAM advance below requires a valid, stable slot, so the
	 * context must be resolvable before anything is written.
	 */
	idx = ctx_get_index(ctx);
	if (idx < 0 || !ctx->active) {
		k_mutex_unlock(&s_ctx_mutex);
		return OSCORE_ERR_NO_CONTEXT;
	}

	write_cb = s_nvm_write_cb;
	ssn = ctx->sender_seq;
	had_peer_eui64 = ctx->has_peer_eui64;
	if (had_peer_eui64) {
		memcpy(eui64_copy, ctx->peer_eui64, OSCORE_EUI64_LEN);
		eui64 = eui64_copy;
	}

	k_mutex_unlock(&s_ctx_mutex);

	if (write_cb == NULL) {
		/*
		 * No callback registered, success (no-op). Nothing is
		 * durable, so no margin is skipped and the in-RAM SSN is
		 * untouched; reboot safety then rests entirely on the
		 * mandatory oscore_ctx_set_sender_seq() call after every
		 * reboot.
		 */
		return OSCORE_OK;
	}

	/*
	 * SECURITY: the durable value skips OSCORE_SSN_SAFETY_MARGIN
	 * sequences beyond the next unused one. A reboot that reloads this
	 * value resumes STRICTLY ABOVE every sequence this boot could have
	 * transmitted, so no (key, nonce) pair is reused (RFC 8613 Section
	 * 7.2, Appendix D.4); the skipped sequences are permanently unused.
	 * The cap is the exhaustion sentinel OSCORE_SSN_MAX + 1, not
	 * OSCORE_SSN_MAX: if the terminal five-byte PIV itself was ever
	 * transmitted, only a reloaded value strictly above it preserves the
	 * guarantee, and a reloaded sentinel makes protect_request() refuse
	 * with OSCORE_ERR_SEQ_EXHAUSTED (key rotation required).
	 */
	durable = ssn > OSCORE_SSN_MAX - OSCORE_SSN_SAFETY_MARGIN ?
		  OSCORE_SSN_MAX + 1 : ssn + OSCORE_SSN_SAFETY_MARGIN;

	/* Retry logic (3 attempts with backoff) on NVM failure. Critical for
	 * security: SSN persistence prevents nonce reuse on reboot (RFC 8613
	 * Sections 7.2.1, 7.5).
	 */
	for (int attempt = 0; attempt < 3; attempt++) {
		ret = write_cb(eui64, durable);
		if (ret == 0) {
			k_mutex_lock(&s_ctx_mutex, K_FOREVER);

			/*
			 * Advance the in-RAM SSN only for the same, still-live
			 * slot the durable value was computed for, and only
			 * forward (a concurrent reservation may already have
			 * progressed further). On a recycled slot the NVM
			 * value stays valid for the recorded peer and the
			 * caller sees the failure instead of a stale advance.
			 */
			idx = ctx_get_index(ctx);
			bool identity_matches = idx >= 0 && ctx->active &&
				ctx->has_peer_eui64 == had_peer_eui64 &&
				(!had_peer_eui64 ||
				 memcmp(ctx->peer_eui64, eui64_copy,
					OSCORE_EUI64_LEN) == 0);
			if (!identity_matches) {
				k_mutex_unlock(&s_ctx_mutex);
				LOG_ERR("Context slot recycled during SSN persist");
				return OSCORE_ERR_NO_CONTEXT;
			}
			if (ctx->sender_seq < durable) {
				ctx->sender_seq = durable;
			}

			k_mutex_unlock(&s_ctx_mutex);
			return OSCORE_OK;
		}
		if (attempt < 2) {
			LOG_WRN("NVM persist SSN failed (attempt %d/3, ret=%d), retrying after backoff",
				attempt + 1, ret);
			k_msleep(10 * (attempt + 1));
		}
	}

	/*
	 * On NVM failure the in-RAM SSN is left unchanged so the caller's
	 * reservation rollback (protect paths) or explicit recovery decision
	 * governs, as before the margin existed.
	 */
	LOG_ERR("Failed to persist SSN to NVM after 3 attempts: %d", ret);
	return OSCORE_ERR_NVM_FAILED;
}

int oscore_ctx_get(const uint8_t *recipient_id,
		   size_t recipient_id_len,
		   struct oscore_ctx **ctx_out)
{
	struct oscore_ctx *ctx;
	int ret = OSCORE_ERR_NO_CONTEXT;

	if (ctx_out == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}
	*ctx_out = NULL;

	if (recipient_id == NULL && recipient_id_len > 0) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	ctx = ctx_find_by_recipient_locked(recipient_id, recipient_id_len);
	if (ctx != NULL) {
		*ctx_out = ctx;
		ret = OSCORE_OK;
	}

	k_mutex_unlock(&s_ctx_mutex);
	return ret;
}
