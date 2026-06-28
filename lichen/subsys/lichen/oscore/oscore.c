/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file oscore.c
 * @brief OSCORE (RFC 8613) implementation
 *
 * Implements Object Security for Constrained RESTful Environments using
 * AES-CCM-16-64-128 and HKDF-SHA256 key derivation.
 */

#include <limits.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <lichen/oscore.h>
#include "aes_ccm.h"
#include "hkdf.h"
#include <monocypher.h>
#include <zcbor_encode.h>

LOG_MODULE_REGISTER(oscore, CONFIG_LICHEN_OSCORE_LOG_LEVEL);

/* Context storage */
static struct oscore_ctx s_contexts[CONFIG_LICHEN_OSCORE_MAX_CONTEXTS];
static bool s_seq_initialized[CONFIG_LICHEN_OSCORE_MAX_CONTEXTS];
static bool s_initialized;
static K_MUTEX_DEFINE(s_ctx_mutex);

#define OSCORE_REPLAY_PENDING_MAX \
	(CONFIG_LICHEN_OSCORE_MAX_CONTEXTS * CONFIG_LICHEN_OSCORE_REPLAY_WINDOW)

struct oscore_replay_pending {
	bool active;
	int ctx_idx;
	uint32_t seq;
};

static struct oscore_replay_pending s_replay_pending[OSCORE_REPLAY_PENDING_MAX];

/*
 * Find context pointer by recipient ID (internal, caller holds mutex).
 * Returns NULL if not found.
 *
 * Security note: Always compares OSCORE_ID_MAX_LEN bytes in constant time
 * to prevent timing leaks about configured recipient ID lengths. The length
 * match is combined with the byte comparison result to determine the final
 * match. (python-ano.81)
 */
static struct oscore_ctx *ctx_find_by_recipient_locked(const uint8_t *recipient_id,
						       size_t recipient_id_len)
{
	/* Pad input to OSCORE_ID_MAX_LEN with zeros for constant-time compare */
	uint8_t padded_input[OSCORE_ID_MAX_LEN] = {0};
	if (recipient_id_len <= OSCORE_ID_MAX_LEN) {
		memcpy(padded_input, recipient_id, recipient_id_len);
	}

	for (int i = 0; i < CONFIG_LICHEN_OSCORE_MAX_CONTEXTS; i++) {
		if (s_contexts[i].active) {
			/*
			 * Always compare all OSCORE_ID_MAX_LEN bytes in constant time.
			 * The stored recipient_id is already zero-padded (struct is
			 * zeroed at creation and IDs are memcpy'd).
			 */
			uint8_t diff = 0;
			for (size_t j = 0; j < OSCORE_ID_MAX_LEN; j++) {
				diff |= s_contexts[i].recipient_id[j] ^ padded_input[j];
			}
			/*
			 * Match requires both:
			 * 1. All bytes match (diff == 0)
			 * 2. Lengths match (constant-time via XOR + OR)
			 */
			uint8_t len_diff = (uint8_t)(s_contexts[i].recipient_id_len ^
						     (uint8_t)recipient_id_len);
			if ((diff | len_diff) == 0) {
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
static int ctx_get_index(const struct oscore_ctx *ctx)
{
	if (ctx >= &s_contexts[0] && ctx < &s_contexts[CONFIG_LICHEN_OSCORE_MAX_CONTEXTS]) {
		return (int)(ctx - s_contexts);
	}
	return -1;
}

static void replay_clear_pending_context_locked(int ctx_idx);

/*
 * OSCORE info structure for HKDF (RFC 8613 Section 3.2.1):
 *
 * info = [
 *   id : bstr,
 *   id_context : bstr / nil,
 *   alg_aead : int,
 *   type : tstr,
 *   L : uint
 * ]
 *
 * We encode this as a minimal CBOR array.
 */

/* COSE Algorithm ID for AES-CCM-16-64-128 */
#define OSCORE_ALG_AEAD 10

/*
 * CBOR encoding constants (RFC 8949).
 * Major types are encoded in the high 3 bits of the initial byte.
 * The low 5 bits encode the argument (length/value) for values 0-23,
 * or indicate extended encoding (24=1-byte, 25=2-byte, etc.).
 */
#define CBOR_UINT_1BYTE   0x18  /* uint with 1-byte argument follows */
#define CBOR_BSTR_BASE    0x40  /* bstr major type (type 2, arg 0) */
#define CBOR_BSTR_1BYTE   0x58  /* bstr with 1-byte length follows */
#define CBOR_TSTR_BASE    0x60  /* tstr major type (type 3, arg 0) */
#define CBOR_ARRAY_BASE   0x80  /* array major type (type 4, arg 0) */
#define CBOR_NULL         0xf6  /* simple value null */

/*
 * Replay window implementation uses a 32-bit bitmap. The configurable
 * window size must not exceed what can be tracked in uint32_t.
 * (Fixes python-ano.55)
 */
#if CONFIG_LICHEN_OSCORE_REPLAY_WINDOW > 32
#error "CONFIG_LICHEN_OSCORE_REPLAY_WINDOW exceeds 32-bit bitmap capacity"
#endif

/*
 * Maximum plaintext buffer size for OSCORE protect/unprotect.
 * This limits the maximum CoAP payload size to approximately
 * OSCORE_PLAINTEXT_MAX - OSCORE_TAG_LEN - 1 (for code byte).
 * Increase if larger payloads are needed.
 */
#ifndef CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX
#define CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX 256
#endif

/*
 * Build OSCORE HKDF info structure in CBOR format (RFC 8613 Section 3.2.1):
 *   info = [id : bstr, id_context : bstr / nil, alg_aead : int, type : tstr, L : uint]
 * Returns encoded length, or negative on error.
 *
 * Note: This function contains inline CBOR encoding rather than using a
 * shared CBOR library. This is intentional - OSCORE info encoding is a
 * simple, fixed-format structure (5-element array with known types), and
 * pulling in a general CBOR encoder would add code size for no benefit.
 * The encoding here matches RFC 8613 Section 3.2.1 exactly.
 *
 * CBOR encoding reference (RFC 8949 Section 3.1 - Major Types):
 *   Major type 0 (uint):   0x00-0x17 = value 0-23 inline
 *                          0x18 = 1-byte uint follows
 *   Major type 2 (bstr):   0x40-0x57 = bstr length 0-23 inline
 *                          0x58 = 1-byte length follows
 *   Major type 3 (tstr):   0x60-0x77 = tstr length 0-23 inline
 *   Major type 4 (array):  0x80-0x97 = array of 0-23 items
 *   Major type 7 (simple): 0xf6 = null
 */
static int build_info_cbor(const uint8_t *id, size_t id_len,
			   const uint8_t *id_context, size_t id_context_len,
			   const char *type, size_t out_len,
			   uint8_t *buf, size_t buf_len)
{
	size_t off = 0;

	/*
	 * CBOR array header: major type 4 (0x80) + 5 items = 0x85
	 * RFC 8949 Section 3.1: array(n) = 0x80 | n for n <= 23
	 */
	if (off >= buf_len) return -1;
	buf[off++] = 0x85;

	/*
	 * id: bstr (RFC 8613 Section 3.2.1, first element)
	 * CBOR bstr: major type 2 (0x40) + length
	 *   0x40-0x57: length 0-23 inline (0x40 | len)
	 *   0x58: 1-byte length follows
	 */
	if (id_len <= 23) {
		if (off >= buf_len) return -1;
		buf[off++] = 0x40 | (uint8_t)id_len;
	} else {
		if (off + 1 >= buf_len) return -1;
		buf[off++] = 0x58;
		buf[off++] = (uint8_t)id_len;
	}
	if (off + id_len > buf_len) return -1;
	memcpy(buf + off, id, id_len);
	off += id_len;

	/*
	 * id_context: bstr or null (RFC 8613 Section 3.2.1, second element)
	 * Encode as CBOR null (0xf6) when absent, bstr otherwise.
	 * RFC 8949 Section 3.3: simple value 22 (null) = 0xf6
	 */
	if (id_context_len == 0) {
		if (off >= buf_len) return -1;
		buf[off++] = 0xf6;
	} else {
		if (id_context_len <= 23) {
			if (off >= buf_len) return -1;
			buf[off++] = 0x40 | (uint8_t)id_context_len;
		} else {
			if (off + 1 >= buf_len) return -1;
			buf[off++] = 0x58;
			buf[off++] = (uint8_t)id_context_len;
		}
		if (off + id_context_len > buf_len) return -1;
		memcpy(buf + off, id_context, id_context_len);
		off += id_context_len;
	}

	/*
	 * alg_aead: int (RFC 8613 Section 3.2.1, third element)
	 * Value 10 = AES-CCM-16-64-128 (COSE Algorithm ID from RFC 9053)
	 * CBOR uint: major type 0, values 0-23 encode directly (no prefix)
	 */
	if (off >= buf_len) return -1;
	buf[off++] = OSCORE_ALG_AEAD;

	/*
	 * type: tstr (RFC 8613 Section 3.2.1, fourth element)
	 * One of "Key", "IV", or "Info"
	 * CBOR tstr: major type 3 (0x60) + length
	 *   0x60-0x77: length 0-23 inline (0x60 | len)
	 */
	size_t type_len = strlen(type);
	if (type_len <= 23) {
		if (off >= buf_len) return -1;
		buf[off++] = 0x60 | (uint8_t)type_len;
	} else {
		return -1; /* type shouldn't be > 23 chars */
	}
	if (off + type_len > buf_len) return -1;
	memcpy(buf + off, type, type_len);
	off += type_len;

	/*
	 * L: uint (RFC 8613 Section 3.2.1, fifth element)
	 * Output length in bytes (16 for Key, 13 for IV)
	 * CBOR uint: major type 0
	 *   0x00-0x17: value 0-23 inline
	 *   0x18: 1-byte value follows
	 */
	if (out_len <= 23) {
		if (off >= buf_len) return -1;
		buf[off++] = (uint8_t)out_len;
	} else if (out_len <= 255) {
		if (off + 1 >= buf_len) return -1;
		buf[off++] = 0x18;
		buf[off++] = (uint8_t)out_len;
	} else {
		return -1; /* L shouldn't be > 255 for OSCORE */
	}

	/* Guard against unlikely overflow before int cast (python-ano.118) */
	if (off > (size_t)INT_MAX) {
		return -1;
	}

	return (int)off;
}

/*
 * Build OSCORE external AAD per RFC 8613 Section 5.4.
 *
 * external_aad = bstr .cbor aad_array
 * aad_array = [
 *   oscore_version : uint,        (1 for OSCORE v1)
 *   algorithms : [alg_aead : int], (array containing algorithm ID)
 *   request_kid : bstr,
 *   request_piv : bstr,
 *   options : bstr                (Class I options, empty for now)
 * ]
 *
 * Then wrapped in Enc_structure (RFC 9052 Section 5.3):
 * Enc_structure = [
 *   "Encrypt0",
 *   h'',  (empty protected header)
 *   external_aad
 * ]
 *
 * Returns encoded length, or negative on error.
 *
 * CBOR encoding reference (RFC 8949 Section 3.1 - Major Types):
 *   Major type 0 (uint):   0x00-0x17 = value 0-23 inline
 *   Major type 2 (bstr):   0x40-0x57 = bstr length 0-23 inline (0x40 | len)
 *                          0x58 = 1-byte length follows
 *   Major type 3 (tstr):   0x60-0x77 = tstr length 0-23 inline (0x60 | len)
 *   Major type 4 (array):  0x80-0x97 = array of 0-23 items (0x80 | count)
 */
static int build_oscore_aad(const uint8_t *request_kid, size_t request_kid_len,
			    const uint8_t *request_piv, size_t request_piv_len,
			    uint8_t *buf, size_t buf_len)
{
	size_t off = 0;

	/*
	 * First build the aad_array (RFC 8613 Section 5.4), then wrap it.
	 * We build the inner structure in a temp buffer, then encode it
	 * as a bstr inside the Enc_structure.
	 */
	uint8_t inner[64];
	size_t inner_off = 0;

	/*
	 * aad_array: 5-element array
	 * CBOR array: major type 4 (0x80) + 5 items = 0x85
	 */
	inner[inner_off++] = 0x85;

	/*
	 * oscore_version: uint = 1 (RFC 8613 Section 5.4, first element)
	 * CBOR uint: values 0-23 encode directly
	 */
	inner[inner_off++] = 0x01;

	/*
	 * algorithms: 1-element array containing alg_aead (second element)
	 * 0x81 = array of 1 item (0x80 | 1)
	 * Value 10 = AES-CCM-16-64-128 (COSE Algorithm ID from RFC 9053)
	 */
	inner[inner_off++] = 0x81;
	inner[inner_off++] = OSCORE_ALG_AEAD;

	/*
	 * request_kid: bstr (RFC 8613 Section 5.4, third element)
	 * CBOR bstr: 0x40 | len for len <= 23
	 */
	if (request_kid_len <= 23) {
		inner[inner_off++] = 0x40 | (uint8_t)request_kid_len;
	} else {
		return -1; /* shouldn't happen with OSCORE_ID_MAX_LEN */
	}
	if (request_kid_len > 0) {
		if (inner_off + request_kid_len > sizeof(inner)) {
			return -1;
		}
		memcpy(inner + inner_off, request_kid, request_kid_len);
		inner_off += request_kid_len;
	}

	/*
	 * request_piv: bstr (RFC 8613 Section 5.4, fourth element)
	 * CBOR bstr: 0x40 | len for len <= 23
	 */
	if (request_piv_len <= 23) {
		inner[inner_off++] = 0x40 | (uint8_t)request_piv_len;
	} else {
		return -1;
	}
	/*
	 * options: empty bstr (RFC 8613 Section 5.4, fifth element)
	 * Class I options - not used in this implementation
	 * 0x40 = bstr of length 0
	 */
	inner[inner_off++] = 0x40;

	/*
	 * Now build Enc_structure (RFC 9052 Section 5.3):
	 *   ["Encrypt0", h'', external_aad]
	 * where external_aad = bstr .cbor aad_array (the inner buffer)
	 */

	/*
	 * 3-element array
	 * CBOR array: 0x83 = 0x80 | 3
	 */
	if (off >= buf_len) return -1;
	buf[off++] = 0x83;

	/*
	 * "Encrypt0" as tstr (8 chars)
	 * CBOR tstr: 0x68 = 0x60 | 8 (tstr of length 8)
	 */
	if (off >= buf_len) return -1;
	buf[off++] = 0x68;
	if (off + 8 > buf_len) return -1;
	memcpy(buf + off, "Encrypt0", 8);
	off += 8;

	/*
	 * empty bstr (protected header per RFC 9052 Section 5.3)
	 * 0x40 = bstr of length 0
	 */
	if (off >= buf_len) return -1;
	buf[off++] = 0x40;

	/*
	 * external_aad as bstr wrapping the inner CBOR
	 * CBOR bstr: 0x40 | len for len <= 23, 0x58 + len for len 24-255
	 */
	if (inner_off <= 23) {
		if (off >= buf_len) return -1;
		buf[off++] = 0x40 | (uint8_t)inner_off;
	} else {
		if (off + 1 >= buf_len) return -1;
		buf[off++] = 0x58;
		buf[off++] = (uint8_t)inner_off;
	}
	if (off + inner_off > buf_len) return -1;
	memcpy(buf + off, inner, inner_off);
	off += inner_off;

	/* Guard against unlikely overflow before int cast (python-ano.118) */
	if (off > (size_t)INT_MAX) {
		return -1;
	}

	return (int)off;
}

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

int oscore_init(void)
{
	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	if (s_initialized) {
		k_mutex_unlock(&s_ctx_mutex);
		return 0;
	}
	memset(s_contexts, 0, sizeof(s_contexts));
	memset(s_seq_initialized, 0, sizeof(s_seq_initialized));
	memset(s_replay_pending, 0, sizeof(s_replay_pending));
	s_initialized = true;
	k_mutex_unlock(&s_ctx_mutex);

	LOG_INF("OSCORE initialized (%d contexts max)",
		CONFIG_LICHEN_OSCORE_MAX_CONTEXTS);
	return 0;
}

int oscore_ctx_create(const uint8_t master_secret[OSCORE_KEY_LEN],
		      const uint8_t *master_salt, size_t master_salt_len,
		      const uint8_t *sender_id, size_t sender_id_len,
		      const uint8_t *recipient_id, size_t recipient_id_len,
		      struct oscore_ctx **ctx_out)
{
	struct oscore_ctx *ctx = NULL;
	int ret;
	int ctx_idx;

	/* Validate required output and master_secret are provided. */
	if (ctx_out == NULL) {
		LOG_ERR("ctx_out must not be NULL");
		return OSCORE_ERR_INVALID_PARAM;
	}

	if (master_secret == NULL) {
		LOG_ERR("master_secret must not be NULL");
		return OSCORE_ERR_INVALID_PARAM;
	}

	/*
	 * RFC 8613 Section 5.2: The nonce format reserves 6 bytes for
	 * the sender ID in the nonce computation. IDs of 7 bytes are
	 * allowed but the 7th byte overlaps with the ID length field,
	 * which is handled correctly by compute_nonce. IDs > 7 bytes
	 * would overflow the nonce format.
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
	 * Warn if sender_id == recipient_id - this breaks unicast OSCORE
	 * because both peers would derive identical keys. Group OSCORE
	 * (RFC 9203) may allow this, but we don't support it yet.
	 * (python-ano.48)
	 */
	if (sender_id_len > 0 &&
	    sender_id_len == recipient_id_len &&
	    memcmp(sender_id, recipient_id, sender_id_len) == 0) {
		LOG_WRN("sender_id == recipient_id - key derivation will be symmetric");
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

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
	}

	/* Secure wipe of key material (crypto_wipe cannot be optimized away) */
	crypto_wipe(ctx->master_secret, sizeof(ctx->master_secret));
	crypto_wipe(ctx->master_salt, sizeof(ctx->master_salt));
	crypto_wipe(ctx->sender_key, sizeof(ctx->sender_key));
	crypto_wipe(ctx->recipient_key, sizeof(ctx->recipient_key));
	crypto_wipe(ctx->common_iv, sizeof(ctx->common_iv));
	crypto_wipe(ctx->id_context, sizeof(ctx->id_context)); /* python-ano.74 */
	ctx->active = false;

	k_mutex_unlock(&s_ctx_mutex);
}

int oscore_ctx_set_sender_seq(struct oscore_ctx *ctx, uint32_t sender_seq)
{
	int idx;

	if (ctx == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	idx = ctx_get_index(ctx);
	if (idx < 0) {
		k_mutex_unlock(&s_ctx_mutex);
		return OSCORE_ERR_INVALID_PARAM;
	}

	ctx->sender_seq = sender_seq;
	s_seq_initialized[idx] = true;

	k_mutex_unlock(&s_ctx_mutex);

	LOG_DBG("Set sender_seq to %u for nonce persistence", sender_seq);
	return OSCORE_OK;
}

/**
 * @note Unlike oscore_ctx_set_sender_seq(), this function works on any
 *       oscore_ctx pointer including copies from oscore_ctx_lookup().
 *       The mutex protects only the read operation, not pointer validity.
 */
int oscore_ctx_get_sender_seq(const struct oscore_ctx *ctx, uint32_t *sender_seq)
{
	if (ctx == NULL || sender_seq == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	*sender_seq = ctx->sender_seq;
	k_mutex_unlock(&s_ctx_mutex);

	return OSCORE_OK;
}

int oscore_ctx_get_seq_remaining(const struct oscore_ctx *ctx, uint32_t *remaining)
{
	if (ctx == NULL || remaining == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	*remaining = UINT32_MAX - ctx->sender_seq;
	k_mutex_unlock(&s_ctx_mutex);

	return OSCORE_OK;
}

int oscore_ctx_lookup(const uint8_t *recipient_id,
		      size_t recipient_id_len,
		      struct oscore_ctx *ctx_out)
{
	struct oscore_ctx *ctx;
	int ret = OSCORE_ERR_NO_CONTEXT;

	if (ctx_out == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	ctx = ctx_find_by_recipient_locked(recipient_id, recipient_id_len);
	if (ctx != NULL) {
		/*
		 * Copy context to caller buffer.
		 *
		 * WARNING: The copied context CANNOT be used with
		 * oscore_protect_request() or oscore_unprotect_request()
		 * because those functions require a pointer to the real
		 * context in s_contexts[] for atomic state updates.
		 *
		 * Use oscore_ctx_get() instead to obtain a pointer that
		 * works with protect/unprotect operations.
		 *
		 * SECURITY: The copy contains key material (sender_key,
		 * recipient_key, common_iv). Caller MUST wipe ctx_out with
		 * memset(ctx_out, 0, sizeof(*ctx_out)) before it goes out
		 * of scope to prevent key material persisting on stack.
		 */
		memcpy(ctx_out, ctx, sizeof(*ctx_out));
		ret = OSCORE_OK;
	}

	k_mutex_unlock(&s_ctx_mutex);
	return ret;
}

/**
 * @warning The returned pointer references internal state and is only valid
 * while no other thread modifies or frees OSCORE contexts. For thread-safe
 * access, use oscore_ctx_lookup() which copies the context, or ensure
 * external synchronization around all uses of the returned pointer.
 */
int oscore_ctx_get(const uint8_t *recipient_id,
		   size_t recipient_id_len,
		   struct oscore_ctx **ctx_out)
{
	struct oscore_ctx *ctx;
	int ret = OSCORE_ERR_NO_CONTEXT;

	if (ctx_out == NULL) {
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

int oscore_option_parse(const uint8_t *data, size_t len,
			struct oscore_option *option)
{
	if (option == NULL || (data == NULL && len > 0)) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	memset(option, 0, sizeof(*option));

	if (len == 0) {
		/* Empty option: no PIV, no KID, no KID Context */
		return OSCORE_OK;
	}

	/*
	 * OSCORE option format (RFC 8613 Section 6.1):
	 *
	 * +-----------+-----------+------+---------+--------+-----+
	 * | 0 (1 bit) | h (1 bit) | k    | n       | PIV    | ... |
	 * |           |           |(1bit)| (3 bits)| (n B)  |     |
	 * +-----------+-----------+------+---------+--------+-----+
	 *
	 * Followed by:
	 * - If h=1: s (1 byte) || kid_context (s bytes)
	 * - If k=1: kid (rest of option)
	 */

	const uint8_t *p = data;
	size_t remaining = len;

	/* First byte: flags */
	uint8_t flags = *p++;
	remaining--;

	/* Reserved bit must be 0 */
	if (flags & 0x80) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	bool h_flag = (flags & 0x10) != 0; /* KID Context present */
	bool k_flag = (flags & 0x08) != 0; /* KID present */
	uint8_t n = flags & 0x07;          /* PIV length */

	/* Parse PIV */
	if (n > 0) {
		if (n > OSCORE_PIV_MAX_LEN || n > remaining) {
			return OSCORE_ERR_INVALID_PARAM;
		}
		memcpy(option->piv, p, n);
		option->piv_len = n;
		option->has_piv = true;
		p += n;
		remaining -= n;
	}

	/* Parse KID Context */
	if (h_flag) {
		if (remaining < 1) {
			return OSCORE_ERR_INVALID_PARAM;
		}
		uint8_t s = *p++;
		remaining--;

		if (s > OSCORE_ID_CONTEXT_MAX_LEN || s > remaining) {
			return OSCORE_ERR_INVALID_PARAM;
		}
		memcpy(option->kid_context, p, s);
		option->kid_context_len = s;
		option->has_kid_context = true;
		p += s;
		remaining -= s;
	}

	/* Parse KID (rest of option if k=1) */
	if (k_flag) {
		if (remaining > OSCORE_ID_MAX_LEN) {
			return OSCORE_ERR_INVALID_PARAM;
		}
		memcpy(option->kid, p, remaining);
		option->kid_len = (uint8_t)remaining;
		option->has_kid = true;
	} else if (remaining > 0) {
		/* k_flag not set but trailing bytes present - malformed */
		return OSCORE_ERR_INVALID_PARAM;
	}

	return OSCORE_OK;
}

int oscore_option_build(const struct oscore_option *option,
			uint8_t *buf, size_t buflen)
{
	size_t off = 0;

	/* Validate parameters (python-ano.88) */
	if (option == NULL || buf == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Validate field lengths against protocol limits */
	if (option->piv_len > OSCORE_PIV_MAX_LEN ||
	    option->kid_len > OSCORE_ID_MAX_LEN ||
	    option->kid_context_len > OSCORE_ID_CONTEXT_MAX_LEN) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/*
	 * Build OSCORE option value.
	 * Minimum is 1 byte (flags), plus variable parts.
	 */

	/* Flags byte */
	uint8_t flags = 0;
	if (option->has_kid_context) {
		flags |= 0x10;
	}
	if (option->has_kid) {
		flags |= 0x08;
	}
	if (option->has_piv) {
		flags |= option->piv_len;  /* piv_len <= 5 validated above */
	}

	if (off >= buflen) {
		return OSCORE_ERR_BUFFER_TOO_SMALL;
	}
	buf[off++] = flags;

	/* PIV */
	if (option->has_piv && option->piv_len > 0) {
		if (off + option->piv_len > buflen) {
			return OSCORE_ERR_BUFFER_TOO_SMALL;
		}
		memcpy(buf + off, option->piv, option->piv_len);
		off += option->piv_len;
	}

	/* KID Context */
	if (option->has_kid_context) {
		if (off + 1 + option->kid_context_len > buflen) {
			return OSCORE_ERR_BUFFER_TOO_SMALL;
		}
		buf[off++] = option->kid_context_len;
		memcpy(buf + off, option->kid_context, option->kid_context_len);
		off += option->kid_context_len;
	}

	/* KID */
	if (option->has_kid) {
		if (off + option->kid_len > buflen) {
			return OSCORE_ERR_BUFFER_TOO_SMALL;
		}
		memcpy(buf + off, option->kid, option->kid_len);
		off += option->kid_len;
	}

	return (int)off;
}

/*
 * Compute nonce from Partial IV and Common IV per RFC 8613 Section 5.2.
 *
 * Nonce structure (13 bytes for AES-CCM-16-64-128):
 *   Byte 0-5:   zeros (padding)
 *   Byte 6:     sender_id_len (1 byte)
 *   Byte 7-12:  left-padded sender_id (6 bytes max, but 7th byte overlaps len)
 *   Then XOR with PIV (left-padded in last 5 bytes) and common_iv.
 *
 * For sender_id_len == 7, the first byte of sender_id occupies position 6,
 * which is the same position as sender_id_len. Per RFC 8613, this is XORed:
 *   nonce[6] = sender_id_len XOR sender_id[0]
 */
static void compute_nonce(const uint8_t *sender_id, size_t sender_id_len,
			  const uint8_t *piv, size_t piv_len,
			  const uint8_t *common_iv,
			  uint8_t nonce[OSCORE_NONCE_LEN])
{
	memset(nonce, 0, OSCORE_NONCE_LEN);

	/*
	 * RFC 8613 Section 5.2: The nonce is constructed as:
	 *   - First byte: left-pad zeros such that ID ends at byte NONCE_LEN-1
	 *   - s (sender_id_len) is placed at byte (NONCE_LEN - 6 - 1) = byte 6
	 *   - sender_id is right-aligned in the last 6 bytes (positions 7-12)
	 *   - For sender_id_len == 7, the first byte of sender_id is XORed
	 *     with the s field at position 6
	 */

	/* Encode sender_id_len at position OSCORE_NONCE_S_POS per RFC 8613 */
	nonce[OSCORE_NONCE_S_POS] = (uint8_t)sender_id_len;

	/* Place sender_id right-aligned in the last bytes, up to 7 bytes */
	if (sender_id_len > 0 && sender_id_len <= 7) {
		/* sender_id ends at position NONCE_LEN-1 (byte 12) */
		size_t start = OSCORE_NONCE_LEN - sender_id_len;
		for (size_t i = 0; i < sender_id_len; i++) {
			nonce[start + i] ^= sender_id[i];
		}
	}

	/* Left-padded PIV in last 5 bytes (positions 8-12) */
	if (piv_len > 0 && piv_len <= 5) {
		size_t piv_start = OSCORE_NONCE_LEN - piv_len;
		for (size_t i = 0; i < piv_len; i++) {
			nonce[piv_start + i] ^= piv[i];
		}
	}

	/* XOR with common IV */
	for (size_t i = 0; i < OSCORE_NONCE_LEN; i++) {
		nonce[i] ^= common_iv[i];
	}
}

/*
 * Encode PIV (sequence number) as variable-length big-endian.
 */
static size_t encode_piv(uint32_t seq, uint8_t piv[OSCORE_PIV_MAX_LEN])
{
	if (seq == 0) {
		piv[0] = 0;
		return 1;
	}

	/* Find number of bytes needed */
	size_t len = 0;
	uint32_t tmp = seq;
	while (tmp > 0) {
		len++;
		tmp >>= 8;
	}

	/* Encode big-endian */
	for (size_t i = 0; i < len; i++) {
		piv[len - 1 - i] = (uint8_t)(seq & 0xFF);
		seq >>= 8;
	}

	return len;
}

/*
 * Decode PIV to sequence number.
 */
static uint32_t decode_piv(const uint8_t *piv, size_t piv_len)
{
	uint32_t seq = 0;
	for (size_t i = 0; i < piv_len; i++) {
		seq = (seq << 8) | piv[i];
	}
	return seq;
}

/*
 * Check if sequence number would be acceptable (without updating state).
 * Returns true if acceptable, false if replay or too old.
 */
static bool replay_check_acceptable(const struct oscore_ctx *ctx, uint32_t seq)
{
	uint32_t window_size = CONFIG_LICHEN_OSCORE_REPLAY_WINDOW;

	if (seq > ctx->recipient_seq) {
		/* New highest seq - always acceptable */
		return true;
	}

	/* seq <= recipient_seq: check if within window */
	uint32_t diff = ctx->recipient_seq - seq;
	if (diff >= window_size) {
		/* Too old */
		return false;
	}

	/* Check if already seen */
	uint32_t mask = 1U << diff;
	if (ctx->replay_window & mask) {
		/* Replay detected */
		return false;
	}

	return true;
}

/*
 * Reserve an acceptable sequence while authentication runs without the replay
 * mutex. The committed replay window is not advanced until authentication
 * succeeds, so forged packets cannot poison replay state.
 *
 * Caller must hold s_ctx_mutex.
 */
static int replay_reserve_pending_locked(const struct oscore_ctx *ctx, int ctx_idx, uint32_t seq)
{
	int free_idx = -1;

	if (!replay_check_acceptable(ctx, seq)) {
		return OSCORE_ERR_REPLAY;
	}

	for (int i = 0; i < OSCORE_REPLAY_PENDING_MAX; i++) {
		if (!s_replay_pending[i].active) {
			if (free_idx < 0) {
				free_idx = i;
			}
			continue;
		}

		if (s_replay_pending[i].ctx_idx == ctx_idx && s_replay_pending[i].seq == seq) {
			return OSCORE_ERR_REPLAY;
		}
	}

	if (free_idx < 0) {
		return OSCORE_ERR_NO_MEMORY;
	}

	s_replay_pending[free_idx].active = true;
	s_replay_pending[free_idx].ctx_idx = ctx_idx;
	s_replay_pending[free_idx].seq = seq;
	return OSCORE_OK;
}

/*
 * Clear a pending reservation. Caller must hold s_ctx_mutex.
 */
static void replay_clear_pending_locked(int ctx_idx, uint32_t seq)
{
	for (int i = 0; i < OSCORE_REPLAY_PENDING_MAX; i++) {
		if (s_replay_pending[i].active &&
		    s_replay_pending[i].ctx_idx == ctx_idx &&
		    s_replay_pending[i].seq == seq) {
			s_replay_pending[i].active = false;
			return;
		}
	}
}

/*
 * Clear all pending reservations for a context slot. Caller must hold
 * s_ctx_mutex.
 */
static void replay_clear_pending_context_locked(int ctx_idx)
{
	for (int i = 0; i < OSCORE_REPLAY_PENDING_MAX; i++) {
		if (s_replay_pending[i].active && s_replay_pending[i].ctx_idx == ctx_idx) {
			s_replay_pending[i].active = false;
		}
	}
}

/*
 * Update replay window after successful decryption.
 * Must be called ONLY after decryption succeeds (caller holds mutex).
 *
 * Returns true if update succeeded, false if seq is no longer acceptable
 * (another thread may have advanced the window during decryption).
 *
 * Concurrent decryptions are serialized by the pending replay reservations, so
 * a sequence that is already marked here is a replay and must not be delivered.
 */
static bool replay_update_window(struct oscore_ctx *ctx, uint32_t seq)
{
	if (seq > ctx->recipient_seq) {
		/* New highest seq - shift window */
		uint32_t shift = seq - ctx->recipient_seq;
		if (shift >= 32) {
			ctx->replay_window = 0;
		} else {
			ctx->replay_window <<= shift;
		}
		ctx->replay_window |= 1; /* Mark current as seen */
		ctx->recipient_seq = seq;
		return true;
	}

	/* seq <= recipient_seq: check if still within window */
	uint32_t diff = ctx->recipient_seq - seq;
	if (diff >= CONFIG_LICHEN_OSCORE_REPLAY_WINDOW) {
		/*
		 * Seq fell outside window while we were decrypting -
		 * another thread advanced recipient_seq significantly.
		 * We still accept this packet (decryption succeeded),
		 * but we can't mark it in the window.
		 *
		 * This is safe: the packet was verified authentic, and
		 * if a duplicate arrives later, it will either be caught
		 * as a replay (if within the new window) or rejected as
		 * too old (if outside). We just can't perfectly track it.
		 */
		return true;
	}

	/* Check if already marked by another thread */
	uint32_t mask = 1U << diff;
	if (ctx->replay_window & mask) {
		return false;
	}

	/* Mark as seen */
	ctx->replay_window |= mask;
	return true;
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
	int ret;
	int ctx_idx;
	uint32_t seq;

	if (ctx == NULL || ciphertext == NULL || ciphertext_len == NULL ||
	    oscore_opt == NULL || oscore_opt_len == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	if ((options_len > 0 && options == NULL) ||
	    (payload_len > 0 && payload == NULL)) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/*
	 * Atomically check initialization, sequence exhaustion, and increment.
	 * This fixes python-ano.2 (race on sender_seq++) and python-ano.41
	 * (nonce reuse if sender_seq not restored after reboot).
	 */
	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	ctx_idx = ctx_get_index(ctx);
	if (ctx_idx < 0) {
		k_mutex_unlock(&s_ctx_mutex);
		LOG_ERR("OSCORE context not in storage array");
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Require sender_seq to be explicitly initialized before first use */
	if (!s_seq_initialized[ctx_idx]) {
		k_mutex_unlock(&s_ctx_mutex);
		LOG_ERR("OSCORE sender_seq not initialized - call oscore_ctx_set_sender_seq()");
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Check for sender sequence number exhaustion before use */
	if (ctx->sender_seq == UINT32_MAX) {
		k_mutex_unlock(&s_ctx_mutex);
		LOG_ERR("OSCORE sender sequence exhausted - key rotation required");
		return OSCORE_ERR_SEQ_EXHAUSTED;
	}

	/* Get and increment sender sequence number atomically */
	seq = ctx->sender_seq++;

	k_mutex_unlock(&s_ctx_mutex);

	piv_len = encode_piv(seq, piv);

	/* Compute nonce */
	compute_nonce(ctx->sender_id, ctx->sender_id_len,
		      piv, piv_len, ctx->common_iv, nonce);

	/*
	 * Build plaintext: code || options || payload
	 * Code is first byte, options follow, then 0xFF marker and payload.
	 */
	pt_len = 0;
	plaintext[pt_len++] = code;

	if (options_len > 0) {
		if (options_len > sizeof(plaintext) - pt_len) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup_protect_request;
		}
		memcpy(plaintext + pt_len, options, options_len);
		pt_len += options_len;
	}

	if (payload_len > 0) {
		if (payload_len > sizeof(plaintext) - pt_len - 1) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup_protect_request;
		}
		plaintext[pt_len++] = 0xFF; /* Payload marker */
		memcpy(plaintext + pt_len, payload, payload_len);
		pt_len += payload_len;
	}

	/* Build AAD per RFC 8613 Section 5.4 */
	uint8_t aad[64];
	int aad_ret = build_oscore_aad(ctx->sender_id, ctx->sender_id_len,
				       piv, piv_len, aad, sizeof(aad));
	if (aad_ret < 0) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_protect_request;
	}
	size_t aad_len = (size_t)aad_ret;

	/* Check output buffer size */
	size_t required_ct_len = pt_len + OSCORE_TAG_LEN;
	if (*ciphertext_len < required_ct_len) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_protect_request;
	}

	/* Encrypt */
	if (lichen_aes_ccm_encrypt(ctx->sender_key, nonce,
			    aad, aad_len,
			    plaintext, pt_len,
			    ciphertext) != 0) {
		ret = OSCORE_ERR_ENCRYPT_FAILED;
		goto cleanup_protect_request;
	}
	*ciphertext_len = required_ct_len;

	/* Build OSCORE option */
	struct oscore_option opt = {
		.has_piv = true,
		.piv_len = (uint8_t)piv_len,
		.has_kid = true,
		.kid_len = ctx->sender_id_len,
	};
	memcpy(opt.piv, piv, piv_len);
	memcpy(opt.kid, ctx->sender_id, ctx->sender_id_len);

	int opt_len = oscore_option_build(&opt, oscore_opt, *oscore_opt_len);
	if (opt_len < 0) {
		ret = opt_len;
		goto cleanup_protect_request;
	}
	*oscore_opt_len = (size_t)opt_len;

	ret = OSCORE_OK;

cleanup_protect_request:
	crypto_wipe(nonce, sizeof(nonce));
	crypto_wipe(piv, sizeof(piv));
	crypto_wipe(plaintext, sizeof(plaintext));
	crypto_wipe(&seq, sizeof(seq)); /* python-ano.23: wipe sender seq from stack */
	return ret;
}

/*
 * Find the CoAP payload marker (0xFF) by properly parsing options (RFC 7252).
 *
 * CoAP option format: first byte encodes delta (4 bits) and length (4 bits).
 * Extended delta/length use subsequent bytes. The naive scan for 0xFF is wrong
 * because option delta/length bytes can legitimately contain 0xFF (python-ano.15).
 *
 * Returns the position of the 0xFF marker, or the end of data if no payload.
 * Returns -1 on malformed options (e.g., option extends past data).
 *
 * ponytail: Return type is int, limiting buffer size to INT_MAX bytes (~2GB).
 * OSCORE payloads on constrained devices won't approach this limit.
 */
static int find_coap_payload_marker(const uint8_t *data, size_t len)
{
	size_t pos = 0;

	while (pos < len) {
		uint8_t byte = data[pos];

		/* 0xFF is the payload marker - found it */
		if (byte == 0xFF) {
			return (int)pos;
		}

		/* Parse option delta and length nibbles */
		uint8_t delta_nibble = (byte >> 4) & 0x0F;
		uint8_t len_nibble = byte & 0x0F;
		pos++;

		/* Decode delta (determines how many extra bytes for delta) */
		if (delta_nibble == 13) {
			if (pos >= len) return -1;  /* Malformed */
			pos++;  /* 1 extended byte */
		} else if (delta_nibble == 14) {
			if (pos + 1 >= len) return -1;  /* Malformed */
			pos += 2;  /* 2 extended bytes */
		} else if (delta_nibble == 15) {
			/* Reserved for payload marker, but we already checked 0xFF */
			return -1;  /* Malformed */
		}

		/* Decode length */
		size_t opt_len;
		if (len_nibble == 13) {
			if (pos >= len) return -1;  /* Malformed */
			opt_len = data[pos] + 13;
			pos++;
		} else if (len_nibble == 14) {
			if (pos + 1 >= len) return -1;  /* Malformed */
			opt_len = ((size_t)data[pos] << 8) + data[pos + 1] + 269;
			pos += 2;
		} else if (len_nibble == 15) {
			/* Reserved */
			return -1;  /* Malformed */
		} else {
			opt_len = len_nibble;
		}

		/* Skip option value */
		if (pos + opt_len > len) return -1;  /* Malformed */
		pos += opt_len;
	}

	/* No payload marker found - all data is options */
	return (int)len;
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

	/* Parse plaintext: code || options || 0xFF || payload */
	if (pt_len < 1) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_request;
	}
	*code = plaintext[0];

	/*
	 * Find payload marker by properly parsing CoAP options (python-ano.15).
	 * The naive scan for 0xFF is incorrect because option deltas/lengths
	 * can legitimately contain 0xFF bytes.
	 */
	int marker_result = find_coap_payload_marker(plaintext + 1, pt_len - 1);
	if (marker_result < 0) {
		/* Malformed CoAP options */
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_request;
	}
	size_t marker_pos = 1 + (size_t)marker_result;

	/* Copy options */
	size_t opt_len = marker_pos - 1;
	if (options == NULL) {
		if (options_len != NULL) {
			*options_len = 0;
		}
	} else if (options_len != NULL) {
		if (*options_len < opt_len) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup_unprotect_request;
		}
		memcpy(options, plaintext + 1, opt_len);
		*options_len = opt_len;
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

	/* Response uses request's PIV for nonce */
	compute_nonce(ctx->recipient_id, ctx->recipient_id_len,
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
	int opt_len = oscore_option_build(&opt, oscore_opt, *oscore_opt_len);
	if (opt_len < 0) {
		ret = opt_len;
		goto cleanup_protect_response;
	}
	*oscore_opt_len = (size_t)opt_len;

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
	uint8_t nonce[OSCORE_NONCE_LEN];
	uint8_t plaintext[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX];
	int ret;

	(void)oscore_opt;
	(void)oscore_opt_len;

	if (ctx == NULL || ciphertext == NULL || code == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	if (ciphertext_len < OSCORE_TAG_LEN + 1) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	if (request_piv_len > OSCORE_PIV_MAX_LEN) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Response uses request's PIV for nonce */
	compute_nonce(ctx->sender_id, ctx->sender_id_len,
		      request_piv, request_piv_len, ctx->common_iv, nonce);

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

	/* Parse plaintext */
	if (pt_len < 1) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_response;
	}
	*code = plaintext[0];

	/*
	 * Find payload marker by properly parsing CoAP options (python-ano.15).
	 */
	int marker_result = find_coap_payload_marker(plaintext + 1, pt_len - 1);
	if (marker_result < 0) {
		/* Malformed CoAP options */
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_response;
	}
	size_t marker_pos = 1 + (size_t)marker_result;

	/* Copy options */
	size_t opt_len = marker_pos - 1;
	if (options == NULL) {
		if (options_len != NULL) {
			*options_len = 0;
		}
	} else if (options_len != NULL) {
		if (*options_len < opt_len) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup_unprotect_response;
		}
		memcpy(options, plaintext + 1, opt_len);
		*options_len = opt_len;
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
