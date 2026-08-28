/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file oscore_internal.h
 * @brief OSCORE internal definitions shared across implementation files
 *
 * This header contains private definitions used by the OSCORE implementation.
 * It is not part of the public API.
 */

#ifndef OSCORE_INTERNAL_H
#define OSCORE_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <zephyr/kernel.h>

#include <lichen/oscore.h>

/*
 * OSCORE security context - full private definition.
 * This is the canonical definition; oscore.h has only forward declaration.
 * All direct field access must be confined to oscore_*.c files.
 */
struct oscore_ctx {
	/* Common context (shared) */
	uint8_t master_secret[OSCORE_KEY_LEN]; /**< Master Secret */
	uint8_t master_salt[8];                 /**< Master Salt (optional) */
	uint8_t master_salt_len;                /**< Salt length (0-8) */
	uint8_t common_iv[OSCORE_NONCE_LEN];    /**< Common IV */
	uint8_t id_context[OSCORE_ID_CONTEXT_MAX_LEN]; /**< ID Context (optional) */
	uint8_t id_context_len;                 /**< ID Context length */
	bool has_id_context;                    /**< ID Context is present (empty differs from absent) */

	/* Sender context */
	uint8_t sender_id[OSCORE_ID_MAX_LEN];   /**< Sender ID */
	uint8_t sender_id_len;                  /**< Sender ID length */
	uint8_t sender_key[OSCORE_KEY_LEN];     /**< Sender Key */
	uint64_t sender_seq;                    /**< Sender Sequence Number (40-bit max per RFC 8613) */

	/* Recipient context */
	uint8_t recipient_id[OSCORE_ID_MAX_LEN]; /**< Recipient ID */
	uint8_t recipient_id_len;                /**< Recipient ID length */
	uint8_t recipient_key[OSCORE_KEY_LEN];   /**< Recipient Key */
	uint64_t recipient_seq;                  /**< Last received seq (40-bit max per RFC 8613) */
	uint32_t replay_window;                  /**< Replay window bitmap */
	uint64_t response_piv_seq;               /**< Last fresh response PIV */
	uint32_t response_piv_window;            /**< Fresh response PIV replay bitmap */
	uint64_t received_response_seq;          /**< Last request PIV with accepted response */
	uint32_t received_response_window;       /**< No-PIV response correlation bitmap */
	uint64_t sent_response_seq;              /**< Last request PIV answered without fresh PIV */
	uint32_t sent_response_window;           /**< Sent no-PIV response correlation bitmap */
	bool response_piv_window_initialized;    /**< Fresh response replay state initialized */
	bool received_response_window_initialized; /**< No-PIV correlation state initialized */
	bool sent_response_window_initialized;   /**< Sent no-PIV correlation state initialized */

	/* Peer identity (optional EUI-64 for per-peer lookup) */
	uint8_t peer_eui64[OSCORE_EUI64_LEN];   /**< Peer's EUI-64 address */
	bool has_peer_eui64;                     /**< EUI-64 is set */

	/* State */
	bool active;                             /**< Context is in use */
};

/* Context storage - defined in oscore_ctx.c */
extern struct oscore_ctx s_contexts[CONFIG_LICHEN_OSCORE_MAX_CONTEXTS];
extern bool s_seq_initialized[CONFIG_LICHEN_OSCORE_MAX_CONTEXTS];
extern bool s_initialized;
extern struct k_mutex s_ctx_mutex;

/* NVM persistence callbacks - defined in oscore_ctx.c */
extern oscore_nvm_write_cb s_nvm_write_cb;
extern oscore_nvm_read_cb s_nvm_read_cb;

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

/* Internal function declarations - oscore_ctx.c */
struct oscore_ctx *ctx_find_by_recipient_locked(const uint8_t *recipient_id,
						size_t recipient_id_len);
struct oscore_ctx *ctx_find_by_eui64_locked(const uint8_t eui64[OSCORE_EUI64_LEN]);
int ctx_get_index(const struct oscore_ctx *ctx);

/* Internal function declarations - oscore_cbor.c */
int build_info_cbor(const uint8_t *id, size_t id_len,
		    const uint8_t *id_context, size_t id_context_len,
		    bool has_id_context,
		    const char *type, size_t out_len,
		    uint8_t *buf, size_t buf_len);
int build_oscore_aad(const uint8_t *request_kid, size_t request_kid_len,
		     const uint8_t *request_piv, size_t request_piv_len,
		     uint8_t *buf, size_t buf_len);

/* Internal function declarations - oscore_replay.c */
bool replay_check_acceptable(const struct oscore_ctx *ctx, uint64_t seq);
int replay_reserve_pending_locked(const struct oscore_ctx *ctx, int ctx_idx, uint64_t seq);
void replay_clear_pending_locked(int ctx_idx, uint64_t seq);
void replay_clear_pending_context_locked(int ctx_idx);
bool replay_update_window(struct oscore_ctx *ctx, uint64_t seq);

#if defined(CONFIG_LICHEN_OSCORE_SETTINGS)
bool oscore_settings_ready(void);
int oscore_settings_restore_context_locked(struct oscore_ctx *ctx, int ctx_idx);
int oscore_settings_commit_context_locked(const struct oscore_ctx *ctx,
					  bool sender_seq_valid);
#endif

/* Internal function declarations - oscore_nonce.c */
void compute_nonce(const uint8_t *sender_id, size_t sender_id_len,
		   const uint8_t *piv, size_t piv_len,
		   const uint8_t *common_iv,
		   uint8_t nonce[OSCORE_NONCE_LEN]);
size_t encode_piv(uint64_t seq, uint8_t piv[OSCORE_PIV_MAX_LEN]);
uint64_t decode_piv(const uint8_t *piv, size_t piv_len);

/* Internal function declarations - oscore_protect.c */
size_t find_coap_payload_marker(const uint8_t *data, size_t len);

#endif /* OSCORE_INTERNAL_H */
