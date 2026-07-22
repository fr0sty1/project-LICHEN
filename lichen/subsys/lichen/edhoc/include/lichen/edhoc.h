/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file edhoc.h
 * @brief EDHOC (RFC 9528) Suite 0 implementation
 *
 * Ephemeral Diffie-Hellman Over COSE for establishing OSCORE security contexts.
 * Suite 0: X25519 + Ed25519 + AES-CCM-16-64-128 + SHA-256.
 */

#ifndef LICHEN_EDHOC_H_
#define LICHEN_EDHOC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Suite 0 constants (RFC 9528 Section 9.2) */
#define EDHOC_SUITE_0              0
#define EDHOC_AEAD_AES_CCM_16_64_128 10
#define EDHOC_HASH_SHA_256         (-16)
#define EDHOC_ECDH_X25519          4
#define EDHOC_SIGN_EDDSA           (-8)

/* Cryptographic sizes */
#define EDHOC_HASH_LEN             32   /* SHA-256 output */
#define EDHOC_KEY_LEN              16   /* AES-128 key */
#define EDHOC_NONCE_LEN            13   /* AES-CCM nonce */
#define EDHOC_TAG_LEN              8    /* AES-CCM-16-64-128 tag */
#define EDHOC_X25519_KEY_LEN       32
#define EDHOC_ED25519_SIG_LEN      64
#define EDHOC_ED25519_PK_LEN       32
#define EDHOC_ED25519_SK_LEN       32

/* Connection ID limits */
#define EDHOC_CID_MAX_LEN          8

/* Maximum message sizes */
#define EDHOC_MSG1_MAX_LEN         64
#define EDHOC_MSG2_MAX_LEN         256
#define EDHOC_MSG3_MAX_LEN         256

/**
 * @brief EDHOC authentication methods (RFC 9528 Section 3.2)
 *
 * NOTE: This implementation only supports EDHOC_METHOD_SIGN_SIGN (Method 0).
 * The other method values are defined for protocol completeness per RFC 9528,
 * but will be rejected at runtime with -ENOTSUP.
 */
enum edhoc_method {
	EDHOC_METHOD_SIGN_SIGN = 0,    /* Both parties use signatures (SUPPORTED) */
	EDHOC_METHOD_SIGN_STATIC = 1,  /* Initiator signs, responder static DH (NOT SUPPORTED) */
	EDHOC_METHOD_STATIC_SIGN = 2,  /* Initiator static DH, responder signs (NOT SUPPORTED) */
	EDHOC_METHOD_STATIC_STATIC = 3 /* Both use static DH (NOT SUPPORTED) */
};

/**
 * @brief EDHOC session state
 */
enum edhoc_state {
	EDHOC_STATE_IDLE = 0,
	EDHOC_STATE_MSG1_SENT,
	EDHOC_STATE_MSG1_RCVD,
	EDHOC_STATE_MSG2_SENT,
	EDHOC_STATE_MSG2_RCVD,
	EDHOC_STATE_MSG3_SENT,
	EDHOC_STATE_COMPLETED,
	EDHOC_STATE_EXPORTED,   /* OSCORE keys derived; PRK wiped; no re-export allowed */
	EDHOC_STATE_ERROR
};

/**
 * @brief OSCORE context exported from EDHOC
 */
struct edhoc_oscore_ctx {
	uint8_t master_secret[EDHOC_KEY_LEN];
	uint8_t master_salt[8];
	uint8_t sender_id[EDHOC_CID_MAX_LEN];
	size_t sender_id_len;
	uint8_t recipient_id[EDHOC_CID_MAX_LEN];
	size_t recipient_id_len;
};

/**
 * @brief EDHOC initiator context
 */
struct edhoc_initiator {
	enum edhoc_state state;
	enum edhoc_method method;
	uint8_t corr;

	/* Our identity (Ed25519 keypair, copied from caller) */
	uint8_t ed_seed[EDHOC_ED25519_SK_LEN];
	uint8_t ed_pubkey[EDHOC_ED25519_PK_LEN];

	/* Connection identifiers */
	uint8_t c_i[EDHOC_CID_MAX_LEN];
	size_t c_i_len;
	uint8_t c_r[EDHOC_CID_MAX_LEN];
	size_t c_r_len;

	/* Ephemeral X25519 keypair */
	uint8_t eph_sk[EDHOC_X25519_KEY_LEN];
	uint8_t eph_pk[EDHOC_X25519_KEY_LEN];

	/* Peer's ephemeral public key */
	uint8_t g_y[EDHOC_X25519_KEY_LEN];

	/* Derived keys */
	uint8_t prk_2e[EDHOC_HASH_LEN];
	uint8_t prk_3e2m[EDHOC_HASH_LEN];
	uint8_t prk_4e3m[EDHOC_HASH_LEN];

	/* Transcript hashes */
	uint8_t th_2[EDHOC_HASH_LEN];
	uint8_t th_3[EDHOC_HASH_LEN];
	uint8_t th_4[EDHOC_HASH_LEN];

	/* Message 1 for TH computation */
	uint8_t msg1[EDHOC_MSG1_MAX_LEN];
	size_t msg1_len;
};

/**
 * @brief EDHOC responder context
 */
struct edhoc_responder {
	enum edhoc_state state;
	enum edhoc_method method;
	uint8_t corr;

	/* Our identity (Ed25519 keypair, copied from caller) */
	uint8_t ed_seed[EDHOC_ED25519_SK_LEN];
	uint8_t ed_pubkey[EDHOC_ED25519_PK_LEN];

	/* Connection identifiers */
	uint8_t c_i[EDHOC_CID_MAX_LEN];
	size_t c_i_len;
	uint8_t c_r[EDHOC_CID_MAX_LEN];
	size_t c_r_len;

	/* Ephemeral X25519 keypair */
	uint8_t eph_sk[EDHOC_X25519_KEY_LEN];
	uint8_t eph_pk[EDHOC_X25519_KEY_LEN];

	/* Peer's ephemeral public key */
	uint8_t g_x[EDHOC_X25519_KEY_LEN];

	/* Derived keys */
	uint8_t prk_2e[EDHOC_HASH_LEN];
	uint8_t prk_3e2m[EDHOC_HASH_LEN];
	uint8_t prk_4e3m[EDHOC_HASH_LEN];

	/* Transcript hashes */
	uint8_t th_2[EDHOC_HASH_LEN];
	uint8_t th_3[EDHOC_HASH_LEN];
	uint8_t th_4[EDHOC_HASH_LEN];

	/* Message 1 for TH computation */
	uint8_t msg1[EDHOC_MSG1_MAX_LEN];
	size_t msg1_len;
};

/**
 * @brief Initialize EDHOC initiator
 *
 * @param ctx Initiator context to initialize
 * @param ed_seed Ed25519 seed (32 bytes, copied)
 * @param ed_pubkey Ed25519 public key (32 bytes, copied)
 * @param c_i Connection identifier (copied); if NULL, a random 1-byte CID is auto-generated
 * @param c_i_len Length of c_i (ignored if c_i is NULL)
 * @return 0 on success, negative on error
 */
int edhoc_initiator_init(struct edhoc_initiator *_Nonnull ctx,
			 const uint8_t *_Nonnull ed_seed,
			 const uint8_t *_Nonnull ed_pubkey,
			 const uint8_t *_Nullable c_i, size_t c_i_len,
			 uint8_t corr);

/**
 * @brief Create EDHOC Message 1
 *
 * @param ctx Initiator context
 * @param msg1 Buffer for Message 1
 * @param msg1_size Size of buffer
 * @param msg1_len Output: actual message length
 * @return 0 on success, negative on error
 */
int edhoc_initiator_create_msg1(struct edhoc_initiator *_Nonnull ctx,
				uint8_t *_Nonnull msg1, size_t msg1_size,
				size_t *_Nonnull msg1_len);

/**
 * @brief Process EDHOC Message 2 and create Message 3
 *
 * @param ctx Initiator context
 * @param msg2 Message 2 from responder
 * @param msg2_len Length of Message 2
 * @param peer_pubkey Responder's Ed25519 public key (32 bytes)
 * @param msg3 Buffer for Message 3
 * @param msg3_size Size of buffer
 * @param msg3_len Output: actual message length
 * @return 0 on success, negative on error
 */
int edhoc_initiator_process_msg2(struct edhoc_initiator *_Nonnull ctx,
				 const uint8_t *_Nonnull msg2, size_t msg2_len,
				 const uint8_t *_Nonnull peer_pubkey,
				 uint8_t *_Nonnull msg3, size_t msg3_size,
				 size_t *_Nonnull msg3_len);

/**
 * @brief Export OSCORE context from completed initiator
 *
 * Derives OSCORE master secret and salt from EDHOC session, then wipes
 * PRK material from ctx. After export, ctx cannot derive additional keys.
 *
 * @param ctx Initiator context (must be in COMPLETED state, wiped after)
 * @param oscore Output OSCORE context
 * @return 0 on success, negative on error
 */
int edhoc_initiator_export_oscore(struct edhoc_initiator *_Nonnull ctx,
				  struct edhoc_oscore_ctx *_Nonnull oscore);

/**
 * @brief Initialize EDHOC responder
 *
 * @param ctx Responder context to initialize
 * @param ed_seed Ed25519 seed (32 bytes)
 * @param ed_pubkey Ed25519 public key (32 bytes)
 * @param c_r Connection identifier (copied); if NULL, a random 1-byte CID is auto-generated
 * @param c_r_len Length of c_r (ignored if c_r is NULL)
 * @return 0 on success, negative on error
 */
int edhoc_responder_init(struct edhoc_responder *_Nonnull ctx,
			 const uint8_t *_Nonnull ed_seed,
			 const uint8_t *_Nonnull ed_pubkey,
			 const uint8_t *_Nullable c_r, size_t c_r_len,
			 uint8_t corr);

/**
 * @brief Process EDHOC Message 1 and create Message 2
 *
 * @param ctx Responder context
 * @param msg1 Message 1 from initiator
 * @param msg1_len Length of Message 1
 * @param msg2 Buffer for Message 2
 * @param msg2_size Size of buffer
 * @param msg2_len Output: actual message length
 * @return 0 on success, negative on error
 */
int edhoc_responder_process_msg1(struct edhoc_responder *_Nonnull ctx,
				 const uint8_t *_Nonnull msg1, size_t msg1_len,
				 uint8_t *_Nonnull msg2, size_t msg2_size,
				 size_t *_Nonnull msg2_len);

/**
 * @brief Process EDHOC Message 3
 *
 * @param ctx Responder context
 * @param msg3 Message 3 from initiator
 * @param msg3_len Length of Message 3
 * @param peer_pubkey Initiator's Ed25519 public key (32 bytes)
 * @return 0 on success, negative on error
 */
int edhoc_responder_process_msg3(struct edhoc_responder *_Nonnull ctx,
				 const uint8_t *_Nonnull msg3, size_t msg3_len,
				 const uint8_t *_Nonnull peer_pubkey);

/**
 * @brief Export OSCORE context from completed responder
 *
 * Derives OSCORE master secret and salt from EDHOC session, then wipes
 * PRK material from ctx. After export, ctx cannot derive additional keys.
 *
 * @param ctx Responder context (must be in COMPLETED state, wiped after)
 * @param oscore Output OSCORE context
 * @return 0 on success, negative on error
 */
int edhoc_responder_export_oscore(struct edhoc_responder *_Nonnull ctx,
				  struct edhoc_oscore_ctx *_Nonnull oscore);

/**
 * @brief Wipe sensitive data from initiator context
 */
void edhoc_initiator_wipe(struct edhoc_initiator *_Nullable ctx);

/**
 * @brief Wipe sensitive data from responder context
 */
void edhoc_responder_wipe(struct edhoc_responder *_Nullable ctx);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_EDHOC_H_ */
